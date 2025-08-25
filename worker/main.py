import os, time, re, json, math, hashlib
import feedparser, requests, yaml
from datetime import datetime
from dateutil import parser as dtparse, tz
import psycopg2
from psycopg2.extras import RealDictCursor
import youtube_transcript_api as yta
from youtube_transcript_api import (
    YouTubeTranscriptApi as YT,
    NoTranscriptFound,
    TranscriptsDisabled,
    CouldNotRetrieveTranscript,
)
from google import genai
from google.genai import types as gtypes

# ---------------- Env ----------------
DB_URL = os.environ["DATABASE_URL"]
WEB_BASE_URL = os.environ["WEB_BASE_URL"].rstrip("/")
INTERNAL_API_TOKEN = os.environ["INTERNAL_API_TOKEN"]

# Optional: where to read config (defaults to YouTube-only if present; else falls back to feeds.yaml)
DEFAULT_FEEDS_PATHS = [
    os.getenv("FEEDS_PATH", "/app/config/feeds.youtube.yaml"),
    "/app/config/feeds.yaml",
]

POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "600"))
TIMEZONE = os.getenv("TIMEZONE", "America/Los_Angeles")
DEBUG = os.getenv("DEBUG", "0") == "1"
FORCE_ONE_SHOT = os.getenv("FORCE_ONE_SHOT", "0") == "1"  # process newest item once

LA = tz.gettz(TIMEZONE)
UTC = tz.UTC

def dlog(*args):
    if DEBUG:
        print("[debug]", *args, flush=True)

def log(*args):
    print("[worker]", *args, flush=True)

def _load_config():
    last_err = None
    for path in DEFAULT_FEEDS_PATHS:
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
                dlog("loaded config from", path)
                return cfg
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"Unable to load feeds config from {DEFAULT_FEEDS_PATHS}: {last_err}")

CONFIG = _load_config()

POST_CHAR_LIMIT = int(CONFIG.get("post_char_limit", 300))
KEYWORDS = [k.lower() for k in CONFIG.get("keywords_positive", [])]
EXCLUDE_NOTE = CONFIG.get("exclude_note", "")

dlog("config keys:", list(CONFIG.keys()))
dlog(
    "counts:",
    "national_feeds=", len(CONFIG.get("national_feeds", [])),
    "blazers_feeds=", len(CONFIG.get("blazers_feeds", [])),
)

# ---------------- DB helpers ----------------
conn = psycopg2.connect(DB_URL)
conn.autocommit = True

def db_exec(sql, args=None):
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, args or [])
        if cur.description:
            return cur.fetchall()
        return []

def ensure_schema():
    # state table
    db_exec("""
    create table if not exists state (
      key   text primary key,
      value text not null
    );
    """)

    # seen episodes: reuse existing columns; we'll store YouTube video IDs in spotify_episode_id column
    db_exec("""
    create table if not exists seen_episodes (
      id                 bigserial primary key,
      feed_url           text not null,
      rss_guid           text,
      spotify_episode_id text,
      published_at       timestamptz,
      first_seen_at      timestamptz default now()
    );
    """)

    # Dedupe via UNIQUE INDEX with expressions
    db_exec("""
    create unique index if not exists uq_seen
      on seen_episodes (
        feed_url,
        coalesce(rss_guid, ''),
        coalesce(spotify_episode_id, '')
      );
    """)
ensure_schema()

# ---------------- Baseline helpers ----------------
def _baseline_key(feed_url: str) -> str:
    h = hashlib.sha1(feed_url.encode("utf-8")).hexdigest()
    return f"feed_baseline:{h}"

def get_feed_baseline(feed_url: str):
    rows = db_exec("select value from state where key=%s", [_baseline_key(feed_url)])
    if rows:
        try:
            return dtparse.isoparse(rows[0]["value"])
        except Exception:
            return None
    return None

def set_feed_baseline(feed_url: str, dt_utc: datetime):
    db_exec(
        "insert into state(key, value) values(%s, %s) "
        "on conflict (key) do update set value = excluded.value",
        [_baseline_key(feed_url), dt_utc.astimezone(UTC).isoformat()],
    )

# ---------------- YouTube helpers ----------------
def yt_channel_feed_url(channel_id: str) -> str:
    return f"https://www.youtube.com/feeds/videos.xml?channel_id={channel_id}"

def parse_youtube_video_id(entry) -> str | None:
    """
    Try multiple places to robustly extract a video ID from a YouTube channel RSS entry.
    """
    vid = entry.get("yt_videoid")
    if vid:
        return vid
    eid = entry.get("id") or ""
    m = re.search(r'[:/](?P<vid>[A-Za-z0-9_-]{6,})$', eid)
    if m:
        return m.group("vid")
    link = entry.get("link") or ""
    m = re.search(r'[?&]v=([A-Za-z0-9_-]{6,})', link)
    if m:
        return m.group(1)
    return None

def get_transcript_text(video_id: str) -> tuple[str, list]:
    """
    Return (full_text, segments) where segments = [(start, dur, text), ...].
    Works across youtube-transcript-api versions by trying both the
    static method and the transcript-list API.
    """
    transcript = None

    # Try the common static method first (present in many releases)
    try:
        if hasattr(YT, "get_transcript"):
            transcript = YT.get_transcript(video_id, languages=["en", "en-US", "en-GB"])
    except NoTranscriptFound:
        transcript = None
    except (TranscriptsDisabled, CouldNotRetrieveTranscript) as e:
        raise e
    except AttributeError:
        # Older/newer version without the static method – fall through to list_transcripts
        transcript = None

    # Fallback: use the transcripts list API (present across versions)
    if transcript is None:
        try:
            tl = YT.list_transcripts(video_id)
            # Prefer manually created English, else auto-generated English
            try:
                transcript = tl.find_manually_created_transcript(["en", "en-US", "en-GB"]).fetch()
            except Exception:
                transcript = tl.find_generated_transcript(["en", "en-US", "en-GB"]).fetch()
        except NoTranscriptFound:
            raise
        except (TranscriptsDisabled, CouldNotRetrieveTranscript) as e:
            raise e

    # transcript is a list of dicts: {'text':..., 'start':..., 'duration':...}
    segs = [
        (float(t.get("start", 0.0)), float(t.get("duration", 0.0)), (t.get("text") or "").strip())
        for t in (transcript or [])
    ]
    full_text = " ".join(s[2] for s in segs if s[2])
    return full_text, segs

def fmt_mmss(seconds: int) -> str:
    m = seconds // 60
    s = seconds % 60
    return f"{int(m):02d}:{int(s):02d}"

def clamp(text, limit=POST_CHAR_LIMIT):
    if len(text) <= limit:
        return text
    return text[:limit-1] + "…"

def first_keyword_hit(segs: list) -> tuple[int | None, str | None]:
    """
    Find first segment that contains any of the target keywords.
    Returns (start_seconds, matched_text) or (None, None).
    """
    for (start, dur, text) in segs:
        low = text.lower()
        if any(k in low for k in KEYWORDS):
            return int(math.floor(start)), text
    return None, None

# ---------------- Posting ----------------
def create_thread(first_text, second_text):
    payload = {"firstText": first_text, "secondText": second_text}
    r = requests.post(
        f"{WEB_BASE_URL}/post-thread",
        headers={"Content-Type": "application/json", "X-Internal-Token": INTERNAL_API_TOKEN},
        data=json.dumps(payload),
        timeout=60,
    )
    if r.status_code != 200:
        log("post-thread failed", r.status_code, r.text)
    else:
        log("posted thread ok")

# ---------------- Dedupe ----------------
def already_seen(feed_url, guid, media_id):
    rows = db_exec(
        "select 1 from seen_episodes "
        "where feed_url=%s and coalesce(rss_guid,'')=coalesce(%s,'') and coalesce(spotify_episode_id,'')=coalesce(%s,'')",
        [feed_url, guid, media_id],
    )
    return bool(rows)

def mark_seen(feed_url, guid, media_id, published_at):
    db_exec(
        "insert into seen_episodes(feed_url, rss_guid, spotify_episode_id, published_at) "
        "values(%s, %s, %s, %s) on conflict do nothing",
        [feed_url, guid, media_id, published_at],
    )

# ---------------- Gemini ----------------
# Per https://ai.google.dev/gemini-api/docs/quickstart
ai = genai.Client()  # uses GEMINI_API_KEY from env

def gemini_json(prompt, text):
    resp = ai.models.generate_content(
        model="gemini-2.5-flash-lite",
        contents=[{"role": "user", "parts": [{"text": prompt + "\n\n" + text}]}],
        config=gtypes.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema={
                "type": "object",
                "properties": {
                    "is_blazers": {"type": "boolean"},
                    "topic": {"type": "string"},
                    "summary": {"type": "string"},
                },
                "required": ["is_blazers"],
            },
            thinking_config=gtypes.ThinkingConfig(thinking_budget=0),
        ),
    )
    try:
        return json.loads(resp.text or "{}")
    except Exception:
        return {}

# ---------------- Core processing ----------------
def parse_pubdate(entry):
    # YouTube RSS typically has 'published' like "2025-08-22T17:11:00+00:00"
    if "published" in entry:
        try:
            dt = dtparse.parse(entry["published"])
            if not dt.tzinfo:
                dt = dt.replace(tzinfo=UTC)
            return dt.astimezone(UTC)
        except Exception:
            pass
    # Fallback: now
    return datetime.now(UTC)

def process_channel(channel_id: str, mode: str):
    feed_url = yt_channel_feed_url(channel_id)
    try:
        d = feedparser.parse(feed_url)
        entries = list(d.entries)
        dlog("feed:", feed_url, "entries:", len(entries))

        if not entries:
            dlog("feed has 0 entries:", feed_url)
            return

        # Build (pub, entry, vid)
        rows = []
        for e in entries:
            vid = parse_youtube_video_id(e)
            if not vid:
                dlog("skip entry: could not parse video id", e.get("id") or e.get("link"))
                continue
            pub = parse_pubdate(e)
            rows.append((pub, e, vid))

        if not rows:
            dlog("no rows after parsing video ids")
            return

        rows.sort(key=lambda t: t[0], reverse=True)
        newest_pub = rows[0][0]
        baseline = get_feed_baseline(feed_url)
        dlog("baseline for", feed_url, "=", baseline.isoformat() if baseline else None)
        dlog("newest_pub:", newest_pub.isoformat())

        # First run: process only most recent
        if baseline is None:
            dlog("first run for feed; newest entry will be processed once")
            pub, entry, vid = rows[0]
            handle_video(feed_url, mode, entry, vid)
            set_feed_baseline(feed_url, pub)
            return

        # Subsequent: strictly newer than baseline, oldest→newest
        to_process = [(p, e, v) for (p, e, v) in rows if p > baseline]
        to_process.sort(key=lambda t: t[0])
        dlog("to_process count:", len(to_process))
        if not to_process:
            dlog("no items newer than baseline for feed:", feed_url)

        for pub, entry, vid in to_process[:8]:  # safety cap
            handle_video(feed_url, mode, entry, vid)

        if newest_pub > baseline:
            set_feed_baseline(feed_url, newest_pub)

    except Exception as e:
        log("channel error", channel_id, e)

def handle_video(feed_url: str, mode: str, entry, video_id: str):
    guid = entry.get("id") or entry.get("link") or video_id
    pub = parse_pubdate(entry)
    title = (entry.get("title") or "").strip()

    if already_seen(feed_url, guid, video_id):
        dlog("skip: already_seen", guid)
        return

    try:
        full_text, segs = get_transcript_text(video_id)
    except (NoTranscriptFound, TranscriptsDisabled, CouldNotRetrieveTranscript) as e:
        log("no transcript", video_id, e)
        mark_seen(feed_url, guid, video_id, pub)
        return
    except Exception as e:
        log("transcript error", video_id, e)
        return  # don't mark seen if we had a transient error

    # find first keyword hit to get a timestamp + local snippet
    start_sec, matched_text = first_keyword_hit(segs)
    if start_sec is None:
        dlog("no direct keyword hit in transcript; mode=", mode)
        # No direct keyword hit — allow Gemini for "blazers" feeds, stricter for "national"
        if mode == "national":
            mark_seen(feed_url, guid, video_id, pub)
            return
        snippet = full_text[:4000]
        jump = 0
    else:
        window_end = start_sec + 180  # ~3 minutes after
        window_texts = [t for (s, dur, t) in segs if s >= start_sec and s <= window_end]
        snippet = " ".join(window_texts)[:8000]
        jump = start_sec

    # Ask Gemini to judge & summarize (strict Blazers context)
    prompt = (
        "You will be given a snippet from a podcast transcript. "
        "Decide if it is about the NBA team the Portland Trail Blazers (players, coaches, front office). "
        "Exclude any generic 'trailblazer' usages not about the NBA team. "
        f"{EXCLUDE_NOTE}\n\n"
        "Return JSON with fields: is_blazers (boolean), topic (short string), summary (<=300 chars, neutral tone)."
    )
    out = gemini_json(prompt, snippet)
    if not out.get("is_blazers"):
        dlog("gemini says not blazers; marking seen", video_id)
        mark_seen(feed_url, guid, video_id, pub)
        return

    topic = (out.get("topic") or "Blazers").strip()
    link = f"https://www.youtube.com/watch?v={video_id}"
    if jump > 0:
        link += f"&t={int(jump)}s"

    time_txt = fmt_mmss(jump) if jump > 0 else ""
    first = clamp(f"{title}{' — ' + time_txt if time_txt else ''} {topic} {link}", POST_CHAR_LIMIT)
    second = clamp((out.get("summary", "") or "").strip(), POST_CHAR_LIMIT)

    create_thread(first, second)
    mark_seen(feed_url, guid, video_id, pub)

# ---------------- Loop ----------------
def loop():
    global FORCE_ONE_SHOT
    if FORCE_ONE_SHOT:
        dlog("FORCE_ONE_SHOT enabled: will process the newest item once, then disable")

    while True:
        log("polling…")

        # National shows
        for f in CONFIG.get("national_feeds", []):
            cid = f.get("youtube_channel_id")
            if not cid:
                log("skip (no youtube_channel_id)", f.get("youtube_search") or f.get("rss"))
                continue
            process_channel(cid, "national")

        # Blazers-specific shows
        for f in CONFIG.get("blazers_feeds", []):
            cid = f.get("youtube_channel_id")
            if not cid:
                log("skip (no youtube_channel_id)", f.get("youtube_search") or f.get("rss"))
                continue
            process_channel(cid, "blazers")

        # Turn off FORCE_ONE_SHOT after the first loop to avoid repeat posting
        if FORCE_ONE_SHOT:
            FORCE_ONE_SHOT = False
            dlog("FORCE_ONE_SHOT completed; set to False")

        log("sleep", POLL_INTERVAL_SECONDS, "s")
        time.sleep(POLL_INTERVAL_SECONDS)

if __name__ == "__main__":
    loop()

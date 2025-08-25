import os, time, re, json, math, hashlib
import feedparser, requests, yaml
from datetime import datetime
from dateutil import parser as dtparse, tz
import psycopg2
from psycopg2.extras import RealDictCursor
import youtube_transcript_api as yta
# YouTube transcripts
try:
    from youtube_transcript_api import (
        YouTubeTranscriptApi,
        NoTranscriptFound,
        TranscriptsDisabled,
        CouldNotRetrieveTranscript,
    )
except ModuleNotFoundError as e:
    # Make the error obvious at startup instead of a NameError later
    raise RuntimeError(
        "Missing dependency 'youtube-transcript-api'. "
        "Add it to worker/requirements.txt and redeploy."
    ) from e
from youtube_transcript_api import (
    YouTubeTranscriptApi as YT,
    NoTranscriptFound,
    TranscriptsDisabled,
    CouldNotRetrieveTranscript,
)
from google import genai
from google.genai import types as gtypes
from yt_dlp import YoutubeDL

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

def _parse_vtt_to_segments(vtt_text: str):
    """
    Very small VTT parser -> [(start, dur, text), ...]
    Accepts HH:MM:SS.mmm or MM:SS.mmm; commas or dots for millis.
    """
    def _to_seconds(ts: str) -> float:
        ts = ts.strip().replace(',', '.')
        parts = ts.split(':')
        if len(parts) == 3:
            h, m, s = parts
            return int(h) * 3600 + int(m) * 60 + float(s)
        elif len(parts) == 2:
            m, s = parts
            return int(m) * 60 + float(s)
        return float(ts)

    segs = []
    lines = [ln.rstrip('\r') for ln in vtt_text.splitlines()]
    i = 0
    while i < len(lines):
        ln = lines[i].strip()
        i += 1
        if not ln or ln.upper().startswith('WEBVTT') or ln.startswith('NOTE'):
            continue
        # Optional cue id line (numeric or text); next should be timecode
        time_line = ln
        if '-->' not in time_line and i < len(lines):
            time_line = lines[i].strip()
            i += 1
        if '-->' not in time_line:
            continue
        try:
            start_s, end_s = [p.strip() for p in time_line.split('-->')[:2]]
            start = _to_seconds(start_s)
            end = _to_seconds(end_s)
        except Exception:
            continue
        # collect cue text until blank line
        texts = []
        while i < len(lines) and lines[i].strip():
            texts.append(lines[i].strip())
            i += 1
        # skip blank separator
        while i < len(lines) and not lines[i].strip():
            i += 1
        cue = ' '.join(texts).strip()
        if cue:
            segs.append((start, max(0.0, end - start), cue))
    return segs

def _parse_json3_to_segments(json_text: str):
    """
    Parse YouTube 'json3' captions (srv3) => [(start, dur, text), ...]
    """
    data = json.loads(json_text)
    segs = []
    for ev in data.get('events', []):
        seg_list = ev.get('segs')
        if not seg_list:
            continue
        text = ''.join(seg.get('utf8', '') for seg in seg_list).strip()
        if not text:
            continue
        start = float(ev.get('tStartMs', 0)) / 1000.0
        dur = float(ev.get('dDurationMs', 0)) / 1000.0 if ev.get('dDurationMs') is not None else 0.0
        segs.append((start, dur, text))
    return segs

def _fallback_transcript_via_ytdlp(video_id: str):
    """
    Fetch subtitles (manual or auto) using yt-dlp without downloading the video.
    Prefer English and .vtt or json3 tracks.
    """
    url = f"https://www.youtube.com/watch?v={video_id}"
    # no download; quiet output
    ydl_opts = {
        'quiet': True,
        'skip_download': True,
        # No need to write files; we’ll fetch the caption URL ourselves
    }
    with YoutubeDL(ydl_opts) as ydl:
        info = ydl.extract_info(url, download=False)

    # Both keys may exist; prefer authored subs over auto
    tracks_by_lang = {}
    subs = info.get('subtitles') or {}
    autos = info.get('automatic_captions') or {}

    for lang in ['en', 'en-US', 'en-GB']:
        if lang in subs:
            tracks_by_lang[lang] = subs[lang]
        elif lang in autos:
            tracks_by_lang[lang] = autos[lang]

    if not tracks_by_lang:
        raise NoTranscriptFound("yt-dlp: no English subtitles or auto-captions found")

    # Choose one URL, preferring json3 or vtt
    fmt_order = ['json3', 'vtt', 'ttml', 'srv3', 'srv2', 'srv1']
    chosen = None
    chosen_ext = None
    for lang, lst in tracks_by_lang.items():
        # Each item has {'ext': 'vtt'|'json3'|..., 'url': '...'}
        lst_sorted = sorted(
            lst,
            key=lambda x: fmt_order.index(x.get('ext', 'vtt')) if x.get('ext') in fmt_order else 99
        )
        if lst_sorted:
            chosen = lst_sorted[0].get('url')
            chosen_ext = lst_sorted[0].get('ext')
            break

    if not chosen:
        raise NoTranscriptFound("yt-dlp: could not choose a captions URL")

    # Download the caption file itself (tiny)
    with YoutubeDL({'quiet': True}) as ydl:
        data = ydl.urlopen(chosen).read()

    text = data.decode('utf-8', 'ignore')
    if chosen_ext == 'json3':
        segs = _parse_json3_to_segments(text)
    else:
        # treat vtt/ttml/srvN roughly as VTT; VTT works for most YouTube caption URLs
        segs = _parse_vtt_to_segments(text)

    if not segs:
        raise NoTranscriptFound("yt-dlp: parsed 0 segments")

    full_text = ' '.join(t for (_, _, t) in segs if t)
    return full_text, segs

def get_transcript_text(video_id: str) -> tuple[str, list]:
    """
    Primary (youtube-transcript-api) with a yt-dlp fallback.
    Returns (full_text, segments) or raises NoTranscriptFound / TranscriptsDisabled.
    """
    # Try youtube-transcript-api first (fastest when it works)
    try:
        transcript = YouTubeTranscriptApi.get_transcript(video_id, languages=["en", "en-US", "en-GB"])
        segs = [(float(t.get("start", 0.0)), float(t.get("duration", 0.0)), t.get("text", "").strip())
                for t in transcript]
        full_text = " ".join(s[2] for s in segs if s[2])
        if full_text:
            return full_text, segs
    except (NoTranscriptFound, TranscriptsDisabled, CouldNotRetrieveTranscript):
        # pass to fallback
        pass
    except Exception as e:
        # This captures your "no element found: line 1, column 0" case and similar HTML/empty responses.
        log("youtube-transcript-api failed; using yt-dlp fallback:", video_id, str(e))

    # Fallback via yt-dlp (no video download)
    return _fallback_transcript_via_ytdlp(video_id)

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
# Per https://ai.google.dev/gemini-api/docs/api-key
# The SDK will recognize GEMINI_API_KEY or GOOGLE_API_KEY, but we pass explicitly for clarity.
GEMINI_KEY = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
if not GEMINI_KEY:
    raise RuntimeError("Missing GOOGLE_API_KEY / GEMINI_API_KEY in environment for Gemini API.")
# Pass explicitly (also recommended by docs if auto-discovery isn't working)
ai = genai.Client(api_key=GEMINI_KEY)
# Optional, non-secret log (no key content):
log("Gemini API key detected via", "GOOGLE_API_KEY" if os.getenv("GOOGLE_API_KEY") else "GEMINI_API_KEY")

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

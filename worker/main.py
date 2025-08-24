import os, time, io, re, json, math, hashlib
import feedparser, requests, yaml
from datetime import datetime, timezone, timedelta
from dateutil import parser as dtparse, tz
from pydub import AudioSegment
from faster_whisper import WhisperModel
import psycopg2
from psycopg2.extras import RealDictCursor
from google import genai
from google.genai import types as gtypes

DB_URL = os.environ["DATABASE_URL"]
WEB_BASE_URL = os.environ["WEB_BASE_URL"]
INTERNAL_API_TOKEN = os.environ["INTERNAL_API_TOKEN"]
SPOTIFY_CLIENT_ID = os.environ["SPOTIFY_CLIENT_ID"]
SPOTIFY_CLIENT_SECRET = os.environ["SPOTIFY_CLIENT_SECRET"]
GEMINI_API_KEY = os.environ["GEMINI_API_KEY"]
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "600"))
TIMEZONE = os.getenv("TIMEZONE", "America/Los_Angeles")
RAW_WHISPER_MODEL = os.getenv("WHISPER_MODEL", "small")
# tolerate accidental suffixes like "-int8" or "-int8_float32"
WHISPER_MODEL = re.sub(r"-(int8.*)$", "", RAW_WHISPER_MODEL.strip().lower())

LA = tz.gettz(TIMEZONE)
UTC = tz.UTC

with open("/app/config/feeds.yaml", "r") as f:
    CONFIG = yaml.safe_load(f)

POST_CHAR_LIMIT = int(CONFIG.get("post_char_limit", 300))
KEYWORDS = [k.lower() for k in CONFIG.get("keywords_positive", [])]

def log(*args):
    print("[worker]", *args, flush=True)

# --- DB helpers ---
conn = psycopg2.connect(DB_URL)
conn.autocommit = True

def db_exec(sql, args=None):
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, args or [])
        if cur.description:
            return cur.fetchall()
        return []

def ensure_schema():
    # Base tables (safe to run repeatedly)
    db_exec("""
    create table if not exists state (
      key   text primary key,
      value text not null
    );
    """)

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

    # Expressions aren't allowed in a table-level UNIQUE constraint in Postgres.
    # Enforce the same rule via a UNIQUE INDEX with expressions:
    db_exec("""
    create unique index if not exists uq_seen
      on seen_episodes (
        feed_url,
        coalesce(rss_guid, ''),
        coalesce(spotify_episode_id, '')
      );
    """)
ensure_schema()

# -------- Per-feed "latest episode baseline" helpers --------
def _baseline_key(feed_url: str) -> str:
    # Avoid overly long keys by hashing the URL
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

# --- Spotify API ---
_spotify_token = None
_spotify_token_exp = 0
def spotify_token():
    global _spotify_token, _spotify_token_exp
    if _spotify_token and time.time() < _spotify_token_exp - 30:
        return _spotify_token
    resp = requests.post("https://accounts.spotify.com/api/token",
                         data={"grant_type":"client_credentials"},
                         auth=(SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET),
                         timeout=20)
    resp.raise_for_status()
    data = resp.json()
    _spotify_token = data["access_token"]
    _spotify_token_exp = time.time() + data["expires_in"]
    return _spotify_token

def spotify_get(url, params=None):
    tok = spotify_token()
    headers = {"Authorization": f"Bearer {tok}"}
    r = requests.get(url, headers=headers, params=params or {}, timeout=30)
    r.raise_for_status()
    return r.json()

def parse_spotify_show_id(show_url):
    # https://open.spotify.com/show/<ID>(?...)?  -> <ID>
    m = re.search(r'/show/([A-Za-z0-9]+)', show_url)
    return m.group(1) if m else None

def get_spotify_episode_for_title(show_id, title_guess):
    # Fetch recent episodes, try title match (case-insensitive, punctuation-stripped), fallback to fuzzy contains.
    data = spotify_get(f"https://api.spotify.com/v1/shows/{show_id}/episodes", params={"limit": 50, "market":"US"})
    norm = lambda s: re.sub(r'[^a-z0-9 ]','', (s or "").lower())
    tnorm = norm(title_guess or "")
    best = None
    for ep in data.get("items", []):
        en = norm(ep.get("name",""))
        if en == tnorm or (tnorm and tnorm in en) or (en and en in tnorm):
            best = ep; break
    return best

def spotify_timestamp_link(ep_id, seconds):
    # Best-effort timestamp param
    return f"https://open.spotify.com/episode/{ep_id}?t={int(seconds)}"

def fmt_mmss(seconds):
    m = seconds // 60
    s = seconds % 60
    return f"{int(m):02d}:{int(s):02d}"

# --- Whisper ---
log("Loading faster-whisper model:", WHISPER_MODEL)
whisper = WhisperModel(WHISPER_MODEL, device="cpu", compute_type="int8")

# --- Gemini ---
ai = genai.Client()  # uses GEMINI_API_KEY from env

def gemini_json(prompt, text):
    resp = ai.models.generate_content(
        model="gemini-2.5-flash-lite",
        contents=[{"role":"user","parts":[{"text": prompt + "\n\n" + text}]}],
        config=gtypes.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema={
                "type":"object",
                "properties":{
                    "is_blazers":{"type":"boolean"},
                    "topic":{"type":"string"},
                    "summary":{"type":"string"}
                },
                "required":["is_blazers"]
            },
            thinking_config=gtypes.ThinkingConfig(thinking_budget=0),
        ),
    )
    try:
        return json.loads(resp.text or "{}")
    except Exception:
        return {}

def clamp(text, limit=POST_CHAR_LIMIT):
    if len(text) <= limit:
        return text
    return text[:limit-1] + "…"

def download_audio(enclosure_url):
    r = requests.get(enclosure_url, timeout=120, stream=True)
    r.raise_for_status()
    content = r.content
    audio = AudioSegment.from_file(io.BytesIO(content))
    audio = audio.set_channels(1).set_frame_rate(16000)
    buf = io.BytesIO()
    audio.export(buf, format="wav")
    return buf.getvalue()

def transcribe(bytes_wav):
    segments, _ = whisper.transcribe(bytes_wav, vad_filter=True, vad_parameters={"min_silence_duration_ms": 500})
    texts = []
    spans = []
    for seg in segments:
        texts.append(seg.text.strip())
        spans.append((seg.start, seg.end, seg.text.strip()))
    return " ".join(texts), spans

def find_blazers_segments(spans):
    # find earliest segment that contains any keyword; extend window
    idxs = []
    keys = KEYWORDS
    for i, (start, end, text) in enumerate(spans):
        low = text.lower()
        if any(k in low for k in keys):
            idxs.append(i)
    if not idxs:
        return None
    first_i = idxs[0]
    start_t = max(0, math.floor(spans[first_i][0] - 10))
    end_t = math.floor(spans[min(first_i+30, len(spans)-1)][1])  # ~ up to ~2-3 min after
    snippet = " ".join(t for (s,e,t) in spans if s>=start_t and e<=end_t)
    return start_t, end_t, snippet

def create_thread(first_text, second_text):
    payload = {"firstText": first_text, "secondText": second_text}
    r = requests.post(f"{WEB_BASE_URL}/post-thread",
                      headers={"Content-Type":"application/json","X-Internal-Token": INTERNAL_API_TOKEN},
                      data=json.dumps(payload),
                      timeout=60)
    if r.status_code != 200:
        log("post-thread failed", r.status_code, r.text)
    else:
        log("posted thread ok")

def already_seen(feed_url, guid, sp_id):
    rows = db_exec("select 1 from seen_episodes where feed_url=%s and coalesce(rss_guid,'')=coalesce(%s,'') and coalesce(spotify_episode_id,'')=coalesce(%s,'')",
                   [feed_url, guid, sp_id])
    return bool(rows)

def mark_seen(feed_url, guid, sp_id, published_at):
    db_exec(
        "insert into seen_episodes(feed_url, rss_guid, spotify_episode_id, published_at) "
        "values(%s, %s, %s, %s) on conflict do nothing",
        [feed_url, guid, sp_id, published_at],
    )

def parse_pubdate(entry):
    # prefer explicit fields; fallback to now if missing
    for k in ["published", "pubDate", "updated"]:
        if k in entry:
            try:
                dt = dtparse.parse(entry[k])
                if not dt.tzinfo: dt = dt.replace(tzinfo=UTC)
                return dt.astimezone(UTC)
            except Exception:
                pass
    return datetime.now(UTC)

# -------- Handlers --------
def handle_national(feed_url, show_id, entry):
    guid = entry.get("id") or entry.get("guid") or entry.get("link")
    pub = parse_pubdate(entry)
    if already_seen(feed_url, guid, None):
        return
    enc = enclosure_url(entry)
    if not enc:
        mark_seen(feed_url, guid, None, pub); return

    audio = download_audio(enc)
    full_text, spans = transcribe(audio)
    seg = find_blazers_segments(spans)
    if not seg:
        mark_seen(feed_url, guid, None, pub); return

    start_t, end_t, snippet = seg
    prompt = ("Decide if the following podcast snippet is about the NBA team the Portland Trail Blazers. "
              "Return JSON with fields: is_blazers (boolean), topic (short), summary (<=300 chars, neutral). "
              "Only mark true if it clearly refers to the NBA team or its players/coaches/front office.")
    out = gemini_json(prompt, snippet)
    if not out.get("is_blazers"):
        mark_seen(feed_url, guid, None, pub); return

    topic = (out.get("topic") or "Blazers").strip()
    title = entry.get("title","").strip()
    ep = get_spotify_episode_for_title(show_id, title)
    if not ep:
        mark_seen(feed_url, guid, None, pub); return
    sp_id = ep["id"]
    link = spotify_timestamp_link(sp_id, start_t)
    time_txt = fmt_mmss(start_t)

    first = clamp(f"{title} — {time_txt} {topic} {link}", POST_CHAR_LIMIT)
    second = clamp((out.get("summary","") or "").strip(), POST_CHAR_LIMIT)

    create_thread(first, second)
    mark_seen(feed_url, guid, sp_id, pub)

def handle_blazers(feed_url, show_id, entry):
    guid = entry.get("id") or entry.get("guid") or entry.get("link")
    pub = parse_pubdate(entry)
    if already_seen(feed_url, guid, None):
        return
    enc = enclosure_url(entry)
    if not enc:
        mark_seen(feed_url, guid, None, pub); return

    audio = download_audio(enc)
    full_text, spans = transcribe(audio)

    out = ai.models.generate_content(
        model="gemini-2.5-flash-lite",
        contents=[{"role":"user","parts":[{"text": full_text[:50000]}]}],
        config=gtypes.GenerateContentConfig(
            response_mime_type="text/plain",
            thinking_config=gtypes.ThinkingConfig(thinking_budget=0),
        ),
    )
    summary = clamp((out.text or "").strip(), POST_CHAR_LIMIT)

    title = entry.get("title","").strip()
    ep = get_spotify_episode_for_title(show_id, title)
    if not ep:
        mark_seen(feed_url, guid, None, pub); return
    sp_id = ep["id"]
    link = f"https://open.spotify.com/episode/{sp_id}"

    first = clamp(f"{title} {link}", POST_CHAR_LIMIT)
    second = summary

    create_thread(first, second)
    mark_seen(feed_url, guid, sp_id, pub)

def enclosure_url(entry):
    if "links" in entry:
        for l in entry["links"]:
            if l.get("rel") == "enclosure" and l.get("type","").startswith("audio"):
                return l.get("href")
    if "enclosures" in entry and entry["enclosures"]:
        return entry["enclosures"][0].get("href")
    return None

# -------- Feed processing with per-feed baseline --------
def process_feed(feed_url, show_url, mode):
    try:
        show_id = parse_spotify_show_id(show_url)
        d = feedparser.parse(feed_url)
        entries = list(d.entries)
        if not entries:
            return

        # Compute published timestamps for ordering
        entries_with_pub = []
        for e in entries:
            pub = parse_pubdate(e)
            entries_with_pub.append((pub, e))

        # Sort by published time descending (newest first)
        entries_with_pub.sort(key=lambda t: t[0], reverse=True)
        newest_pub = entries_with_pub[0][0]

        baseline = get_feed_baseline(feed_url)

        if baseline is None:
            # First time seeing this feed:
            # Process only the single most recent episode, then set baseline to its published time.
            pub, latest_entry = entries_with_pub[0]
            if mode == "national":
                handle_national(feed_url, show_id, latest_entry)
            else:
                handle_blazers(feed_url, show_id, latest_entry)
            set_feed_baseline(feed_url, pub)
            return

        # Subsequent runs: process only entries strictly newer than baseline, in chronological order
        to_process = [(p, e) for (p, e) in entries_with_pub if p > baseline]
        # Process older -> newer so posts appear in order if multiple arrived between polls
        to_process.sort(key=lambda t: t[0])

        for pub, entry in to_process[:10]:  # safety cap
            if mode == "national":
                handle_national(feed_url, show_id, entry)
            else:
                handle_blazers(feed_url, show_id, entry)

        # Always move baseline forward to the newest publish time we see in the feed.
        # This prevents re-scanning the same old list when none matched posting criteria.
        if newest_pub > baseline:
            set_feed_baseline(feed_url, newest_pub)

    except Exception as e:
        log("feed error", feed_url, e)

def loop():
    while True:
        log("polling…")
        for f in CONFIG["national_feeds"]:
            process_feed(f["rss"], f["spotify_show"], "national")
        for f in CONFIG["blazers_feeds"]:
            process_feed(f["rss"], f["spotify_show"], "blazers")
        log("sleep", POLL_INTERVAL_SECONDS, "s")
        time.sleep(POLL_INTERVAL_SECONDS)

if __name__ == "__main__":
    loop()

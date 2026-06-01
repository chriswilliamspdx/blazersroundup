import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta

import feedparser
import psycopg2
import requests
import yaml
from dateutil import parser as dtparse, tz
from google import genai
from google.genai import errors as genai_errors
from google.genai import types as gtypes
from psycopg2.extras import RealDictCursor

from retry import next_retry_at_for_attempt, transcript_retry_due
from text_utils import (
    build_model_input,
    clamp_heading_with_link,
    clamp_text,
    first_keyword_hit,
    fmt_mmss,
    transcript_window,
    youtube_link,
)
from transcript_providers import TranscriptError, fetch_transcript, settings_from_env


UTC = tz.UTC


def log(*args):
    print("[worker]", *args, flush=True)


def dlog(settings, *args):
    if settings.debug:
        print("[debug]", *args, flush=True)


@dataclass
class WorkerSettings:
    db_url: str
    web_base_url: str
    internal_api_token: str
    gemini_key: str
    gemini_model: str
    feeds_paths: list[str]
    poll_interval_seconds: int
    timezone: str
    debug: bool
    dry_run: bool
    dry_run_record_transcript_retries: bool
    force_one_shot: bool
    force_transcript_retry: bool
    reset_feed_state: bool
    reset_llm_state: bool
    feed_mode: str
    scan_pause_seconds: float
    transcript_retry_minutes: int
    transcript_max_attempts: int
    max_videos_per_feed: int
    max_feed_candidate_fallbacks: int
    max_videos_per_poll: int
    llm_max_calls_per_poll: int
    llm_retry_minutes: int
    llm_max_attempts: int
    llm_quota_cooldown_minutes: int
    gemini_thinking_level: str

    @classmethod
    def from_env(cls):
        return cls(
            db_url=os.environ["DATABASE_URL"],
            web_base_url=os.environ["WEB_BASE_URL"].rstrip("/"),
            internal_api_token=os.environ["INTERNAL_API_TOKEN"],
            gemini_key=os.getenv("GOOGLE_API_KEY") or os.environ["GEMINI_API_KEY"],
            gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite"),
            feeds_paths=[
                os.getenv("FEEDS_PATH", "/app/config/feeds.youtube.yaml"),
                "/app/config/feeds.yaml",
            ],
            poll_interval_seconds=int(os.getenv("POLL_INTERVAL_SECONDS", "600")),
            timezone=os.getenv("TIMEZONE", "America/Los_Angeles"),
            debug=os.getenv("DEBUG", "0") == "1",
            dry_run=os.getenv("DRY_RUN", "0") == "1",
            dry_run_record_transcript_retries=os.getenv("DRY_RUN_RECORD_TRANSCRIPT_RETRIES", "1") == "1",
            force_one_shot=os.getenv("FORCE_ONE_SHOT", "0") == "1",
            force_transcript_retry=os.getenv("FORCE_TRANSCRIPT_RETRY", "0") == "1",
            reset_feed_state=os.getenv("RESET_FEED_STATE", "0") == "1",
            reset_llm_state=os.getenv("RESET_LLM_STATE", "0") == "1",
            feed_mode=os.getenv("FEED_MODE", "all").lower(),
            scan_pause_seconds=float(os.getenv("SCAN_PAUSE_SECONDS", "2.0")),
            transcript_retry_minutes=int(os.getenv("TRANSCRIPT_RETRY_MINUTES", "60")),
            transcript_max_attempts=int(os.getenv("TRANSCRIPT_MAX_ATTEMPTS", "5")),
            max_videos_per_feed=int(os.getenv("MAX_VIDEOS_PER_FEED", "1")),
            max_feed_candidate_fallbacks=int(os.getenv("MAX_FEED_CANDIDATE_FALLBACKS", "5")),
            max_videos_per_poll=int(os.getenv("MAX_VIDEOS_PER_POLL", "40")),
            llm_max_calls_per_poll=int(os.getenv("LLM_MAX_CALLS_PER_POLL", "10")),
            llm_retry_minutes=int(os.getenv("LLM_RETRY_MINUTES", "60")),
            llm_max_attempts=int(os.getenv("LLM_MAX_ATTEMPTS", "5")),
            llm_quota_cooldown_minutes=int(os.getenv("LLM_QUOTA_COOLDOWN_MINUTES", "60")),
            gemini_thinking_level=os.getenv("GEMINI_THINKING_LEVEL", "low"),
        )


def load_config(settings: WorkerSettings):
    last_error = None
    for path in settings.feeds_paths:
        try:
            with open(path, "r", encoding="utf-8") as file:
                config = yaml.safe_load(file) or {}
            dlog(settings, "loaded config from", path)
            return config
        except Exception as exc:
            last_error = exc
    raise RuntimeError(f"Unable to load feeds config from {settings.feeds_paths}: {last_error}")


class Database:
    def __init__(self, db_url: str):
        self.conn = psycopg2.connect(db_url)
        self.conn.autocommit = True

    def exec(self, sql, args=None):
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, args or [])
            if cur.description:
                return cur.fetchall()
            return []

    def ensure_schema(self):
        self.exec(
            """
            create table if not exists state (
              key text primary key,
              value text not null
            );
            """
        )
        self.exec(
            """
            create table if not exists seen_episodes (
              id bigserial primary key,
              feed_url text not null,
              rss_guid text,
              spotify_episode_id text,
              published_at timestamptz,
              first_seen_at timestamptz default now()
            );
            """
        )
        self.exec(
            """
            create unique index if not exists uq_seen
              on seen_episodes (
                feed_url,
                coalesce(rss_guid, ''),
                coalesce(spotify_episode_id, '')
              );
            """
        )
        self.exec(
            """
            create table if not exists transcript_attempts (
              video_id text primary key,
              last_attempt_at timestamptz not null default now(),
              attempt_count integer not null default 0,
              last_error_type text,
              next_retry_at timestamptz
            );
            """
        )
        self.exec(
            """
            create table if not exists summary_attempts (
              video_id text primary key,
              last_attempt_at timestamptz not null default now(),
              attempt_count integer not null default 0,
              last_error_type text,
              next_retry_at timestamptz
            );
            """
        )

    def get_state(self, key: str):
        rows = self.exec("select value from state where key=%s", [key])
        return rows[0]["value"] if rows else None

    def set_state(self, key: str, value: str):
        self.exec(
            "insert into state(key, value) values(%s, %s) "
            "on conflict (key) do update set value = excluded.value",
            [key, value],
        )

    def delete_state(self, key: str):
        self.exec("delete from state where key=%s", [key])

    def _baseline_key(self, feed_url: str) -> str:
        digest = hashlib.sha1(feed_url.encode("utf-8")).hexdigest()
        return f"feed_baseline:{digest}"

    def get_feed_baseline(self, feed_url: str):
        rows = self.exec("select value from state where key=%s", [self._baseline_key(feed_url)])
        if not rows:
            return None
        try:
            return dtparse.isoparse(rows[0]["value"])
        except Exception:
            return None

    def set_feed_baseline(self, feed_url: str, dt_utc: datetime):
        self.exec(
            "insert into state(key, value) values(%s, %s) "
            "on conflict (key) do update set value = excluded.value",
            [self._baseline_key(feed_url), dt_utc.astimezone(UTC).isoformat()],
        )

    def already_seen(self, feed_url, guid, media_id):
        rows = self.exec(
            "select 1 from seen_episodes "
            "where feed_url=%s and coalesce(rss_guid,'')=coalesce(%s,'') "
            "and coalesce(spotify_episode_id,'')=coalesce(%s,'')",
            [feed_url, guid, media_id],
        )
        return bool(rows)

    def mark_seen(self, feed_url, guid, media_id, published_at):
        self.exec(
            "insert into seen_episodes(feed_url, rss_guid, spotify_episode_id, published_at) "
            "values(%s, %s, %s, %s) on conflict do nothing",
            [feed_url, guid, media_id, published_at],
        )

    def reset_feed_state(self):
        self.exec("delete from state where key like 'feed_baseline:%%'")
        self.exec("delete from transcript_attempts")
        self.exec("delete from summary_attempts")

    def reset_llm_state(self):
        self.exec("delete from summary_attempts")
        self.delete_state("llm_cooldown_until")
        self.delete_state("llm_cooldown_reason")

    def get_transcript_attempt(self, video_id: str):
        rows = self.exec("select * from transcript_attempts where video_id=%s", [video_id])
        return rows[0] if rows else None

    def has_due_transcript_retry(self, video_id: str, max_attempts: int, now=None) -> bool:
        attempt = self.get_transcript_attempt(video_id)
        if not attempt:
            return False
        return transcript_retry_due(attempt, max_attempts, now or datetime.now(UTC))

    def transcript_retry_ready(self, video_id: str, max_attempts: int, now=None) -> bool:
        attempt = self.get_transcript_attempt(video_id)
        return transcript_retry_due(attempt, max_attempts, now or datetime.now(UTC))

    def record_transcript_success(self, video_id: str):
        self.exec("delete from transcript_attempts where video_id=%s", [video_id])

    def record_transcript_failure(self, video_id: str, error_type: str, retry_minutes: int, max_attempts: int):
        existing = self.get_transcript_attempt(video_id)
        attempt_count = int(existing["attempt_count"]) + 1 if existing else 1
        now = datetime.now(UTC)
        next_retry_at = next_retry_at_for_attempt(now, attempt_count, retry_minutes, max_attempts)
        self.exec(
            """
            insert into transcript_attempts(video_id, last_attempt_at, attempt_count, last_error_type, next_retry_at)
            values(%s, %s, %s, %s, %s)
            on conflict(video_id) do update set
              last_attempt_at = excluded.last_attempt_at,
              attempt_count = excluded.attempt_count,
              last_error_type = excluded.last_error_type,
              next_retry_at = excluded.next_retry_at
            """,
            [video_id, now, attempt_count, error_type, next_retry_at],
        )
        return attempt_count, next_retry_at

    def get_summary_attempt(self, video_id: str):
        rows = self.exec("select * from summary_attempts where video_id=%s", [video_id])
        return rows[0] if rows else None

    def summary_retry_ready(self, video_id: str, max_attempts: int, now=None) -> bool:
        attempt = self.get_summary_attempt(video_id)
        return transcript_retry_due(attempt, max_attempts, now or datetime.now(UTC))

    def record_summary_success(self, video_id: str):
        self.exec("delete from summary_attempts where video_id=%s", [video_id])

    def record_summary_failure(self, video_id: str, error_type: str, retry_minutes: int, max_attempts: int):
        existing = self.get_summary_attempt(video_id)
        attempt_count = int(existing["attempt_count"]) + 1 if existing else 1
        now = datetime.now(UTC)
        next_retry_at = next_retry_at_for_attempt(now, attempt_count, retry_minutes, max_attempts)
        self.exec(
            """
            insert into summary_attempts(video_id, last_attempt_at, attempt_count, last_error_type, next_retry_at)
            values(%s, %s, %s, %s, %s)
            on conflict(video_id) do update set
              last_attempt_at = excluded.last_attempt_at,
              attempt_count = excluded.attempt_count,
              last_error_type = excluded.last_error_type,
              next_retry_at = excluded.next_retry_at
            """,
            [video_id, now, attempt_count, error_type, next_retry_at],
        )
        return attempt_count, next_retry_at

    def get_llm_cooldown_until(self):
        value = self.get_state("llm_cooldown_until")
        if not value:
            return None
        try:
            return dtparse.isoparse(value).astimezone(UTC)
        except Exception:
            return None

    def llm_cooldown_active(self, now=None):
        cooldown_until = self.get_llm_cooldown_until()
        if not cooldown_until:
            return None
        now = now or datetime.now(UTC)
        if cooldown_until <= now:
            self.delete_state("llm_cooldown_until")
            self.delete_state("llm_cooldown_reason")
            return None
        return cooldown_until

    def set_llm_cooldown(self, cooldown_until: datetime, reason: str):
        cooldown_until = cooldown_until.astimezone(UTC)
        self.set_state("llm_cooldown_until", cooldown_until.isoformat())
        self.set_state("llm_cooldown_reason", reason)
        return cooldown_until


class LLMError(Exception):
    def __init__(self, error_type: str, message: str = ""):
        super().__init__(message or error_type)
        self.error_type = error_type


class LLMQuotaError(LLMError):
    def __init__(self, cooldown_until: datetime, error_type: str = "LLMQuota", message: str = ""):
        super().__init__(error_type, message)
        self.cooldown_until = cooldown_until


@dataclass
class PollContext:
    llm_limit: int
    llm_calls: int = 0
    llm_wait: bool = False
    llm_wait_reason: str = ""

    def has_llm_capacity(self) -> bool:
        return self.llm_limit < 0 or self.llm_calls < self.llm_limit

    def reserve_llm_call(self) -> bool:
        if not self.has_llm_capacity():
            self.llm_wait = True
            self.llm_wait_reason = "budget"
            return False
        self.llm_calls += 1
        return True


def _retry_delay_seconds_from_payload(payload) -> int | None:
    if not isinstance(payload, dict):
        return None
    for detail in payload.get("error", {}).get("details", []):
        delay = detail.get("retryDelay") if isinstance(detail, dict) else None
        if isinstance(delay, str):
            match = re.match(r"^(\d+)(?:\.\d+)?s$", delay)
            if match:
                return int(match.group(1))
    return None


def _is_daily_quota_payload(payload) -> bool:
    if not isinstance(payload, dict):
        return False
    error = payload.get("error", {})
    message = str(error.get("message", ""))
    if "PerDay" in message or "requests per day" in message.lower():
        return True
    for detail in error.get("details", []):
        for violation in (detail.get("violations") or []) if isinstance(detail, dict) else []:
            quota_id = str(violation.get("quotaId", ""))
            quota_metric = str(violation.get("quotaMetric", ""))
            if "PerDay" in quota_id or "requests_per_day" in quota_metric:
                return True
    return False


def _next_pacific_quota_reset(now=None) -> datetime:
    pacific = tz.gettz("America/Los_Angeles")
    now = now or datetime.now(UTC)
    local_now = now.astimezone(pacific)
    next_day = (local_now + timedelta(days=1)).date()
    midnight_local = datetime.combine(next_day, datetime.min.time()).replace(tzinfo=pacific)
    return midnight_local.astimezone(UTC) + timedelta(minutes=5)


def _payload_from_genai_error(exc):
    payload = getattr(exc, "response_json", None)
    if isinstance(payload, dict):
        return payload
    for arg in getattr(exc, "args", []):
        if isinstance(arg, dict):
            return arg
    return None


def _cooldown_until_for_genai_error(exc, fallback_minutes: int) -> datetime:
    now = datetime.now(UTC)
    payload = _payload_from_genai_error(exc)
    if _is_daily_quota_payload(payload):
        return _next_pacific_quota_reset(now)
    retry_seconds = _retry_delay_seconds_from_payload(payload)
    if retry_seconds is not None:
        return now + timedelta(seconds=max(retry_seconds, 1))
    return now + timedelta(minutes=fallback_minutes)


def _thinking_config_for_model(model: str, thinking_level: str):
    if model.startswith("gemini-3"):
        return gtypes.ThinkingConfig(thinking_level=thinking_level)
    return gtypes.ThinkingConfig(thinking_budget=0)


class GeminiSummarizer:
    def __init__(self, api_key: str, model: str, thinking_level: str, quota_cooldown_minutes: int):
        self.model = model
        self.thinking_level = thinking_level
        self.quota_cooldown_minutes = quota_cooldown_minutes
        self.client = genai.Client(api_key=api_key)

    def summarize_json(self, prompt: str, text: str):
        try:
            response = self.client.models.generate_content(
                model=self.model,
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
                    thinking_config=_thinking_config_for_model(self.model, self.thinking_level),
                ),
            )
        except genai_errors.ClientError as exc:
            status_code = getattr(exc, "status_code", None)
            if status_code == 429:
                raise LLMQuotaError(_cooldown_until_for_genai_error(exc, self.quota_cooldown_minutes), message=str(exc))
            raise LLMError("LLMClientError", str(exc)) from exc
        except Exception as exc:
            raise LLMError("LLMError", str(exc)) from exc
        try:
            return json.loads(response.text or "{}")
        except Exception:
            raise LLMError("LLMInvalidJson", response.text or "")


def yt_channel_feed_url(channel_id: str) -> str:
    return f"https://www.youtube.com/feeds/videos.xml?channel_id={channel_id}"


def parse_youtube_video_id(entry) -> str | None:
    video_id = entry.get("yt_videoid")
    if video_id:
        return video_id
    entry_id = entry.get("id") or ""
    match = re.search(r"[:/](?P<vid>[A-Za-z0-9_-]{6,})$", entry_id)
    if match:
        return match.group("vid")
    link = entry.get("link") or ""
    match = re.search(r"[?&]v=([A-Za-z0-9_-]{6,})", link)
    return match.group(1) if match else None


def parse_pubdate(entry):
    if "published" in entry:
        try:
            parsed = dtparse.parse(entry["published"])
            if not parsed.tzinfo:
                parsed = parsed.replace(tzinfo=UTC)
            return parsed.astimezone(UTC)
        except Exception:
            pass
    return datetime.now(UTC)


def build_rows(entries):
    rows = []
    for entry in entries:
        video_id = parse_youtube_video_id(entry)
        if video_id:
            rows.append((parse_pubdate(entry), entry, video_id))
    rows.sort(key=lambda item: item[0], reverse=True)
    return rows


def create_thread(settings: WorkerSettings, first_text: str, second_text: str) -> bool:
    if settings.dry_run:
        log("DRY_RUN post 1:", first_text)
        log("DRY_RUN post 2:", second_text)
        return True

    response = requests.post(
        f"{settings.web_base_url}/post-thread",
        headers={"Content-Type": "application/json", "X-Internal-Token": settings.internal_api_token},
        data=json.dumps({"firstText": first_text, "secondText": second_text}),
        timeout=60,
    )
    if response.status_code != 200:
        log("post-thread failed", response.status_code, response.text)
        return False
    log("posted thread ok")
    return True


def maybe_mark_seen(settings: WorkerSettings, db: Database, feed_url, guid, media_id, published_at):
    if settings.dry_run:
        return
    db.mark_seen(feed_url, guid, media_id, published_at)


def build_summary_prompt(exclude_note: str) -> str:
    return (
        "You will be given podcast metadata and a snippet from a transcript. "
        "Decide if it is about the NBA team the Portland Trail Blazers, including players, coaches, "
        "front office, ownership, draft, trades, injuries, or season context. "
        "If the feed type is blazers, this is a dedicated Portland Trail Blazers show; summarize the episode "
        "unless the title and transcript are clearly unrelated to the team. "
        "Exclude any generic 'trailblazer' usages not about the NBA team. "
        "Use the title as context, but do not say an episode is about the Blazers unless the title or transcript "
        "supports that conclusion. "
        f"{exclude_note}\n\n"
        "Return JSON with fields: is_blazers (boolean), topic (short string), "
        "summary (<=300 chars, neutral tone)."
    )


VIDEO_OK = "ok"
VIDEO_RETRY_LATER = "retry_later"
VIDEO_SKIP_CANDIDATE = "skip_candidate"
VIDEO_POST_FAILED = "post_failed"


def handle_video(
    settings: WorkerSettings,
    db: Database,
    summarizer: GeminiSummarizer,
    config: dict,
    transcript_settings,
    poll_context: PollContext,
    feed_url: str,
    show_name: str,
    mode: str,
    entry,
    video_id: str,
) -> str:
    guid = entry.get("id") or entry.get("link") or video_id
    published_at = parse_pubdate(entry)
    title = (entry.get("title") or "").strip()
    keywords = [keyword.lower() for keyword in config.get("keywords_positive", [])]
    post_char_limit = int(config.get("post_char_limit", 300))

    if db.already_seen(feed_url, guid, video_id):
        dlog(settings, "skip: already seen", video_id)
        return VIDEO_OK
    cooldown_until = db.llm_cooldown_active()
    if cooldown_until:
        poll_context.llm_wait = True
        poll_context.llm_wait_reason = "cooldown"
        log("Gemini cooldown active until", cooldown_until.isoformat())
        return VIDEO_RETRY_LATER
    if not poll_context.has_llm_capacity():
        poll_context.llm_wait = True
        poll_context.llm_wait_reason = "budget"
        return VIDEO_RETRY_LATER
    if not db.summary_retry_ready(video_id, settings.llm_max_attempts):
        dlog(settings, "skip: Gemini retry not due", video_id)
        return VIDEO_RETRY_LATER
    if not settings.force_transcript_retry and not db.transcript_retry_ready(video_id, settings.transcript_max_attempts):
        dlog(settings, "skip: transcript retry not due", video_id)
        return VIDEO_RETRY_LATER
    if settings.force_transcript_retry:
        dlog(settings, "force transcript retry", video_id)

    try:
        result = fetch_transcript(video_id, transcript_settings, log=log)
        if not settings.dry_run:
            db.record_transcript_success(video_id)
    except TranscriptError as exc:
        if exc.error_type == "LiveUpcoming":
            log("skip upcoming live video", video_id)
            return VIDEO_SKIP_CANDIDATE
        if exc.transient:
            log("transient transcript failure", video_id, exc.error_type)
            if not settings.dry_run or settings.dry_run_record_transcript_retries:
                attempts, retry_at = db.record_transcript_failure(
                    video_id,
                    exc.error_type,
                    settings.transcript_retry_minutes,
                    settings.transcript_max_attempts,
                )
                log("transcript retry scheduled", video_id, "attempts", attempts, "next", retry_at)
            return VIDEO_RETRY_LATER
        log("permanent transcript failure", video_id, exc.error_type)
        maybe_mark_seen(settings, db, feed_url, guid, video_id, published_at)
        return VIDEO_OK

    start_seconds, _matched_text = first_keyword_hit(result.segments, keywords)
    if mode == "blazers":
        if start_seconds is None:
            dlog(settings, "no direct keyword hit", video_id, mode)
        snippet = result.full_text[:12000]
        jump_seconds = 0
    elif start_seconds is None:
        dlog(settings, "no direct keyword hit", video_id, mode)
        maybe_mark_seen(settings, db, feed_url, guid, video_id, published_at)
        return VIDEO_OK
    else:
        snippet = transcript_window(result.segments, start_seconds, window_seconds=180, char_limit=8000)
        jump_seconds = start_seconds

    model_input = build_model_input(mode, title, video_id, start_seconds is not None, snippet)
    if not poll_context.reserve_llm_call():
        return VIDEO_RETRY_LATER
    dlog(
        settings,
        "Gemini request",
        poll_context.llm_calls,
        "of",
        settings.llm_max_calls_per_poll if settings.llm_max_calls_per_poll >= 0 else "unlimited",
        video_id,
    )
    try:
        output = summarizer.summarize_json(build_summary_prompt(config.get("exclude_note", "")), model_input)
        db.record_summary_success(video_id)
    except LLMQuotaError as exc:
        cooldown_until = db.set_llm_cooldown(exc.cooldown_until, exc.error_type)
        poll_context.llm_wait = True
        poll_context.llm_wait_reason = "cooldown"
        attempts, retry_at = db.record_summary_failure(
            video_id,
            exc.error_type,
            settings.llm_retry_minutes,
            settings.llm_max_attempts,
        )
        log("Gemini quota exhausted; cooldown until", cooldown_until.isoformat())
        log("Gemini retry scheduled", video_id, "attempts", attempts, "next", retry_at)
        return VIDEO_RETRY_LATER
    except LLMError as exc:
        attempts, retry_at = db.record_summary_failure(
            video_id,
            exc.error_type,
            settings.llm_retry_minutes,
            settings.llm_max_attempts,
        )
        log("Gemini failure", video_id, exc.error_type)
        log("Gemini retry scheduled", video_id, "attempts", attempts, "next", retry_at)
        return VIDEO_RETRY_LATER
    if not output.get("is_blazers"):
        dlog(settings, "gemini says not blazers", video_id)
        maybe_mark_seen(settings, db, feed_url, guid, video_id, published_at)
        return VIDEO_OK

    link = youtube_link(video_id, jump_seconds)
    title_part = title or "New podcast episode"
    heading = f"{show_name} - {title_part}" if show_name else title_part
    if mode == "national":
        first_text = clamp_heading_with_link(heading, f"{fmt_mmss(jump_seconds)} {link}", post_char_limit)
    else:
        first_text = clamp_heading_with_link(heading, youtube_link(video_id), post_char_limit)
    second_text = (output.get("summary") or "").strip()

    posted = create_thread(
        settings,
        clamp_text(first_text, post_char_limit),
        clamp_text(second_text, post_char_limit),
    )
    if not posted:
        return VIDEO_POST_FAILED

    maybe_mark_seen(settings, db, feed_url, guid, video_id, published_at)
    return VIDEO_OK


def process_channel(
    settings: WorkerSettings,
    db: Database,
    summarizer: GeminiSummarizer,
    config: dict,
    transcript_settings,
    poll_context: PollContext,
    feed: dict,
    mode: str,
):
    channel_id = feed.get("youtube_channel_id")
    show_name = (feed.get("show_name") or feed.get("youtube_search") or "").strip()
    if show_name.lower().startswith(("http://", "https://")):
        show_name = ""
    feed_url = yt_channel_feed_url(channel_id)
    parsed = feedparser.parse(feed_url)
    entries = list(parsed.entries)
    dlog(settings, "feed", feed_url, "entries", len(entries))
    if not entries:
        return

    rows = build_rows(entries)
    if not rows:
        dlog(settings, "feed has no parseable video ids", feed_url)
        return

    baseline = db.get_feed_baseline(feed_url)
    latest = rows[0]
    latest_pub, _latest_entry, latest_video_id = latest
    if baseline is None or latest_pub > baseline or db.has_due_transcript_retry(latest_video_id, settings.transcript_max_attempts):
        candidates = [
            row
            for row in rows[: settings.max_feed_candidate_fallbacks]
            if baseline is None or row[0] > baseline or row[2] == latest_video_id
        ]
    else:
        candidates = []

    dlog(settings, "candidates", len(candidates), "baseline", baseline.isoformat() if baseline else None)
    all_posting_ok = True
    processed = 0
    newest_completed_pub = None
    for published_at, entry, video_id in candidates:
        if poll_context.llm_wait:
            break
        if processed >= settings.max_videos_per_feed:
            break
        outcome = handle_video(
            settings,
            db,
            summarizer,
            config,
            transcript_settings,
            poll_context,
            feed_url,
            show_name,
            mode,
            entry,
            video_id,
        )
        if outcome == VIDEO_SKIP_CANDIDATE:
            continue
        processed += 1
        if outcome == VIDEO_OK:
            newest_completed_pub = published_at if newest_completed_pub is None else max(newest_completed_pub, published_at)
        else:
            all_posting_ok = False
        break

    if not settings.dry_run and all_posting_ok and newest_completed_pub and (baseline is None or newest_completed_pub > baseline):
        db.set_feed_baseline(feed_url, newest_completed_pub)
    return processed


def poll_once(settings: WorkerSettings, db: Database, summarizer: GeminiSummarizer, config: dict, transcript_settings):
    cooldown_until = db.llm_cooldown_active()
    if cooldown_until:
        log("Gemini cooldown active until", cooldown_until.isoformat())
        return
    poll_context = PollContext(settings.llm_max_calls_per_poll)
    if not poll_context.has_llm_capacity():
        log("Gemini poll budget is 0; skipping poll")
        return
    log("polling...")
    remaining = settings.max_videos_per_poll
    feed_groups = []
    if settings.feed_mode in ("all", "national"):
        feed_groups.append(("national_feeds", "national"))
    if settings.feed_mode in ("all", "blazers"):
        feed_groups.append(("blazers_feeds", "blazers"))
    if not feed_groups:
        raise RuntimeError("FEED_MODE must be one of: all, national, blazers")

    for config_key, mode in feed_groups:
        for feed in config.get(config_key, []):
            if remaining <= 0:
                log("poll video budget reached")
                return
            channel_id = feed.get("youtube_channel_id")
            if not channel_id:
                log(f"skip {mode} feed without youtube_channel_id", feed.get("youtube_search") or feed.get("rss"))
                continue
            remaining -= process_channel(settings, db, summarizer, config, transcript_settings, poll_context, feed, mode) or 0
            if poll_context.llm_wait:
                if poll_context.llm_wait_reason == "budget":
                    log("Gemini poll budget reached")
                else:
                    log("Gemini poll paused", poll_context.llm_wait_reason or "waiting")
                return
            time.sleep(settings.scan_pause_seconds)


def loop():
    settings = WorkerSettings.from_env()
    config = load_config(settings)
    transcript_settings = settings_from_env()
    db = Database(settings.db_url)
    db.ensure_schema()
    if settings.reset_feed_state:
        db.reset_feed_state()
        log("RESET_FEED_STATE enabled: feed baselines and transcript retry state were cleared")
    if settings.reset_llm_state:
        db.reset_llm_state()
        log("RESET_LLM_STATE enabled: Gemini cooldown and summary retry state were cleared")
    summarizer = GeminiSummarizer(
        settings.gemini_key,
        settings.gemini_model,
        settings.gemini_thinking_level,
        settings.llm_quota_cooldown_minutes,
    )
    log("Gemini model", settings.gemini_model)
    if settings.gemini_model.startswith("gemini-3"):
        log("Gemini thinking level", settings.gemini_thinking_level)
    log("Gemini poll request budget", settings.llm_max_calls_per_poll if settings.llm_max_calls_per_poll >= 0 else "unlimited")
    if transcript_settings.ytdlp_cookies:
        log("yt-dlp cookies enabled")
    else:
        log("yt-dlp cookies not configured")
    if settings.dry_run:
        log("DRY_RUN enabled: posts and episode state will not be written")

    while True:
        poll_once(settings, db, summarizer, config, transcript_settings)
        if settings.force_one_shot:
            log("FORCE_ONE_SHOT complete")
            return
        log("sleep", settings.poll_interval_seconds, "s")
        time.sleep(settings.poll_interval_seconds)


if __name__ == "__main__":
    loop()

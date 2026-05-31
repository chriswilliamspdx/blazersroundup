import json
import os
import re
from dataclasses import dataclass
from typing import Callable

from yt_dlp import YoutubeDL

try:
    from youtube_transcript_api import YouTubeTranscriptApi
    try:
        from youtube_transcript_api._errors import (
            CouldNotRetrieveTranscript,
            IpBlocked,
            NoTranscriptFound,
            RequestBlocked,
            TranscriptsDisabled,
        )
    except ImportError:
        from youtube_transcript_api import CouldNotRetrieveTranscript, NoTranscriptFound, TranscriptsDisabled

        class IpBlocked(CouldNotRetrieveTranscript):
            pass

        class RequestBlocked(CouldNotRetrieveTranscript):
            pass
except ModuleNotFoundError as exc:
    raise RuntimeError(
        "Missing dependency 'youtube-transcript-api'. Add it to worker/requirements.txt and redeploy."
    ) from exc


LANGUAGE_PRIORITY = ["en", "en-US", "en-GB"]
CAPTION_FORMAT_PRIORITY = ["json3", "vtt"]


@dataclass
class TranscriptSettings:
    proxy_enabled: bool = False
    swiftshadow_countries: list[str] | None = None
    proxy_attempts: int = 2
    ytdlp_cookies: str | None = None
    ytdlp_extractor_clients: list[str] | None = None
    ytdlp_sleep_requests: float = 1.0


@dataclass
class TranscriptResult:
    full_text: str
    segments: list[tuple[float, float, str]]
    provider: str


class TranscriptError(Exception):
    def __init__(self, message: str, error_type: str, transient: bool = True):
        super().__init__(message)
        self.error_type = error_type
        self.transient = transient


def _clean_caption_text(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text or "")
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def parse_json3_to_segments(text: str) -> list[tuple[float, float, str]]:
    data = json.loads(text)
    segments = []
    for event in data.get("events", []):
        chunks = event.get("segs") or []
        cue = _clean_caption_text("".join(chunk.get("utf8", "") for chunk in chunks))
        if not cue:
            continue
        start = float(event.get("tStartMs", 0)) / 1000.0
        duration = float(event.get("dDurationMs") or 0) / 1000.0
        segments.append((start, duration, cue))
    return segments


def _timestamp_to_seconds(timestamp: str) -> float:
    timestamp = timestamp.strip().replace(",", ".")
    parts = timestamp.split(":")
    if len(parts) == 3:
        hours, minutes, seconds = parts
        return int(hours) * 3600 + int(minutes) * 60 + float(seconds)
    if len(parts) == 2:
        minutes, seconds = parts
        return int(minutes) * 60 + float(seconds)
    return float(timestamp)


def parse_vtt_to_segments(text: str) -> list[tuple[float, float, str]]:
    segments = []
    lines = [line.rstrip("\r") for line in text.splitlines()]
    index = 0
    while index < len(lines):
        line = lines[index].strip()
        index += 1
        if not line or line.upper().startswith("WEBVTT") or line.startswith(("NOTE", "STYLE", "REGION")):
            continue

        time_line = line
        if "-->" not in time_line and index < len(lines):
            time_line = lines[index].strip()
            index += 1
        if "-->" not in time_line:
            continue

        try:
            raw_start, raw_end = [part.strip() for part in time_line.split("-->", 1)]
            raw_end = raw_end.split()[0]
            start = _timestamp_to_seconds(raw_start)
            end = _timestamp_to_seconds(raw_end)
        except Exception:
            continue

        cue_lines = []
        while index < len(lines) and lines[index].strip():
            cue_lines.append(lines[index].strip())
            index += 1
        cue = _clean_caption_text(" ".join(cue_lines))
        if cue:
            segments.append((start, max(0.0, end - start), cue))
    return segments


def _segments_to_result(segments: list[tuple[float, float, str]], provider: str) -> TranscriptResult:
    full_text = " ".join(text for _start, _duration, text in segments if text).strip()
    if not full_text:
        raise TranscriptError(f"{provider}: transcript was empty", "empty_transcript", transient=True)
    return TranscriptResult(full_text=full_text, segments=segments, provider=provider)


def _classify_yta_error(exc: Exception) -> TranscriptError:
    if isinstance(exc, (NoTranscriptFound, TranscriptsDisabled)):
        return TranscriptError(str(exc), exc.__class__.__name__, transient=False)
    if isinstance(exc, (RequestBlocked, IpBlocked)):
        return TranscriptError(str(exc), exc.__class__.__name__, transient=True)
    if isinstance(exc, CouldNotRetrieveTranscript):
        return TranscriptError(str(exc), exc.__class__.__name__, transient=True)
    return TranscriptError(str(exc), exc.__class__.__name__, transient=True)


def fetch_with_youtube_transcript_api(video_id: str, proxy_url: str | None = None) -> TranscriptResult:
    kwargs = {}
    if proxy_url:
        from youtube_transcript_api.proxies import GenericProxyConfig

        kwargs["proxy_config"] = GenericProxyConfig(http_url=proxy_url, https_url=proxy_url)

    api = YouTubeTranscriptApi(**kwargs)
    try:
        fetched = api.fetch(video_id, languages=LANGUAGE_PRIORITY)
        raw = fetched.to_raw_data() if hasattr(fetched, "to_raw_data") else fetched
        segments = [
            (
                float(item.get("start", 0.0)),
                float(item.get("duration", 0.0)),
                _clean_caption_text(item.get("text", "")),
            )
            for item in raw
            if _clean_caption_text(item.get("text", ""))
        ]
        provider = "youtube-transcript-api" if not proxy_url else "youtube-transcript-api-proxy"
        return _segments_to_result(segments, provider)
    except Exception as exc:
        raise _classify_yta_error(exc) from exc


def _pick_caption_track(info: dict) -> tuple[str, str]:
    subtitles = info.get("subtitles") or {}
    automatic_captions = info.get("automatic_captions") or {}
    for language in LANGUAGE_PRIORITY:
        tracks = subtitles.get(language) or automatic_captions.get(language) or []
        ranked = [
            track
            for track in tracks
            if track.get("ext") in CAPTION_FORMAT_PRIORITY and track.get("url")
        ]
        ranked.sort(key=lambda track: CAPTION_FORMAT_PRIORITY.index(track["ext"]))
        if ranked:
            return ranked[0]["url"], ranked[0]["ext"]
    raise TranscriptError("yt-dlp: no English json3 or vtt caption track found", "NoCaptionTrack", transient=False)


def fetch_with_ytdlp(video_id: str, settings: TranscriptSettings, proxy_url: str | None = None) -> TranscriptResult:
    url = f"https://www.youtube.com/watch?v={video_id}"
    ydl_opts = {
        "quiet": True,
        "skip_download": True,
        "sleep_requests": settings.ytdlp_sleep_requests,
        "extractor_args": {"youtube": {"player_client": settings.ytdlp_extractor_clients or ["android", "web"]}},
    }
    if settings.ytdlp_cookies:
        ydl_opts["cookiefile"] = settings.ytdlp_cookies
    if proxy_url:
        ydl_opts["proxy"] = proxy_url

    try:
        with YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            caption_url, caption_ext = _pick_caption_track(info)
            body = ydl.urlopen(caption_url).read().decode("utf-8", "ignore")
    except TranscriptError:
        raise
    except Exception as exc:
        raise TranscriptError(str(exc), exc.__class__.__name__, transient=True) from exc

    try:
        segments = parse_json3_to_segments(body) if caption_ext == "json3" else parse_vtt_to_segments(body)
    except Exception as exc:
        raise TranscriptError(str(exc), f"{caption_ext}_parse_error", transient=True) from exc
    provider = "yt-dlp-caption" if not proxy_url else "yt-dlp-caption-proxy"
    return _segments_to_result(segments, provider)


def _swiftshadow_proxy_factory(countries: list[str] | None) -> Callable[[], str]:
    from swiftshadow.classes import ProxyInterface

    manager = ProxyInterface(countries=countries or ["US"], protocol="http", maxProxies=10, autoRotate=True)

    def next_proxy() -> str:
        proxy = manager.get()
        return proxy.as_string()

    return next_proxy


def fetch_transcript(video_id: str, settings: TranscriptSettings, log: Callable[..., None] = print) -> TranscriptResult:
    errors: list[TranscriptError] = []

    for provider_name, call in (
        ("youtube-transcript-api", lambda: fetch_with_youtube_transcript_api(video_id)),
        ("yt-dlp-caption", lambda: fetch_with_ytdlp(video_id, settings)),
    ):
        try:
            result = call()
            log("transcript ok", video_id, result.provider)
            return result
        except TranscriptError as exc:
            errors.append(exc)
            log("transcript provider failed", video_id, provider_name, exc.error_type)
            if not exc.transient and provider_name == "yt-dlp-caption":
                raise exc

    if settings.proxy_enabled:
        try:
            next_proxy = _swiftshadow_proxy_factory(settings.swiftshadow_countries)
        except Exception as exc:
            log("swiftshadow unavailable", exc.__class__.__name__, str(exc))
            next_proxy = None

        if next_proxy:
            for attempt in range(max(1, settings.proxy_attempts)):
                try:
                    proxy_url = next_proxy()
                    log("trying transcript proxy", attempt + 1)
                    try:
                        result = fetch_with_youtube_transcript_api(video_id, proxy_url=proxy_url)
                    except TranscriptError:
                        result = fetch_with_ytdlp(video_id, settings, proxy_url=proxy_url)
                    log("transcript ok", video_id, result.provider)
                    return result
                except TranscriptError as exc:
                    errors.append(exc)
                    log("transcript proxy failed", video_id, exc.error_type)
                except Exception as exc:
                    errors.append(TranscriptError(str(exc), exc.__class__.__name__, transient=True))
                    log("transcript proxy failed", video_id, exc.__class__.__name__)

    if errors:
        all_permanent = all(not error.transient for error in errors)
        last = errors[-1]
        raise TranscriptError(str(last), last.error_type, transient=not all_permanent) from last
    raise TranscriptError("transcript providers failed", "TranscriptUnavailable", transient=True)


def settings_from_env() -> TranscriptSettings:
    countries = [item.strip().upper() for item in os.getenv("SWIFTSHADOW_COUNTRIES", "US").split(",") if item.strip()]
    clients = [item.strip() for item in os.getenv("YTDLP_EXTRACTOR_CLIENTS", "android,web").split(",") if item.strip()]
    return TranscriptSettings(
        proxy_enabled=os.getenv("TRANSCRIPT_PROXY_ENABLED", "0") == "1",
        swiftshadow_countries=countries or ["US"],
        proxy_attempts=int(os.getenv("TRANSCRIPT_PROXY_ATTEMPTS", "2")),
        ytdlp_cookies=os.getenv("YTDLP_COOKIES") or None,
        ytdlp_extractor_clients=clients or ["android", "web"],
        ytdlp_sleep_requests=float(os.getenv("YTDLP_SLEEP_REQUESTS", "1.0")),
    )

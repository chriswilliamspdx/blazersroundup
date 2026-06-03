import base64
import json
import os
import random
import re
import tempfile
import time
from dataclasses import dataclass
from typing import Callable

import requests
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
COOKIE_FILE_PATH = os.path.join(tempfile.gettempdir(), "ytdlp-cookies.txt")
MISSING_TRANSCRIPT_ERROR_TYPES = {
    "NoTranscriptFound",
    "TranscriptsDisabled",
    "NoCaptionTrack",
    "empty_transcript",
}
BLOCKED_TRANSCRIPT_ERROR_TYPES = {
    "RequestBlocked",
    "IpBlocked",
}
PROXY_BLOCKED_ERROR_TYPES = {
    "HTTPError",
    "IpBlocked",
    "RequestBlocked",
}
DEFAULT_PROXY_LIST_URLS = [
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/yuceltoluyag/GoodProxy/main/GoodProxy.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/proxies.txt",
]
PROXY_LIST_CACHE: dict[str, object] = {"loaded_at": 0.0, "urls": (), "proxies": []}
PROXY_HEALTH_CACHE: dict[str, dict[str, object]] = {}
PROXY_TOKEN_RE = re.compile(
    r"^(?:(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)://)?(?P<host>[A-Za-z0-9_.-]+):(?P<port>\d{1,5})$"
)


@dataclass
class TranscriptSettings:
    proxy_enabled: bool = False
    proxy_sources: list[str] | None = None
    swiftshadow_countries: list[str] | None = None
    swiftshadow_protocol: str = "https"
    swiftshadow_protocols: list[str] | None = None
    proxy_attempts: int = 2
    proxy_ytdlp_enabled: bool = True
    proxy_ytdlp_attempts: int = 1
    request_timeout_seconds: float = 10.0
    ytdlp_cookies: str | None = None
    ytdlp_extractor_clients: list[str] | None = None
    ytdlp_sleep_requests: float = 1.0
    ytdlp_socket_timeout_seconds: float = 8.0
    ytdlp_retries: int = 1
    ytdlp_extractor_retries: int = 1
    oneproxy_api_url: str | None = None
    oneproxy_country: str | None = None
    oneproxy_protocols: list[str] | None = None
    oneproxy_limit: int = 20
    oneproxy_min_quality: int | None = None
    oneproxy_can_access_google: bool | None = None
    oneproxy_strategy: str = "quality"
    oneproxy_max_latency: int | None = None
    proxy_list_urls: list[str] | None = None
    proxy_list_protocols: list[str] | None = None
    proxy_list_refresh_seconds: int = 3600
    proxy_list_max_proxies: int = 2000
    proxy_timeout_seconds: float = 10.0
    proxy_bad_cooldown_seconds: int = 3600
    proxy_blocked_cooldown_seconds: int = 21600
    proxy_selection_attempts: int = 25


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


class TimeoutSession(requests.Session):
    def __init__(self, timeout_seconds: float):
        super().__init__()
        self.timeout_seconds = timeout_seconds

    def request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", self.timeout_seconds)
        return super().request(method, url, **kwargs)


def is_live_unavailable_message(message: str) -> bool:
    message = (message or "").lower()
    return any(
        phrase in message
        for phrase in (
            "live event will begin",
            "premiere will begin",
            "premieres in",
            "waiting for this live stream",
            "this live stream recording is not available",
        )
    )


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
    if is_live_unavailable_message(str(exc)):
        return TranscriptError(str(exc), "LiveUpcoming", transient=False)
    if isinstance(exc, CouldNotRetrieveTranscript):
        return TranscriptError(str(exc), exc.__class__.__name__, transient=True)
    return TranscriptError(str(exc), exc.__class__.__name__, transient=True)


def fetch_with_youtube_transcript_api(
    video_id: str,
    proxy_url: str | None = None,
    timeout_seconds: float = 10.0,
) -> TranscriptResult:
    kwargs = {"http_client": TimeoutSession(timeout_seconds)}
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
        "socket_timeout": settings.ytdlp_socket_timeout_seconds,
        "retries": settings.ytdlp_retries,
        "fragment_retries": settings.ytdlp_retries,
        "extractor_retries": settings.ytdlp_extractor_retries,
        "file_access_retries": settings.ytdlp_retries,
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
        if is_live_unavailable_message(str(exc)):
            raise TranscriptError(str(exc), "LiveUpcoming", transient=False) from exc
        raise TranscriptError(str(exc), exc.__class__.__name__, transient=True) from exc

    try:
        segments = parse_json3_to_segments(body) if caption_ext == "json3" else parse_vtt_to_segments(body)
    except Exception as exc:
        raise TranscriptError(str(exc), f"{caption_ext}_parse_error", transient=True) from exc
    provider = "yt-dlp-caption" if not proxy_url else "yt-dlp-caption-proxy"
    return _segments_to_result(segments, provider)


def _normalize_proxy_url(value: str, default_scheme: str = "http") -> str | None:
    value = (value or "").strip()
    if not value:
        return None
    if "://" not in value:
        value = f"{default_scheme}://{value}"
    return value


def _proxy_failure_cooldown_seconds(settings: TranscriptSettings, error_type: str) -> int:
    if error_type in PROXY_BLOCKED_ERROR_TYPES:
        return max(0, settings.proxy_blocked_cooldown_seconds)
    return max(0, settings.proxy_bad_cooldown_seconds)


def _proxy_is_cooling_down(proxy_url: str, now: float | None = None) -> bool:
    state = PROXY_HEALTH_CACHE.get(proxy_url)
    if not state:
        return False

    now = time.time() if now is None else now
    blocked_until = float(state.get("blocked_until") or 0.0)
    if blocked_until <= now:
        PROXY_HEALTH_CACHE.pop(proxy_url, None)
        return False
    return True


def _record_proxy_failure(proxy_url: str | None, error_type: str, settings: TranscriptSettings) -> None:
    if not proxy_url:
        return

    cooldown = _proxy_failure_cooldown_seconds(settings, error_type)
    if cooldown <= 0:
        return

    now = time.time()
    state = PROXY_HEALTH_CACHE.get(proxy_url) or {}
    fail_count = int(state.get("fail_count") or 0) + 1
    multiplier = min(4, 2 ** max(0, fail_count - 1))
    PROXY_HEALTH_CACHE[proxy_url] = {
        "blocked_until": now + cooldown * multiplier,
        "fail_count": fail_count,
        "last_error_type": error_type,
        "last_failed_at": now,
    }


def _record_proxy_success(proxy_url: str | None) -> None:
    if proxy_url:
        PROXY_HEALTH_CACHE.pop(proxy_url, None)


def _next_usable_proxy(
    source: str,
    next_proxy: Callable[[], str],
    settings: TranscriptSettings,
    log: Callable[..., None] | None = None,
) -> str:
    attempts = max(1, settings.proxy_selection_attempts)
    skipped = 0
    fallback_proxy = None
    for _ in range(attempts):
        proxy_url = next_proxy()
        fallback_proxy = proxy_url
        if not _proxy_is_cooling_down(proxy_url):
            if skipped and log:
                log("skipped unhealthy transcript proxies", source, skipped)
            return proxy_url
        skipped += 1

    if skipped and log:
        log("all sampled transcript proxies unhealthy", source, skipped, "using least-recent candidate")
    if fallback_proxy:
        return fallback_proxy
    raise TranscriptError("proxy source did not return a proxy", "NoProxy", transient=True)


def _candidate_proxy_tokens(text: str) -> list[str]:
    tokens: list[str] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        for token in re.split(r"[\s,;]+", line):
            token = token.strip().strip("\"'()[]{}")
            if token:
                tokens.append(token)
    return tokens


def _proxy_from_raw_list_token(token: str, allowed_protocols: list[str] | None = None) -> str | None:
    allowed = {item.lower() for item in (allowed_protocols or ["http", "https"])}
    match = PROXY_TOKEN_RE.match((token or "").strip())
    if not match:
        return None

    scheme = (match.group("scheme") or "http").lower()
    if scheme not in allowed:
        return None

    port = int(match.group("port"))
    if port < 1 or port > 65535:
        return None

    return f"{scheme}://{match.group('host')}:{port}"


def _load_raw_proxy_lists(settings: TranscriptSettings, log: Callable[..., None] | None = None) -> list[str]:
    urls = settings.proxy_list_urls or DEFAULT_PROXY_LIST_URLS
    urls = [url.strip() for url in urls if url.strip()]
    urls_key = tuple(urls)
    now = time.time()
    cached_urls = tuple(PROXY_LIST_CACHE.get("urls") or ())
    cached_proxies = list(PROXY_LIST_CACHE.get("proxies") or [])
    loaded_at = float(PROXY_LIST_CACHE.get("loaded_at") or 0.0)

    if cached_proxies and cached_urls == urls_key and now - loaded_at < max(60, settings.proxy_list_refresh_seconds):
        proxies = cached_proxies
    else:
        session = TimeoutSession(settings.proxy_timeout_seconds)
        session.headers.update({"User-Agent": "blazersroundup/1.0"})
        seen: set[str] = set()
        proxies = []
        protocols = settings.proxy_list_protocols or ["http", "https"]

        for url in urls:
            try:
                response = session.get(url)
                response.raise_for_status()
            except Exception as exc:
                if log:
                    log("proxy list unavailable", url, exc.__class__.__name__)
                continue

            before = len(proxies)
            for token in _candidate_proxy_tokens(response.text):
                proxy_url = _proxy_from_raw_list_token(token, protocols)
                if proxy_url and proxy_url not in seen:
                    seen.add(proxy_url)
                    proxies.append(proxy_url)
            if log:
                log("proxy list loaded", url, len(proxies) - before, "usable")

        random.shuffle(proxies)
        if settings.proxy_list_max_proxies > 0:
            proxies = proxies[: settings.proxy_list_max_proxies]
        PROXY_LIST_CACHE.update({"loaded_at": now, "urls": urls_key, "proxies": proxies})

    shuffled = list(proxies)
    random.shuffle(shuffled)
    if log:
        log("proxy list pool ready", len(shuffled), "usable proxies")
    return shuffled


def _raw_proxy_list_factory(settings: TranscriptSettings, log: Callable[..., None] | None = None) -> Callable[[], str] | None:
    proxies = _load_raw_proxy_lists(settings, log=log)
    if not proxies:
        return None

    index = -1

    def next_proxy() -> str:
        nonlocal index
        index = (index + 1) % len(proxies)
        return proxies[index]

    return next_proxy


def _swiftshadow_proxy_factory(settings: TranscriptSettings) -> Callable[[], str] | None:
    from swiftshadow.classes import ProxyInterface

    managers = []
    protocols = settings.swiftshadow_protocols or [settings.swiftshadow_protocol or "https"]
    last_error = None
    for protocol in protocols:
        try:
            managers.append(
                (
                    protocol,
                    ProxyInterface(
                        countries=settings.swiftshadow_countries or ["US"],
                        protocol=protocol,
                        maxProxies=10,
                        autoRotate=True,
                    ),
                )
            )
        except Exception as exc:
            last_error = exc
    if not managers:
        if last_error:
            raise last_error
        return None

    index = -1

    def next_proxy() -> str:
        nonlocal index
        index = (index + 1) % len(managers)
        protocol, manager = managers[index]
        proxy = manager.get()
        return _normalize_proxy_url(proxy.as_string(), default_scheme=protocol)

    return next_proxy


def _proxy_url_from_oneproxy_item(item) -> str | None:
    if isinstance(item, str):
        return _normalize_proxy_url(item)
    if not isinstance(item, dict):
        return None

    for key in ("proxy", "url", "proxy_url", "connection_url"):
        if item.get(key):
            return _normalize_proxy_url(str(item[key]), default_scheme=str(item.get("protocol") or "http"))

    host = item.get("host") or item.get("ip") or item.get("address")
    port = item.get("port")
    if not host or not port:
        return None
    protocol = str(item.get("protocol") or "http").lower()
    username = item.get("username") or item.get("user")
    password = item.get("password") or item.get("pass")
    auth = f"{username}:{password}@" if username and password else ""
    return _normalize_proxy_url(f"{protocol}://{auth}{host}:{port}", default_scheme=protocol)


def _oneproxy_proxy_factory(settings: TranscriptSettings) -> Callable[[], str] | None:
    if not settings.oneproxy_api_url:
        return None

    protocols = settings.oneproxy_protocols or ["http", "https"]
    if settings.oneproxy_api_url.rstrip("/").endswith("/rotate"):
        index = -1

        def next_proxy() -> str:
            nonlocal index
            index = (index + 1) % len(protocols)
            params = {
                "strategy": settings.oneproxy_strategy,
                "protocol": protocols[index],
            }
            if settings.oneproxy_country:
                params["country_code"] = settings.oneproxy_country
            if settings.oneproxy_min_quality is not None:
                params["min_quality"] = settings.oneproxy_min_quality
            if settings.oneproxy_max_latency is not None:
                params["max_latency"] = settings.oneproxy_max_latency
            response = requests.get(settings.oneproxy_api_url, params=params, timeout=settings.proxy_timeout_seconds)
            response.raise_for_status()
            proxy_url = _proxy_url_from_oneproxy_item(response.json())
            if not proxy_url:
                raise TranscriptError("1proxy rotate response did not include a proxy URL", "NoProxy", transient=True)
            return proxy_url

        return next_proxy

    params = {"limit": settings.oneproxy_limit}
    if settings.oneproxy_country:
        params["country_code"] = settings.oneproxy_country
    if len(protocols) == 1:
        params["protocol"] = protocols[0]
    if settings.oneproxy_min_quality is not None:
        params["min_quality"] = settings.oneproxy_min_quality
    if settings.oneproxy_can_access_google is not None:
        params["can_access_google"] = str(settings.oneproxy_can_access_google).lower()

    response = requests.get(settings.oneproxy_api_url, params=params, timeout=settings.proxy_timeout_seconds)
    response.raise_for_status()
    payload = response.json()
    items = payload
    if isinstance(payload, dict):
        for key in ("proxies", "data", "items", "results"):
            if isinstance(payload.get(key), list):
                items = payload[key]
                break
        else:
            items = [payload] if _proxy_url_from_oneproxy_item(payload) else []

    if not isinstance(items, list):
        return None

    proxies = []
    for item in items:
        proxy_url = _proxy_url_from_oneproxy_item(item)
        if proxy_url:
            proxies.append(proxy_url)
    if not proxies:
        return None

    index = -1

    def next_proxy() -> str:
        nonlocal index
        index = (index + 1) % len(proxies)
        return proxies[index]

    return next_proxy


def env_first(*names: str) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


def cookiefile_from_env() -> str | None:
    cookie_path = env_first("YTDLP_COOKIES", "ytdlp_cookies")
    if cookie_path:
        return cookie_path

    cookie_text = env_first("YTDLP_COOKIES_TEXT", "ytdlp_cookies_text")
    cookie_b64 = env_first("YTDLP_COOKIES_B64", "ytdlp_cookies_b64")
    if cookie_b64 and not cookie_text:
        cookie_text = base64.b64decode(cookie_b64).decode("utf-8")
    if not cookie_text:
        return None

    os.makedirs(os.path.dirname(COOKIE_FILE_PATH), exist_ok=True)
    with open(COOKIE_FILE_PATH, "w", encoding="utf-8") as file:
        file.write(cookie_text.strip() + "\n")
    os.chmod(COOKIE_FILE_PATH, 0o600)
    return COOKIE_FILE_PATH


def fetch_transcript(video_id: str, settings: TranscriptSettings, log: Callable[..., None] = print) -> TranscriptResult:
    errors: list[TranscriptError] = []

    for provider_name, call in (
        ("youtube-transcript-api", lambda: fetch_with_youtube_transcript_api(video_id, timeout_seconds=settings.request_timeout_seconds)),
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
        has_missing_transcript_signal = any(error.error_type in MISSING_TRANSCRIPT_ERROR_TYPES for error in errors)
        has_blocked_transcript_signal = any(error.error_type in BLOCKED_TRANSCRIPT_ERROR_TYPES for error in errors)
        if has_missing_transcript_signal and not has_blocked_transcript_signal:
            raise TranscriptError(
                "transcript captions are missing or not ready yet",
                "TranscriptNotReadyOrDisabled",
                transient=True,
            )

        proxy_factories = []
        for source in settings.proxy_sources or ["swiftshadow"]:
            source = source.strip().lower()
            try:
                if source == "swiftshadow":
                    factory = _swiftshadow_proxy_factory(settings)
                elif source in ("1proxy", "oneproxy"):
                    factory = _oneproxy_proxy_factory(settings)
                elif source in ("proxylist", "rawlist", "raw"):
                    factory = _raw_proxy_list_factory(settings, log=log)
                else:
                    log("unknown transcript proxy source", source)
                    factory = None
            except Exception as exc:
                log(f"{source} unavailable", exc.__class__.__name__, str(exc))
                factory = None
            if factory:
                proxy_factories.append((source, factory))

        for source, next_proxy in proxy_factories:
            for attempt in range(max(1, settings.proxy_attempts)):
                proxy_url = None
                try:
                    proxy_url = _next_usable_proxy(source, next_proxy, settings, log=log)
                    log("trying transcript proxy", source, "youtube-transcript-api", attempt + 1)
                    result = fetch_with_youtube_transcript_api(
                        video_id,
                        proxy_url=proxy_url,
                        timeout_seconds=settings.request_timeout_seconds,
                    )
                    _record_proxy_success(proxy_url)
                    log("transcript ok", video_id, result.provider)
                    return result
                except TranscriptError as exc:
                    if exc.error_type == "LiveUpcoming":
                        raise exc
                    _record_proxy_failure(proxy_url, exc.error_type, settings)
                    errors.append(exc)
                    log("transcript proxy failed", video_id, exc.error_type)
                except Exception as exc:
                    _record_proxy_failure(proxy_url, exc.__class__.__name__, settings)
                    errors.append(TranscriptError(str(exc), exc.__class__.__name__, transient=True))
                    log("transcript proxy failed", video_id, exc.__class__.__name__)

        if settings.proxy_ytdlp_enabled:
            for source, next_proxy in proxy_factories:
                for attempt in range(max(0, settings.proxy_ytdlp_attempts)):
                    proxy_url = None
                    try:
                        proxy_url = _next_usable_proxy(source, next_proxy, settings, log=log)
                        log("trying transcript proxy", source, "yt-dlp", attempt + 1)
                        result = fetch_with_ytdlp(video_id, settings, proxy_url=proxy_url)
                        _record_proxy_success(proxy_url)
                        log("transcript ok", video_id, result.provider)
                        return result
                    except TranscriptError as exc:
                        if exc.error_type == "LiveUpcoming":
                            raise exc
                        _record_proxy_failure(proxy_url, exc.error_type, settings)
                        errors.append(exc)
                        log("transcript proxy failed", video_id, exc.error_type)
                    except Exception as exc:
                        _record_proxy_failure(proxy_url, exc.__class__.__name__, settings)
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
    proxy_sources = [
        item.strip().lower()
        for item in os.getenv("TRANSCRIPT_PROXY_SOURCES", "proxylist,1proxy,swiftshadow").split(",")
        if item.strip()
    ]
    swiftshadow_protocols = [
        item.strip().lower() for item in os.getenv("SWIFTSHADOW_PROTOCOLS", os.getenv("SWIFTSHADOW_PROTOCOL", "http,https")).split(",") if item.strip()
    ]
    oneproxy_protocols = [item.strip().lower() for item in os.getenv("ONEPROXY_PROTOCOLS", "http,https").split(",") if item.strip()]
    proxy_list_urls = [
        item.strip()
        for item in os.getenv("TRANSCRIPT_PROXY_LIST_URLS", ",".join(DEFAULT_PROXY_LIST_URLS)).split(",")
        if item.strip()
    ]
    proxy_list_protocols = [
        item.strip().lower()
        for item in os.getenv("TRANSCRIPT_PROXY_LIST_PROTOCOLS", "http,https").split(",")
        if item.strip()
    ]
    oneproxy_min_quality = os.getenv("ONEPROXY_MIN_QUALITY")
    oneproxy_can_access_google = os.getenv("ONEPROXY_CAN_ACCESS_GOOGLE")
    oneproxy_max_latency = os.getenv("ONEPROXY_MAX_LATENCY")
    return TranscriptSettings(
        proxy_enabled=os.getenv("TRANSCRIPT_PROXY_ENABLED", "0") == "1",
        proxy_sources=proxy_sources or ["swiftshadow"],
        swiftshadow_countries=countries or ["US"],
        swiftshadow_protocol=os.getenv("SWIFTSHADOW_PROTOCOL", swiftshadow_protocols[0] if swiftshadow_protocols else "http").lower(),
        swiftshadow_protocols=swiftshadow_protocols or ["http", "https"],
        proxy_attempts=int(os.getenv("TRANSCRIPT_PROXY_ATTEMPTS", "2")),
        proxy_ytdlp_enabled=os.getenv("TRANSCRIPT_PROXY_YTDLP_ENABLED", "1") == "1",
        proxy_ytdlp_attempts=int(os.getenv("TRANSCRIPT_PROXY_YTDLP_ATTEMPTS", "1")),
        request_timeout_seconds=float(os.getenv("TRANSCRIPT_REQUEST_TIMEOUT_SECONDS", os.getenv("TRANSCRIPT_PROXY_TIMEOUT_SECONDS", "10.0"))),
        ytdlp_cookies=cookiefile_from_env(),
        ytdlp_extractor_clients=clients or ["android", "web"],
        ytdlp_sleep_requests=float(os.getenv("YTDLP_SLEEP_REQUESTS", "1.0")),
        ytdlp_socket_timeout_seconds=float(os.getenv("YTDLP_SOCKET_TIMEOUT_SECONDS", "8.0")),
        ytdlp_retries=int(os.getenv("YTDLP_RETRIES", "1")),
        ytdlp_extractor_retries=int(os.getenv("YTDLP_EXTRACTOR_RETRIES", "1")),
        oneproxy_api_url=os.getenv("ONEPROXY_API_URL", "https://1proxy-api.aitradepulse.com/api/v1/proxies/rotate"),
        oneproxy_country=os.getenv("ONEPROXY_COUNTRY", "US") or None,
        oneproxy_protocols=oneproxy_protocols or ["http", "https"],
        oneproxy_limit=int(os.getenv("ONEPROXY_LIMIT", "20")),
        oneproxy_min_quality=int(oneproxy_min_quality) if oneproxy_min_quality else None,
        oneproxy_can_access_google=(
            None
            if oneproxy_can_access_google is None
            else oneproxy_can_access_google.strip().lower() in ("1", "true", "yes")
        ),
        oneproxy_strategy=os.getenv("ONEPROXY_STRATEGY", "quality"),
        oneproxy_max_latency=int(oneproxy_max_latency) if oneproxy_max_latency else None,
        proxy_list_urls=proxy_list_urls or DEFAULT_PROXY_LIST_URLS,
        proxy_list_protocols=proxy_list_protocols or ["http", "https"],
        proxy_list_refresh_seconds=int(os.getenv("TRANSCRIPT_PROXY_LIST_REFRESH_SECONDS", "3600")),
        proxy_list_max_proxies=int(os.getenv("TRANSCRIPT_PROXY_LIST_MAX_PROXIES", "2000")),
        proxy_timeout_seconds=float(os.getenv("TRANSCRIPT_PROXY_TIMEOUT_SECONDS", "10.0")),
        proxy_bad_cooldown_seconds=int(os.getenv("TRANSCRIPT_PROXY_BAD_COOLDOWN_SECONDS", "3600")),
        proxy_blocked_cooldown_seconds=int(os.getenv("TRANSCRIPT_PROXY_BLOCKED_COOLDOWN_SECONDS", "21600")),
        proxy_selection_attempts=int(os.getenv("TRANSCRIPT_PROXY_SELECTION_ATTEMPTS", "25")),
    )

from __future__ import annotations

import html
import json
import os
import re
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from text_utils import clamp_text, first_keyword_hit, has_keyword, normalize_spaces


UTC = timezone.utc
LAST_DRY_RUN_NEWS_SCAN_AT = None
NEWS_USER_AGENT = (
    "Mozilla/5.0 (compatible; BlazersRoundupNewsBot/1.0; "
    "+https://github.com/chriswilliamspdx/blazersroundup)"
)
GOOGLE_NEWS_HOSTS = {"news.google.com", "www.news.google.com"}
GOOGLE_RELATED_HOST_SUFFIXES = (
    "google.com",
    "googleusercontent.com",
    "gstatic.com",
    "ggpht.com",
)
NON_ARTICLE_HOSTS = {
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
}
NON_ARTICLE_PATH_EXTENSIONS = (
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".json",
    ".png",
    ".svg",
    ".webp",
    ".xml",
)
TRACKING_QUERY_PARAMS = {
    "fbclid",
    "gclid",
    "igshid",
    "mc_cid",
    "mc_eid",
    "ocid",
    "ref",
    "smid",
}
GENERIC_BROAD_TERMS = {"portland", "blazers"}
DEFAULT_NEWS_CONFIG_PATHS = ("/app/config/news.yaml", "config/news.yaml")


@dataclass
class NewsSettings:
    enabled: bool
    dry_run: bool
    config_path: str
    interval_seconds: int
    lookback_hours: int
    max_posts_per_poll: int
    max_posts_per_day: int
    max_entries_per_feed: int
    max_google_resolves_per_scan: int
    request_timeout_seconds: float
    scan_pause_seconds: float
    require_strong_match_for_broad: bool
    resolve_google_links: bool
    allow_unresolved_google_urls: bool
    web_base_url: str
    internal_api_token: str

    @classmethod
    def from_env(cls, web_base_url: str, internal_api_token: str, global_dry_run: bool = False):
        news_dry_run = os.getenv("NEWS_DRY_RUN")
        return cls(
            enabled=os.getenv("NEWS_ENABLED", "0") == "1",
            dry_run=(global_dry_run if news_dry_run is None else news_dry_run == "1"),
            config_path=os.getenv("NEWS_CONFIG_PATH", "/app/config/news.yaml"),
            interval_seconds=int(os.getenv("NEWS_INTERVAL_SECONDS", "3600")),
            lookback_hours=int(os.getenv("NEWS_LOOKBACK_HOURS", "24")),
            max_posts_per_poll=int(os.getenv("NEWS_MAX_POSTS_PER_POLL", "3")),
            max_posts_per_day=int(os.getenv("NEWS_MAX_POSTS_PER_DAY", "8")),
            max_entries_per_feed=int(os.getenv("NEWS_MAX_ENTRIES_PER_FEED", "25")),
            max_google_resolves_per_scan=int(os.getenv("NEWS_MAX_GOOGLE_RESOLVES_PER_SCAN", "75")),
            request_timeout_seconds=float(os.getenv("NEWS_REQUEST_TIMEOUT_SECONDS", "10")),
            scan_pause_seconds=float(os.getenv("NEWS_SCAN_PAUSE_SECONDS", "0.25")),
            require_strong_match_for_broad=os.getenv("NEWS_REQUIRE_STRONG_MATCH_FOR_BROAD", "1") == "1",
            resolve_google_links=os.getenv("NEWS_RESOLVE_GOOGLE_LINKS", "1") == "1",
            allow_unresolved_google_urls=os.getenv("NEWS_ALLOW_UNRESOLVED_GOOGLE_URLS", "0") == "1",
            web_base_url=web_base_url.rstrip("/"),
            internal_api_token=internal_api_token,
        )


def load_news_config(path: str):
    import yaml

    paths = [path] if path else []
    paths.extend(item for item in DEFAULT_NEWS_CONFIG_PATHS if item not in paths)
    last_error = None
    for candidate in paths:
        try:
            with open(candidate, "r", encoding="utf-8") as file:
                return yaml.safe_load(file) or {}
        except Exception as exc:
            last_error = exc
    raise RuntimeError(f"Unable to load news config from {paths}: {last_error}")


def ensure_news_schema(db):
    db.exec(
        """
        create table if not exists news_seen_links (
          canonical_url text primary key,
          original_url text,
          source_name text,
          source_type text,
          source_trust text,
          title text,
          summary text,
          published_at timestamptz,
          matched_keyword text,
          status text not null default 'candidate',
          first_seen_at timestamptz not null default now(),
          last_seen_at timestamptz not null default now(),
          posted_at timestamptz,
          last_error text
        );
        """
    )
    db.exec(
        """
        create index if not exists idx_news_seen_links_status
          on news_seen_links(status, last_seen_at);
        """
    )
    db.exec(
        """
        create index if not exists idx_news_seen_links_posted_at
          on news_seen_links(posted_at);
        """
    )


def normalized_domain(url: str) -> str:
    try:
        host = urlparse(str(url or "")).netloc.lower().split("@")[-1].split(":")[0]
    except Exception:
        return ""
    return host.removeprefix("www.")


def canonicalize_url(url: str) -> str:
    url = html.unescape(str(url or "")).strip()
    if not url:
        return ""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    query = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        lower = key.lower()
        if lower.startswith("utm_") or lower in TRACKING_QUERY_PARAMS:
            continue
        query.append((key, value))
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    cleaned = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        path=path,
        query=urlencode(query, doseq=True),
        fragment="",
    )
    return urlunparse(cleaned)


def is_google_news_url(url: str) -> bool:
    return normalized_domain(url) in GOOGLE_NEWS_HOSTS


def is_google_related_domain(domain: str) -> bool:
    return any(domain == suffix or domain.endswith(f".{suffix}") for suffix in GOOGLE_RELATED_HOST_SUFFIXES)


def is_non_article_url(url: str) -> bool:
    parsed = urlparse(str(url or ""))
    domain = normalized_domain(url)
    if not domain:
        return True
    if domain in NON_ARTICLE_HOSTS or any(domain == item or domain.endswith(f".{item}") for item in NON_ARTICLE_HOSTS):
        return True
    path = (parsed.path or "").lower()
    return any(path.endswith(extension) for extension in NON_ARTICLE_PATH_EXTENSIONS)


def google_news_rss_url(query: str) -> str:
    query = normalize_spaces(query)
    if "when:" not in query.lower():
        query = f"{query} when:1d"
    return "https://news.google.com/rss/search?" + urlencode(
        {
            "q": query,
            "hl": "en-US",
            "gl": "US",
            "ceid": "US:en",
        }
    )


def site_search_query(url: str) -> str:
    parsed = urlparse(str(url or ""))
    host = parsed.netloc.lower().split("@")[-1].split(":")[0].removeprefix("www.")
    path = (parsed.path or "").rstrip("/")
    target = f"{host}{path}" if path else host
    return f"site:{target} when:1d"


def feed_specs(config: dict):
    for item in config.get("rss_feeds", []):
        if item.get("url"):
            yield {
                "name": item.get("name") or item["url"],
                "feed_url": item["url"],
                "source_url": item["url"],
                "source_type": "rss",
                "trust": item.get("trust", "trusted"),
            }
    for item in config.get("site_searches", []):
        if item.get("url"):
            query = item.get("query") or site_search_query(item["url"])
            yield {
                "name": item.get("name") or item["url"],
                "feed_url": google_news_rss_url(query),
                "source_url": item["url"],
                "source_type": "site_search",
                "trust": item.get("trust", "trusted"),
            }
    for item in config.get("keyword_searches", []):
        query = item.get("query") if isinstance(item, dict) else str(item)
        if query:
            yield {
                "name": query,
                "feed_url": google_news_rss_url(query),
                "source_url": "",
                "source_type": "keyword_search",
                "trust": item.get("trust", "broad") if isinstance(item, dict) else "broad",
            }


def parse_entry_datetime(entry):
    from dateutil import parser as dtparse

    for key in ("published", "updated", "created"):
        value = entry.get(key)
        if value:
            try:
                return dtparse.parse(str(value)).astimezone(UTC)
            except Exception:
                pass
        parsed = entry.get(f"{key}_parsed")
        if parsed:
            try:
                return datetime(*parsed[:6], tzinfo=UTC)
            except Exception:
                pass
    return None


def entry_summary(entry) -> str:
    return normalize_spaces(entry.get("summary") or entry.get("description") or "")


def entry_title(entry) -> str:
    return normalize_spaces(entry.get("title") or "")


def entry_source_name(entry, fallback: str) -> str:
    source = entry.get("source") or {}
    if isinstance(source, dict):
        return normalize_spaces(source.get("title") or fallback)
    return fallback


def blocked_domains(config: dict) -> set[str]:
    return {normalized_domain(url) for url in config.get("blocked_sources", []) if normalized_domain(url)}


def blocked_source_names(config: dict) -> set[str]:
    return {normalize_spaces(name).lower() for name in config.get("blocked_source_names", []) if normalize_spaces(name)}


def source_name_is_blocked(source_name: str, config: dict) -> bool:
    normalized = normalize_spaces(source_name).lower()
    return bool(normalized and normalized in blocked_source_names(config))


def all_keywords(config: dict) -> list[str]:
    return [str(item).strip() for item in config.get("keywords_positive", []) if str(item).strip()]


def junk_words(config: dict) -> list[str]:
    return [str(item).strip() for item in config.get("junk_words", []) if str(item).strip()]


def first_matching_keyword(text: str, keywords: list[str]) -> str | None:
    for keyword in keywords:
        start, _matched_text = first_keyword_hit([(0, 0, text)], [keyword])
        if start is not None:
            return keyword
    return None


def strong_broad_match(text: str, matched_keyword: str | None) -> bool:
    if matched_keyword and normalize_spaces(matched_keyword).lower() not in GENERIC_BROAD_TERMS:
        return True
    return has_keyword(text, ["portland trail blazers", "trail blazers", "rip city"])


def resolve_original_url(url: str, settings: NewsSettings, resolve_budget: dict) -> tuple[str, bool]:
    canonical = canonicalize_url(url)
    if not canonical or not is_google_news_url(canonical):
        return canonical, False
    if not settings.resolve_google_links or resolve_budget.get("used", 0) >= settings.max_google_resolves_per_scan:
        return canonical, True

    import requests

    resolve_budget["used"] = resolve_budget.get("used", 0) + 1
    try:
        response = requests.get(
            canonical,
            headers={"User-Agent": NEWS_USER_AGENT},
            allow_redirects=True,
            timeout=settings.request_timeout_seconds,
        )
        final_url = canonicalize_url(response.url)
        if final_url and not is_google_news_url(final_url):
            return final_url, False
        body = html.unescape(response.text or "")[:200000]
        for match in re.findall(r"https?://[^\"'<>\\\s]+", body):
            candidate = canonicalize_url(match)
            domain = normalized_domain(candidate)
            if candidate and domain and not is_google_related_domain(domain) and not is_non_article_url(candidate):
                return candidate, False
    except Exception:
        pass
    return canonical, True


def fetch_feed(feed_url: str, settings: NewsSettings):
    import feedparser
    import requests

    response = requests.get(
        feed_url,
        headers={"User-Agent": NEWS_USER_AGENT},
        timeout=settings.request_timeout_seconds,
    )
    response.raise_for_status()
    return feedparser.parse(response.content)


def build_candidate(entry, spec: dict, config: dict, settings: NewsSettings, cutoff: datetime, resolve_budget: dict):
    published_at = parse_entry_datetime(entry)
    if not published_at:
        return None, "missing_published"
    if published_at < cutoff:
        return None, "old"
    if published_at > datetime.now(UTC) + timedelta(hours=2):
        return None, "future"

    original_url = canonicalize_url(entry.get("link") or "")
    canonical_url, unresolved_google_url = resolve_original_url(original_url, settings, resolve_budget)
    if not canonical_url:
        return None, "missing_url"
    if is_non_article_url(canonical_url):
        return None, "non_article_url"

    domain = normalized_domain(canonical_url)
    if domain in blocked_domains(config):
        return None, "blocked_source"

    title = entry_title(entry)
    summary = entry_summary(entry)
    source_name = entry_source_name(entry, spec["name"])
    if source_name_is_blocked(source_name, config):
        return None, "blocked_source_name"

    haystack = normalize_spaces(f"{title} {summary}")

    if junk_words(config) and has_keyword(haystack, junk_words(config)):
        return None, "junk"

    keywords = all_keywords(config)
    matched_keyword = first_matching_keyword(haystack, keywords)
    if not matched_keyword:
        return None, "no_keyword"

    if (
        settings.require_strong_match_for_broad
        and normalize_spaces(matched_keyword).lower() in GENERIC_BROAD_TERMS
        and not strong_broad_match(haystack, matched_keyword)
    ):
        return None, "weak_broad_match"

    return {
        "canonical_url": canonical_url,
        "original_url": original_url,
        "source_name": source_name,
        "source_type": spec["source_type"],
        "source_trust": spec.get("trust", ""),
        "title": title,
        "summary": summary,
        "published_at": published_at,
        "matched_keyword": matched_keyword,
        "unresolved_google_url": unresolved_google_url,
    }, "candidate"


def news_due(settings: NewsSettings, db, now=None) -> bool:
    from dateutil import parser as dtparse

    global LAST_DRY_RUN_NEWS_SCAN_AT
    if not settings.enabled:
        return False
    if settings.interval_seconds <= 0:
        return True
    now = now or datetime.now(UTC)
    if settings.dry_run:
        if not LAST_DRY_RUN_NEWS_SCAN_AT:
            return True
        return LAST_DRY_RUN_NEWS_SCAN_AT + timedelta(seconds=settings.interval_seconds) <= now
    value = db.get_state("news_last_scan_at")
    if not value:
        return True
    try:
        return dtparse.isoparse(value).astimezone(UTC) + timedelta(seconds=settings.interval_seconds) <= now
    except Exception:
        return True


def news_link_already_seen(db, canonical_url: str) -> bool:
    rows = db.exec("select 1 from news_seen_links where canonical_url=%s and posted_at is not null", [canonical_url])
    return bool(rows)


def news_posts_today(db) -> int:
    rows = db.exec(
        "select count(*)::integer as count from news_seen_links where posted_at >= now() - interval '24 hours'"
    )
    return int(rows[0]["count"]) if rows else 0


def upsert_news_candidate(db, candidate: dict, status: str):
    db.exec(
        """
        insert into news_seen_links(
          canonical_url, original_url, source_name, source_type, source_trust,
          title, summary, published_at, matched_keyword, status, last_seen_at
        )
        values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())
        on conflict(canonical_url) do update set
          original_url = excluded.original_url,
          source_name = excluded.source_name,
          source_type = excluded.source_type,
          source_trust = excluded.source_trust,
          title = excluded.title,
          summary = excluded.summary,
          published_at = excluded.published_at,
          matched_keyword = excluded.matched_keyword,
          status = case
            when news_seen_links.posted_at is not null then news_seen_links.status
            else excluded.status
          end,
          last_seen_at = now(),
          last_error = null
        """,
        [
            candidate["canonical_url"],
            candidate.get("original_url"),
            candidate.get("source_name"),
            candidate.get("source_type"),
            candidate.get("source_trust"),
            candidate.get("title"),
            candidate.get("summary"),
            candidate.get("published_at"),
            candidate.get("matched_keyword"),
            status,
        ],
    )


def mark_news_posted(db, canonical_url: str):
    db.exec(
        """
        update news_seen_links
        set status='posted', posted_at=now(), last_error=null, last_seen_at=now()
        where canonical_url=%s
        """,
        [canonical_url],
    )


def mark_news_failed(db, canonical_url: str, error: str):
    db.exec(
        """
        update news_seen_links
        set status='post_failed', last_error=%s, last_seen_at=now()
        where canonical_url=%s
        """,
        [str(error or "")[:500], canonical_url],
    )


def post_news_link(settings: NewsSettings, candidate: dict, log) -> bool:
    import requests

    if settings.dry_run:
        if candidate.get("unresolved_google_url"):
            log(
                "DRY_RUN news unresolved_google_url:",
                candidate.get("source_name"),
                clamp_text(candidate.get("title") or "", 140),
                candidate["canonical_url"],
            )
        else:
            log(
                "DRY_RUN news post:",
                candidate.get("source_name"),
                "matched",
                candidate.get("matched_keyword"),
                candidate["canonical_url"],
            )
        return True

    if candidate.get("unresolved_google_url") and not settings.allow_unresolved_google_urls:
        log("news skip unresolved_google_url", candidate.get("source_name"), candidate["canonical_url"])
        return False

    payload = {
        "text": candidate["canonical_url"],
        "url": candidate["canonical_url"],
        "title": candidate.get("title") or candidate.get("source_name") or "News link",
        "description": candidate.get("source_name") or "News link",
    }
    try:
        response = requests.post(
            f"{settings.web_base_url}/post-link",
            headers={"Content-Type": "application/json", "X-Internal-Token": settings.internal_api_token},
            data=json.dumps(payload),
            timeout=60,
        )
    except requests.RequestException as exc:
        log("news post-link failed request_error", exc.__class__.__name__, candidate["canonical_url"])
        return False
    if response.status_code != 200:
        log("news post-link failed", response.status_code, response.text[:300])
        return False
    log("posted news link ok", candidate.get("source_name"), candidate["canonical_url"])
    return True


def scan_news_links(settings: NewsSettings, db, config: dict, log=print, debug: bool = False):
    global LAST_DRY_RUN_NEWS_SCAN_AT
    if not news_due(settings, db):
        return

    ensure_news_schema(db)
    cutoff = datetime.now(UTC) - timedelta(hours=settings.lookback_hours)
    specs = list(feed_specs(config))
    skipped = Counter()
    seen_this_scan = set()
    accepted = 0
    posted = 0
    searched_feeds = 0
    resolve_budget = {"used": 0}
    daily_remaining = max(0, settings.max_posts_per_day - news_posts_today(db))

    log("news scan", "feeds", len(specs), "since", cutoff.isoformat(), "dry_run", int(settings.dry_run))
    for spec in specs:
        if not settings.dry_run and posted >= min(settings.max_posts_per_poll, daily_remaining):
            break
        try:
            parsed = fetch_feed(spec["feed_url"], settings)
        except Exception as exc:
            skipped[f"feed_error:{exc.__class__.__name__}"] += 1
            log("news feed failed", spec["name"], exc.__class__.__name__)
            continue

        searched_feeds += 1
        entries = list(parsed.entries)[: max(1, settings.max_entries_per_feed)]
        if debug:
            log("news feed", spec["name"], spec["source_type"], "entries", len(entries))
        for entry in entries:
            candidate, reason = build_candidate(entry, spec, config, settings, cutoff, resolve_budget)
            if not candidate:
                skipped[reason] += 1
                continue
            canonical_url = candidate["canonical_url"]
            if canonical_url in seen_this_scan:
                skipped["duplicate_in_scan"] += 1
                continue
            seen_this_scan.add(canonical_url)
            if news_link_already_seen(db, canonical_url):
                skipped["already_posted"] += 1
                continue

            accepted += 1
            if debug:
                log(
                    "news candidate",
                    candidate.get("source_type"),
                    candidate.get("source_name"),
                    "matched",
                    candidate.get("matched_keyword"),
                    clamp_text(candidate.get("title") or "", 140),
                )
            if not settings.dry_run:
                upsert_news_candidate(db, candidate, "candidate")
            if settings.dry_run:
                post_news_link(settings, candidate, log)
                continue
            if candidate.get("unresolved_google_url") and not settings.allow_unresolved_google_urls:
                skipped["unresolved_google_url"] += 1
                continue
            if posted >= settings.max_posts_per_poll:
                skipped["poll_cap"] += 1
                continue
            if posted >= daily_remaining:
                skipped["daily_cap"] += 1
                continue
            if post_news_link(settings, candidate, log):
                posted += 1
                mark_news_posted(db, canonical_url)
            else:
                mark_news_failed(db, canonical_url, "post_link_failed")

        if settings.scan_pause_seconds > 0:
            time.sleep(settings.scan_pause_seconds)

    if settings.dry_run:
        LAST_DRY_RUN_NEWS_SCAN_AT = datetime.now(UTC)
    else:
        db.set_state("news_last_scan_at", datetime.now(UTC).isoformat())
    log(
        "news scan complete",
        "feeds",
        searched_feeds,
        "accepted",
        accepted,
        "posted",
        posted,
        "google_resolves",
        resolve_budget.get("used", 0),
        "skipped",
        dict(sorted(skipped.items())),
    )

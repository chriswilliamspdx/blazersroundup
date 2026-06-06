from __future__ import annotations

import re
from datetime import datetime

from dateutil import parser as dtparse, tz

from text_utils import has_keyword, normalize_spaces


UTC = tz.UTC

DEFAULT_JUNK_WORDS = [
    "betting",
    "parlay",
    "odds",
    "fantasy",
    "dfs",
    "draftkings",
    "fanduel",
    "prizepicks",
    "underdog fantasy",
    "trade machine",
]

GENERIC_SEARCH_EXCLUDES = {"portland"}


def split_csv_words(value: str | None, default: list[str] | None = None) -> list[str]:
    if value is None or not str(value).strip():
        return list(default or [])
    return [item.strip() for item in str(value).split(",") if item.strip()]


def normalize_handle(value: str | None) -> str:
    return str(value or "").strip().lower().removeprefix("@")


def post_uri(post: dict) -> str:
    return str(post.get("uri") or "").strip()


def post_cid(post: dict) -> str:
    return str(post.get("cid") or "").strip()


def post_author_did(post: dict) -> str:
    return str((post.get("author") or {}).get("did") or "").strip()


def post_author_handle(post: dict) -> str:
    return normalize_handle((post.get("author") or {}).get("handle"))


def post_text(post: dict) -> str:
    return str((post.get("record") or {}).get("text") or "")


def post_indexed_at(post: dict):
    value = post.get("indexedAt") or (post.get("record") or {}).get("createdAt")
    if not value:
        return None
    try:
        return dtparse.isoparse(str(value)).astimezone(UTC)
    except Exception:
        return None


def post_like_count(post: dict) -> int:
    try:
        return int(post.get("likeCount") or 0)
    except Exception:
        return 0


def post_repost_count(post: dict) -> int:
    try:
        return int(post.get("repostCount") or 0)
    except Exception:
        return 0


def post_quote_count(post: dict) -> int:
    try:
        return int(post.get("quoteCount") or 0)
    except Exception:
        return 0


def is_reply(post: dict) -> bool:
    return bool(post.get("reply"))


def contains_junk(text: str, junk_words: list[str]) -> bool:
    return has_keyword(text, junk_words)


def build_search_queries(config: dict, max_queries: int, configured_queries: list[str] | None = None) -> list[str]:
    if configured_queries:
        candidates = configured_queries
    else:
        priority = [
            "portland trail blazers",
            "trail blazers",
            "rip city",
            "blazers",
        ]
        keywords = [str(keyword).strip().lower() for keyword in config.get("keywords_positive", []) if str(keyword).strip()]
        candidates = priority + keywords

    seen: set[str] = set()
    queries: list[str] = []
    for candidate in candidates:
        cleaned = normalize_spaces(str(candidate).lower())
        if not cleaned or cleaned in seen or cleaned in GENERIC_SEARCH_EXCLUDES:
            continue
        seen.add(cleaned)
        if re.search(r"\s", cleaned):
            queries.append(f'"{cleaned}"')
        else:
            queries.append(cleaned)
        if len(queries) >= max(1, max_queries):
            break
    return queries


def candidate_reason(
    post: dict,
    *,
    keywords: list[str],
    junk_words: list[str],
    bot_handles: list[str],
    min_likes: int,
    skip_replies: bool,
) -> tuple[bool, str]:
    if not post_uri(post) or not post_cid(post):
        return False, "missing_uri_or_cid"
    if post_author_handle(post) in {normalize_handle(handle) for handle in bot_handles}:
        return False, "self_post"
    if skip_replies and is_reply(post):
        return False, "reply"

    text = post_text(post)
    if contains_junk(text, junk_words):
        return False, "junk"
    if not has_keyword(text, keywords):
        return False, "no_keyword"
    if post_like_count(post) < min_likes:
        return True, "below_threshold"
    return True, "ready"


def candidate_row(post: dict, matched_query: str, status: str = "candidate") -> dict:
    return {
        "uri": post_uri(post),
        "cid": post_cid(post),
        "author_did": post_author_did(post),
        "author_handle": post_author_handle(post),
        "text": post_text(post),
        "indexed_at": post_indexed_at(post) or datetime.now(UTC),
        "like_count": post_like_count(post),
        "repost_count": post_repost_count(post),
        "quote_count": post_quote_count(post),
        "matched_query": matched_query,
        "status": status,
    }

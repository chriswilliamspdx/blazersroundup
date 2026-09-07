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

FALSE_POSITIVE_CONTEXT_PHRASES = [
    "men in blazers",
    "meninblazers",
    "doctor who",
    "dr who",
    "time lord victorious",
    "gallifrey",
    "tardis",
    "dalek",
    "sonic screwdriver",
]

AMBIGUOUS_REPOST_KEYWORDS = {
    "blazers",
    "portland",
    "time lord",
}

STRONG_BLAZERS_CONTEXT_PHRASES = [
    "portland trail blazers",
    "trail blazers",
    "rip city",
    "moda center",
]

TIME_LORD_CONTEXT_PHRASES = [
    "robert williams",
    "rob williams",
    "williams iii",
    "trail blazers",
    "portland trail blazers",
    "blazers",
    "nba",
    "basketball",
]

BASKETBALL_CONTEXT_PHRASES = [
    "nba",
    "basketball",
    "game",
    "roster",
    "trade",
    "draft",
    "pick",
    "lottery",
    "coach",
    "guard",
    "center",
    "forward",
    "wing",
    "playoff",
    "playoffs",
    "finals",
    "summer league",
    "free agency",
    "contract",
    "extension",
    "rookie",
    "season",
    "offseason",
    "team",
    "arena",
    "moda center",
]


def split_csv_words(value: str | None, default: list[str] | None = None) -> list[str]:
    if value is None or not str(value).strip():
        return list(default or [])
    return [item.strip() for item in str(value).split(",") if item.strip()]


def normalize_handle(value: str | None) -> str:
    return str(value or "").strip().lower().removeprefix("@")


def normalize_match_text(value: str | None) -> str:
    return normalize_spaces(re.sub(r"[^a-zA-Z0-9]+", " ", str(value or "").lower()))


def phrase_in_text(phrase: str, text: str) -> bool:
    normalized_phrase = normalize_match_text(phrase)
    normalized_text = normalize_match_text(text)
    return bool(normalized_phrase and normalized_phrase in normalized_text)


def any_phrase_in_text(phrases: list[str], text: str) -> bool:
    return any(phrase_in_text(phrase, text) for phrase in phrases)


def post_uri(post: dict) -> str:
    return str(post.get("uri") or "").strip()


def post_cid(post: dict) -> str:
    return str(post.get("cid") or "").strip()


def post_author_did(post: dict) -> str:
    return str((post.get("author") or {}).get("did") or "").strip()


def post_author_handle(post: dict) -> str:
    return normalize_handle((post.get("author") or {}).get("handle"))


def post_author_display_name(post: dict) -> str:
    return str((post.get("author") or {}).get("displayName") or "").strip()


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


def contains_false_positive_context(post: dict) -> bool:
    text = " ".join([post_text(post), post_author_handle(post), post_author_display_name(post)])
    return any_phrase_in_text(FALSE_POSITIVE_CONTEXT_PHRASES, text)


def non_ambiguous_keywords(
    keywords: list[str],
    *,
    context_required_keywords: list[str] | None = None,
) -> list[str]:
    context_required = {
        normalize_spaces(str(keyword).lower())
        for keyword in (context_required_keywords or [])
        if normalize_spaces(str(keyword).lower())
    }
    return [
        normalize_spaces(str(keyword).lower())
        for keyword in keywords
        if normalize_spaces(str(keyword).lower())
        and normalize_spaces(str(keyword).lower()) not in AMBIGUOUS_REPOST_KEYWORDS
        and normalize_spaces(str(keyword).lower()) not in context_required
    ]


def has_repost_blazers_context(
    text: str,
    keywords: list[str],
    *,
    context_required_keywords: list[str] | None = None,
) -> bool:
    if any_phrase_in_text(STRONG_BLAZERS_CONTEXT_PHRASES, text):
        return True

    if any_phrase_in_text(
        non_ambiguous_keywords(keywords, context_required_keywords=context_required_keywords),
        text,
    ):
        return True

    if phrase_in_text("time lord", text):
        return any_phrase_in_text(TIME_LORD_CONTEXT_PHRASES, text)

    if phrase_in_text("blazers", text):
        return any_phrase_in_text(BASKETBALL_CONTEXT_PHRASES, text)

    if phrase_in_text("portland", text):
        return any_phrase_in_text(["nba", "basketball", "trail blazers", "rip city", "moda center"], text)

    return False


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
        configured_keywords = config.get("keywords_search")
        keywords_source = configured_keywords if configured_keywords else config.get("keywords_positive", [])
        keywords = [str(keyword).strip().lower() for keyword in keywords_source if str(keyword).strip()]
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
    context_required_keywords: list[str] | None = None,
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
    if contains_false_positive_context(post):
        return False, "false_positive_context"
    if not has_keyword(text, keywords):
        return False, "no_keyword"
    if not has_repost_blazers_context(
        text,
        keywords,
        context_required_keywords=context_required_keywords,
    ):
        return False, "not_blazers_context"
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

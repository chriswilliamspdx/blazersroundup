import math
import re
import unicodedata


def normalize_spaces(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def clamp_text(text: str, limit: int = 300, suffix: str = "...") -> str:
    text = "\n".join(normalize_spaces(line) for line in str(text or "").replace("\r\n", "\n").split("\n")).strip()
    if len(text) <= limit:
        return text
    if limit <= len(suffix):
        return suffix[:limit]
    return text[: limit - len(suffix)].rstrip() + suffix


def clamp_heading_with_link(heading: str, link_line: str, limit: int = 300) -> str:
    heading = normalize_spaces(heading)
    link_line = normalize_spaces(link_line)
    text = f"{heading}\n{link_line}".strip()
    if len(text) <= limit:
        return text

    if len(link_line) >= limit:
        return clamp_text(link_line, limit)

    heading_limit = limit - len(link_line) - 1
    return f"{clamp_text(heading, heading_limit)}\n{link_line}"


def fmt_mmss(seconds: int | float) -> str:
    seconds = int(math.floor(max(0, seconds)))
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    remainder = seconds % 60
    if hours:
        return f"{hours:02d}:{minutes:02d}:{remainder:02d}"
    return f"{minutes:02d}:{remainder:02d}"


def fmt_hhmmss(seconds: int | float) -> str:
    seconds = int(math.floor(max(0, seconds)))
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    remainder = seconds % 60
    return f"{hours:02d}:{minutes:02d}:{remainder:02d}"


def _normalize_for_match(text: str) -> str:
    text = unicodedata.normalize("NFKD", text or "")
    text = "".join(char for char in text if not unicodedata.combining(char))
    text = re.sub(r"[^a-zA-Z0-9]+", " ", text.lower())
    return normalize_spaces(text)


def _match_tokens(text: str) -> list[str]:
    return _normalize_for_match(text).split()


def _edit_distance_at_most(left: str, right: str, limit: int) -> bool:
    if abs(len(left) - len(right)) > limit:
        return False

    previous = list(range(len(right) + 1))
    for row, left_char in enumerate(left, 1):
        current = [row]
        row_min = current[0]
        for col, right_char in enumerate(right, 1):
            cost = 0 if left_char == right_char else 1
            current.append(
                min(
                    previous[col] + 1,
                    current[col - 1] + 1,
                    previous[col - 1] + cost,
                )
            )
            row_min = min(row_min, current[-1])
        if row_min > limit:
            return False
        previous = current
    return previous[-1] <= limit


def _word_close(keyword_word: str, transcript_word: str) -> bool:
    if keyword_word == transcript_word:
        return True
    if len(keyword_word) <= 3:
        return False
    if len(keyword_word) <= 5:
        return _edit_distance_at_most(keyword_word, transcript_word, 1)
    return _edit_distance_at_most(keyword_word, transcript_word, 2)


def _fuzzy_phrase_hit(keyword: str, text: str) -> bool:
    keyword_tokens = _match_tokens(keyword)
    text_tokens = _match_tokens(text)
    if len(keyword_tokens) < 2 or len(text_tokens) < len(keyword_tokens):
        return False

    window_size = len(keyword_tokens)
    for index in range(len(text_tokens) - window_size + 1):
        window = text_tokens[index : index + window_size]
        if all(_word_close(keyword_word, transcript_word) for keyword_word, transcript_word in zip(keyword_tokens, window)):
            return True
    return False


def first_keyword_hit(segments: list[tuple[float, float, str]], keywords: list[str]) -> tuple[int | None, str | None]:
    normalized_keywords = [
        _normalize_for_match(keyword)
        for keyword in keywords
        if _normalize_for_match(keyword)
    ]
    for start, _duration, text in segments:
        normalized_text = _normalize_for_match(text)
        if any(keyword in normalized_text for keyword in normalized_keywords):
            return int(math.floor(start)), text
        if any(_fuzzy_phrase_hit(keyword, text) for keyword in normalized_keywords):
            return int(math.floor(start)), text
    return None, None


def has_keyword(text: str, keywords: list[str]) -> bool:
    start, _matched_text = first_keyword_hit([(0, 0, text or "")], keywords)
    return start is not None


def transcript_window(
    segments: list[tuple[float, float, str]],
    start_seconds: int,
    window_seconds: int = 180,
    char_limit: int = 8000,
) -> str:
    end_seconds = start_seconds + window_seconds
    text = " ".join(text for start, _duration, text in segments if start_seconds <= start <= end_seconds)
    return normalize_spaces(text)[:char_limit]


def build_model_input(mode: str, title: str, video_id: str, direct_keyword_hit: bool, transcript_text: str) -> str:
    return (
        f"Feed type: {mode}\n"
        f"Episode title: {title or 'Untitled'}\n"
        f"YouTube video ID: {video_id}\n"
        f"Direct keyword hit in transcript: {'yes' if direct_keyword_hit else 'no'}\n\n"
        "Transcript snippet:\n"
        f"{transcript_text}"
    )


def youtube_link(video_id: str, start_seconds: int = 0) -> str:
    link = f"https://www.youtube.com/watch?v={video_id}"
    if start_seconds > 0:
        link += f"&t={int(start_seconds)}s"
    return link

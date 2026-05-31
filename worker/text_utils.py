import math
import re


def normalize_spaces(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def clamp_text(text: str, limit: int = 300, suffix: str = "...") -> str:
    text = normalize_spaces(text)
    if len(text) <= limit:
        return text
    if limit <= len(suffix):
        return suffix[:limit]
    return text[: limit - len(suffix)].rstrip() + suffix


def fmt_mmss(seconds: int | float) -> str:
    seconds = int(math.floor(max(0, seconds)))
    minutes = seconds // 60
    remainder = seconds % 60
    return f"{minutes:02d}:{remainder:02d}"


def first_keyword_hit(segments: list[tuple[float, float, str]], keywords: list[str]) -> tuple[int | None, str | None]:
    for start, _duration, text in segments:
        low = text.lower()
        if any(keyword in low for keyword in keywords):
            return int(math.floor(start)), text
    return None, None


def transcript_window(
    segments: list[tuple[float, float, str]],
    start_seconds: int,
    window_seconds: int = 180,
    char_limit: int = 8000,
) -> str:
    end_seconds = start_seconds + window_seconds
    text = " ".join(text for start, _duration, text in segments if start_seconds <= start <= end_seconds)
    return normalize_spaces(text)[:char_limit]


def youtube_link(video_id: str, start_seconds: int = 0) -> str:
    link = f"https://www.youtube.com/watch?v={video_id}"
    if start_seconds > 0:
        link += f"&t={int(start_seconds)}s"
    return link

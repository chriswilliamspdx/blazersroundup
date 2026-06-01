import math
import re


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

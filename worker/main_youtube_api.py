import os
from datetime import datetime

import requests
from dateutil import tz

import main as worker_main


UTC = tz.UTC


def youtube_uploads_playlist_id(channel_id: str) -> str | None:
    channel_id = (channel_id or "").strip()
    if not channel_id.startswith("UC") or len(channel_id) < 3:
        return None
    return "UU" + channel_id[2:]


def youtube_api_item_to_entry(item: dict) -> dict | None:
    snippet = item.get("snippet") or {}
    content_details = item.get("contentDetails") or {}
    resource_id = snippet.get("resourceId") or {}
    video_id = content_details.get("videoId") or resource_id.get("videoId")
    if not video_id:
        return None

    published = content_details.get("videoPublishedAt") or snippet.get("publishedAt") or datetime.now(UTC).isoformat()
    title = snippet.get("title") or "Untitled YouTube video"
    return {
        "id": f"yt:video:{video_id}",
        "yt_videoid": video_id,
        "link": worker_main.youtube_link(video_id),
        "title": title,
        "published": published,
    }


def fetch_youtube_api_entries(settings, channel_id: str, max_results: int):
    api_key = os.getenv("YOUTUBE_API_KEY") or os.getenv("YOUTUBE_DATA_API_KEY")
    if not api_key:
        worker_main.dlog(settings, "YouTube API fallback unavailable: missing YOUTUBE_API_KEY")
        return [], {"status": None, "items": 0, "error": "missing_api_key"}

    playlist_id = youtube_uploads_playlist_id(channel_id)
    if not playlist_id:
        worker_main.dlog(settings, "YouTube API fallback unavailable: unsupported channel id", channel_id)
        return [], {"status": None, "items": 0, "error": "unsupported_channel_id"}

    params = {
        "part": "snippet,contentDetails",
        "playlistId": playlist_id,
        "maxResults": max(1, min(int(max_results or 5), 10)),
        "key": api_key,
    }
    try:
        response = requests.get("https://www.googleapis.com/youtube/v3/playlistItems", params=params, timeout=15)
        payload = response.json()
    except Exception as exc:
        worker_main.dlog(settings, "YouTube API fallback failed", channel_id, exc.__class__.__name__, str(exc))
        return [], {"status": None, "items": 0, "error": f"{exc.__class__.__name__}: {exc}"}

    if response.status_code != 200:
        error = payload.get("error", {}) if isinstance(payload, dict) else {}
        message = error.get("message") or response.text[:200]
        worker_main.dlog(settings, "YouTube API fallback failed", channel_id, "status", response.status_code, message)
        return [], {"status": response.status_code, "items": 0, "error": message}

    entries = []
    for item in payload.get("items", []):
        entry = youtube_api_item_to_entry(item)
        if entry:
            entries.append(entry)
    worker_main.dlog(settings, "YouTube API fallback", channel_id, "entries", len(entries), "status", response.status_code)
    return entries, {"status": response.status_code, "items": len(entries), "error": None}


def process_channel(
    settings,
    db,
    summarizer,
    config: dict,
    transcript_settings,
    poll_context,
    feed: dict,
    mode: str,
):
    channel_id = feed.get("youtube_channel_id")
    show_name = (feed.get("show_name") or feed.get("youtube_search") or "").strip()
    if show_name.lower().startswith(("http://", "https://")):
        show_name = ""
    feed_url = worker_main.yt_channel_feed_url(channel_id)
    parsed, feed_meta = worker_main.fetch_youtube_feed(settings, feed_url)
    entries = list(parsed.entries)
    worker_main.dlog(
        settings,
        "feed",
        feed_url,
        "entries",
        len(entries),
        "status",
        feed_meta.get("status"),
        "bytes",
        feed_meta.get("bytes"),
        "attempt",
        feed_meta.get("attempt"),
    )
    if not entries:
        entries, api_meta = fetch_youtube_api_entries(settings, channel_id, settings.max_feed_candidate_fallbacks)
        if entries:
            worker_main.dlog(
                settings,
                "feed fallback",
                feed_url,
                "source",
                "youtube-data-api",
                "entries",
                len(entries),
                "status",
                api_meta.get("status"),
            )
    if not entries:
        return

    rows = worker_main.build_rows(entries)
    if not rows:
        worker_main.dlog(settings, "feed has no parseable video ids", feed_url)
        return

    baseline = db.get_feed_baseline(feed_url)
    latest_pub, _latest_entry, latest_video_id = rows[0]
    if baseline is None or latest_pub > baseline or db.has_due_transcript_retry(latest_video_id, settings.transcript_max_attempts):
        candidates = [
            row
            for row in rows[: settings.max_feed_candidate_fallbacks]
            if baseline is None or row[0] > baseline or row[2] == latest_video_id
        ]
    else:
        candidates = []

    worker_main.dlog(settings, "candidates", len(candidates), "baseline", baseline.isoformat() if baseline else None)
    all_posting_ok = True
    processed = 0
    newest_completed_pub = None
    for published_at, entry, video_id in candidates:
        if poll_context.llm_wait:
            break
        if processed >= settings.max_videos_per_feed:
            break
        outcome = worker_main.handle_video(
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
        if outcome == worker_main.VIDEO_SKIP_CANDIDATE:
            continue
        if outcome == worker_main.VIDEO_NOT_DUE:
            all_posting_ok = False
            break
        processed += 1
        if outcome == worker_main.VIDEO_OK:
            newest_completed_pub = published_at if newest_completed_pub is None else max(newest_completed_pub, published_at)
        else:
            all_posting_ok = False
        break

    if not settings.dry_run and all_posting_ok and newest_completed_pub and (baseline is None or newest_completed_pub > baseline):
        db.set_feed_baseline(feed_url, newest_completed_pub)
    return processed


if not hasattr(worker_main, "fetch_youtube_api_entries"):
    worker_main.process_channel = process_channel


if __name__ == "__main__":
    worker_main.loop()

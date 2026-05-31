import argparse
import sys

import feedparser
import requests
import yaml


def channel_feed_url(channel_id: str) -> str:
    return f"https://www.youtube.com/feeds/videos.xml?channel_id={channel_id}"


def load_feeds(path: str) -> list[tuple[str, dict]]:
    with open(path, "r", encoding="utf-8") as file:
        config = yaml.safe_load(file) or {}
    feeds = []
    for group_name in ("national_feeds", "blazers_feeds"):
        for feed in config.get(group_name, []):
            feeds.append((group_name, feed))
    return feeds


def check_feed(group_name: str, feed: dict, timeout: int) -> tuple[bool, str]:
    channel_id = feed.get("youtube_channel_id")
    label = feed.get("youtube_search") or feed.get("rss") or channel_id or "(unnamed feed)"
    if not channel_id:
        return False, f"{group_name}: {label}: missing youtube_channel_id"

    url = channel_feed_url(channel_id)
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
    except Exception as exc:
        return False, f"{group_name}: {label}: RSS request failed: {exc}"

    parsed = feedparser.parse(response.content)
    if parsed.bozo and not parsed.entries:
        return False, f"{group_name}: {label}: RSS parse failed: {parsed.bozo_exception}"
    if not parsed.entries:
        return False, f"{group_name}: {label}: RSS returned no videos"

    latest = parsed.entries[0].get("title", "(untitled)")
    return True, f"{group_name}: {label}: ok - {len(parsed.entries)} videos, latest: {latest}"


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Validate YouTube channel RSS feeds without posting.")
    parser.add_argument("config_path", nargs="?", default="config/feeds.youtube.yaml")
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args()

    failures = 0
    feeds = load_feeds(args.config_path)
    print(f"Checking {len(feeds)} configured YouTube feeds...")
    for group_name, feed in feeds:
        ok, message = check_feed(group_name, feed, args.timeout)
        print(("OK " if ok else "BAD ") + message)
        if not ok:
            failures += 1

    if failures:
        print(f"\n{failures} feed check(s) failed.")
        return 1
    print("\nAll configured YouTube feeds responded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

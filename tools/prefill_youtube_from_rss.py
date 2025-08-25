#!/usr/bin/env python3
import os, sys, yaml, requests, time, re
import feedparser

YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY", "").strip()

def rss_title(url):
    d = feedparser.parse(url)
    return (d.feed.get("title") or "").strip()

def yt_search_channel(q):
    # Returns (channelId, channelTitle) or (None, None)
    if not YOUTUBE_API_KEY:
        return None, None
    params = {
        "part": "snippet",
        "q": q,
        "type": "channel",
        "maxResults": 3,
        "key": YOUTUBE_API_KEY,
    }
    r = requests.get("https://www.googleapis.com/youtube/v3/search", params=params, timeout=20)
    r.raise_for_status()
    items = r.json().get("items", [])
    if not items:
        return None, None
    best = None
    q_norm = re.sub(r"\W+", "", q).lower()
    for it in items:
        title = it["snippet"]["title"]
        id_ = it["snippet"]["channelId"]
        t_norm = re.sub(r"\W+", "", title).lower()
        if q_norm and (q_norm in t_norm or t_norm in q_norm):
            return id_, title
        if best is None:
            best = (id_, title)
    return best if best else (None, None)

def convert_list(feed_list):
    out = []
    for item in feed_list:
        rss = item.get("rss")
        if not rss:
            continue
        title = rss_title(rss) or ""
        entry = {
            "rss": rss,
            "youtube_search": title or rss,
        }
        if YOUTUBE_API_KEY and title:
            try:
                cid, ctitle = yt_search_channel(title)
                if cid:
                    entry["youtube_channel_id"] = cid
                    entry["youtube_search"] = title
            except Exception:
                pass
            time.sleep(0.2)
        out.append(entry)
    return out

def main():
    if len(sys.argv) < 2:
        print("usage: prefill_youtube_from_rss.py config/feeds.yaml > config/feeds.youtube.yaml", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        cfg = yaml.safe_load(f)

    result = {
        "timezone": cfg.get("timezone", "America/Los_Angeles"),
        "poll_interval_seconds": cfg.get("poll_interval_seconds", 600),
        "post_char_limit": cfg.get("post_char_limit", 300),
        "keywords_positive": cfg.get("keywords_positive", []),
        "exclude_note": cfg.get("exclude_note", ""),
        "national_feeds": convert_list(cfg.get("national_feeds", [])),
        "blazers_feeds": convert_list(cfg.get("blazers_feeds", [])),
    }

    yaml.safe_dump(result, sys.stdout, sort_keys=False, allow_unicode=True)

if __name__ == "__main__":
    main()

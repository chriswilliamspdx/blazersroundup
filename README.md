# blazersroundup (Bluesky bot)

Two-service Railway app:

- **web/** (Node): Bluesky OAuth confidential client plus the internal `/post-thread` posting API.
- **worker/** (Python): polls YouTube channel RSS, fetches captions/transcripts without downloading media, summarizes with Gemini, and asks `web` to post.

## One-time setup

1. Host OAuth client metadata and JWKS from `docs/` on GitHub Pages.
2. Deploy **web** and complete Bluesky OAuth sign-in once.
3. Deploy **worker** with Gemini credentials and the same internal token as `web`.

Before enabling live worker posting, visit `/session/status` on the web service and confirm `haveSession` is true.

## Behavior

- The worker uses `config/feeds.youtube.yaml` by default.
- Each poll considers only the newest video from each configured YouTube channel.
- If YouTube channel RSS returns zero entries or an error, the worker can fall back to the official YouTube Data API when `YOUTUBE_API_KEY` is set.
- If the newest YouTube entry is an upcoming live event, the worker skips it and tries the next newest entry from that channel.
- Successfully handled newest videos advance that feed's baseline.
- Transcript failures do not advance the feed baseline; the episode stays eligible for a later retry.
- Gemini quota or API failures do not crash the worker; the episode stays eligible for a later retry.
- If Gemini reports a daily quota limit, the worker pauses Gemini work until shortly after the next Pacific-time daily reset.
- Transcript provider order is:
  1. `youtube-transcript-api`
  2. `yt-dlp` caption-only fallback (`skip_download=True`)
  3. Optional rotating proxy retry when `TRANSCRIPT_PROXY_ENABLED=1`
- No audio or video files are downloaded.
- Dedupe is tracked by RSS `guid` and YouTube video ID in Postgres.

### Posting logic

- **National NBA podcasts**: post only when a Blazers mention is detected.
  1. Post 1: timestamped YouTube segment link first, plus "Blazers conversation starts at HH:MM:SS. Video link timestamped."
  2. Post 2: neutral segment summary, max 250 chars by default.
- **Blazers-specific podcasts**: summarize the newest episode.
  1. Post 1: YouTube episode link first, with a YouTube external card embed.
  2. Post 2: neutral episode summary, max 250 chars by default.
- **Bluesky reposts**: optional lightweight scan of recent Bluesky posts. When enabled, the worker searches for Blazers keyword matches from the last 24 hours and asks `web` to repost non-junk posts that have reached the like threshold.

### Formatting and constraints

- Neutral tone, no emojis, no hashtags.
- Link facets are applied by `web`; replies use `reply.root` and `reply.parent` to form a thread.
- The first post can include a YouTube external embed card with an uploaded thumbnail.
- `web` enforces Bluesky's 300 grapheme post limit before posting.

## Environment (Railway)

**Web**:

- `DATABASE_URL`
- `CLIENT_METADATA_URL` = `https://chriswilliamspdx.github.io/blazersroundup/bsky-client-v2.json`
- `BSKY_OAUTH_PRIVATE_KEY_JWK` = private JWK from `scripts/generate-jwk.mjs`
- `BSKY_OAUTH_KID` = kid from `scripts/generate-jwk.mjs`
- `INTERNAL_API_TOKEN` = random shared secret
- `BSKY_EXPECTED_HANDLE` = `@blazersroundup.bsky.social`
- `WEB_BASE_URL` = public Railway URL for the web service
- `PORT` = 8080 (optional)
- `POST_CHAR_LIMIT` = 300 (optional)

**Worker**:

- `DATABASE_URL`
- `WEB_BASE_URL` = `https://<your-web>.up.railway.app`
- `INTERNAL_API_TOKEN` = same value as web
- `GEMINI_API_KEY`
- `GEMINI_MODEL` = `gemini-3.1-flash-lite` (recommended; default remains `gemini-2.5-flash-lite`)
- `GEMINI_THINKING_LEVEL` = `low` for Gemini 3 models (optional)
- `YOUTUBE_API_KEY` = YouTube Data API v3 key for handle resolution, recent-video lookup, metadata, and livestream checks (recommended)
- `LLM_MAX_CALLS_PER_POLL` = 10 (optional, lower to 3-5 while testing)
- `LLM_RETRY_MINUTES` = 60 (optional)
- `LLM_MAX_ATTEMPTS` = 5 (optional)
- `LLM_QUOTA_COOLDOWN_MINUTES` = 60 (optional fallback when Gemini gives no retry/reset details)
- `POLL_INTERVAL_SECONDS` = 600 (optional)
- `TIMEZONE` = `America/Los_Angeles` (optional)
- `DRY_RUN` = 1 to log planned posts without posting or marking episodes seen
- `DRY_RUN_RECORD_TRANSCRIPT_RETRIES` = 1 to still back off blocked transcripts during dry-run
- `FORCE_TRANSCRIPT_RETRY` = 1 to ignore saved transcript cooldowns for one test run
- `RESET_FEED_STATE` = 1 to clear feed baselines and transcript retry state on startup; remove after one deploy
- `RESET_LLM_STATE` = 1 to clear Gemini cooldown and summary retry state on startup; remove after one deploy
- `FEED_MODE` = `all`, `national`, `blazers`, `high_volume`, or a comma-separated subset (optional, use `blazers` while testing)
- `RECENT_LOOKBACK_HOURS` = 24 (optional default for recent-window feed scans)
- `NATIONAL_LOOKBACK_HOURS` = 24 (optional override)
- `BLAZERS_LOOKBACK_HOURS` = 24 (optional override)
- `HIGH_VOLUME_LOOKBACK_HOURS` = 24 (optional override)
- `NATIONAL_MAX_RECENT_VIDEOS_PER_FEED` = 25 (optional; last-24h national videos to inspect per channel)
- `BLAZERS_MAX_RECENT_VIDEOS_PER_FEED` = 15 (optional; last-24h Blazers videos to summarize per channel)
- `HIGH_VOLUME_MAX_RECENT_VIDEOS_PER_FEED` = 75 (optional; last-24h high-volume metadata items to inspect per channel)
- `YOUTUBE_RECENT_API_ENABLED` = 1 (optional; use YouTube Data API to scan beyond RSS's newest entries)
- `MAX_VIDEOS_PER_FEED` = 1 (legacy fallback; recent-window feeds use the group-specific caps above)
- `MAX_FEED_CANDIDATE_FALLBACKS` = 15 (optional; minimum API/RSS candidate depth for stepping past live/upcoming, already-seen, or retry-not-due videos)
- `MAX_TRANSIENT_FAILURES_PER_FEED` = 2 (optional; max blocked/failing transcript attempts before moving to the next channel)
- `MAX_VIDEOS_PER_POLL` = 40 (optional, lower to 5-10 while testing)
- `SUMMARY_POST_CHAR_LIMIT` = 250 (optional)
- `SCAN_PAUSE_SECONDS` = 2.0 (optional, increase to slow requests)
- `YOUTUBE_METADATA_CHECK_ENABLED` = 1 (optional; skips live/upcoming videos before transcript attempts)
- `YOUTUBE_COMPLETED_STREAMS_ENABLED` = 1 (optional; enables completed livestream lookups for feeds with `scan_streams: true`)
- `YOUTUBE_STREAM_SEARCH_MINUTES` = 60 (optional; minimum minutes between completed-stream searches per channel)
- `TRANSCRIPT_RETRY_MINUTES` = 60 (optional)
- `TRANSCRIPT_MAX_ATTEMPTS` = 5 (optional)
- `TRANSCRIPT_PROXY_ENABLED` = 0 or 1 (optional)
- `TRANSCRIPT_PROXY_SOURCES` = `proxylist,1proxy,swiftshadow` (optional)
- `TRANSCRIPT_PROXY_ATTEMPTS` = 2 (optional)
- `TRANSCRIPT_PROXY_YTDLP_ENABLED` = 0 or 1 (optional; default is 0 so cookie-backed `yt-dlp` avoids free proxies)
- `TRANSCRIPT_PROXY_YTDLP_ATTEMPTS` = 1 (optional)
- `TRANSCRIPT_REQUEST_TIMEOUT_SECONDS` = 10.0 (optional)
- `TRANSCRIPT_PROXY_TIMEOUT_SECONDS` = 10.0 (optional)
- `TRANSCRIPT_PROXY_LIST_URLS` = comma-separated raw proxy list URLs (optional; defaults to the public lists from monosans, TheSpeedX, GoodProxy, and mmpx12)
- `TRANSCRIPT_PROXY_LIST_PROTOCOLS` = `http,https` (optional; keep this unless SOCKS support is added)
- `TRANSCRIPT_PROXY_LIST_REFRESH_SECONDS` = 3600 (optional)
- `TRANSCRIPT_PROXY_LIST_MAX_PROXIES` = 2000 (optional)
- `TRANSCRIPT_PROXY_BAD_COOLDOWN_SECONDS` = 3600 (optional; skip recently broken proxies for 1 hour)
- `TRANSCRIPT_PROXY_BLOCKED_COOLDOWN_SECONDS` = 21600 (optional; skip YouTube-blocked proxies for 6 hours)
- `TRANSCRIPT_PROXY_SELECTION_ATTEMPTS` = 25 (optional; how many proxies to sample while skipping unhealthy ones)
- `TRANSCRIPT_PROXY_REPUTATION_ENABLED` = 1 (optional; persists proxy health in Postgres)
- `TRANSCRIPT_PROXY_GOOD_POOL_LIMIT` = 100 (optional; max known-good proxies to sample from)
- `TRANSCRIPT_PROXY_GOOD_ATTEMPTS` = 1 (optional; known-good proxy attempts before fresh proxy sources)
- `TRANSCRIPT_PROXY_GOOD_FIRST_RATIO` = 0.8 (optional; 80% known-good first, 20% fresh-probe first when both pools exist)
- `TRANSCRIPT_PROXY_GOOD_REST_SECONDS` = 3600 (optional; rest known-good proxies after success)
- `TRANSCRIPT_PROXY_RETIRE_AFTER_FAILURES` = 5 (optional; retire repeatedly broken proxies)
- `TRANSCRIPT_PROXY_RETIRE_AFTER_BLOCKS` = 2 (optional; retire repeatedly YouTube-blocked proxies)
- `SWIFTSHADOW_COUNTRIES` = `US` (optional)
- `SWIFTSHADOW_PROTOCOLS` = `http,https` (optional)
- `ONEPROXY_API_URL` = `https://1proxy-api.aitradepulse.com/api/v1/proxies/rotate` (optional)
- `ONEPROXY_COUNTRY` = `US` (optional)
- `ONEPROXY_PROTOCOLS` = `http,https` (optional)
- `ONEPROXY_LIMIT` = 20 (optional)
- `ONEPROXY_MIN_QUALITY` = optional minimum quality score
- `ONEPROXY_CAN_ACCESS_GOOGLE` = optional `1` to ask 1proxy for Google-capable proxies
- `ONEPROXY_STRATEGY` = `quality` (optional)
- `ONEPROXY_MAX_LATENCY` = optional maximum proxy latency in milliseconds
- `YTDLP_COOKIES` = optional path to cookies file
- `YTDLP_COOKIES_TEXT` = optional private Railway variable containing a Netscape-format cookies file
- `YTDLP_COOKIES_B64` = optional base64 version of `YTDLP_COOKIES_TEXT`
- `YTDLP_SOCKET_TIMEOUT_SECONDS` = 8.0 (optional)
- `YTDLP_RETRIES` = 1 (optional)
- `YTDLP_EXTRACTOR_RETRIES` = 1 (optional)
- `BLUESKY_REPOST_ENABLED` = 0 or 1 (optional; default 0)
- `BLUESKY_REPOST_INTERVAL_SECONDS` = 3600 (optional; hourly scan)
- `BLUESKY_REPOST_LOOKBACK_HOURS` = 24 (optional)
- `BLUESKY_REPOST_MIN_LIKES` = 50 (optional)
- `BLUESKY_REPOST_MAX_RESULTS_PER_QUERY` = 50 (optional; Bluesky API maximum is 100)
- `BLUESKY_REPOST_MAX_QUERIES` = 80 (optional; caps searches built from the podcast keyword list)
- `BLUESKY_REPOST_MAX_PER_POLL` = 5 (optional; safety cap on reposts per scan)
- `BLUESKY_REPOST_SEARCH_SORT` = `top` (optional; `latest` is also supported)
- `BLUESKY_REPOST_SKIP_REPLIES` = 1 (optional; avoids reposting replies without context)
- `BLUESKY_REPOST_BOT_HANDLES` = `blazersroundup.bsky.social` (optional comma-separated self-handle list)
- `BLUESKY_REPOST_JUNK_WORDS` = optional comma-separated override for betting/fantasy/junk filtering
- `BLUESKY_REPOST_SEARCH_QUERIES` = optional comma-separated search queries; leave unset to derive from `keywords_positive`
- `BLUESKY_SEARCH_BASE_URL` = `https://public.api.bsky.app` (optional)

Use a dedicated YouTube account for cookies, not your primary personal account.
Free proxy retries are focused on `youtube-transcript-api`; keep `TRANSCRIPT_PROXY_YTDLP_ENABLED=0`. If cookies are configured, the worker will skip proxy-backed `yt-dlp` even if this variable is accidentally enabled, so YouTube account/session cookies do not go through free proxies.

Proxy reputation is stored in `proxy_health`. Useful statuses are:

- `good`: worked recently; may be resting if `cooldown_until` is in the future
- `blocked`: YouTube blocked the proxy; it is skipped until cooldown expires or it retires
- `purgatory`: failed for a non-YouTube-block reason; it can be retried after cooldown
- `retired`: skipped permanently unless the row is manually cleared

The worker logs a compact proxy health summary at the start of each poll when proxy reputation is enabled.

`national_feeds` and `blazers_feeds` scan recent archived videos from the lookback window. `high_volume_feeds` scans recent video metadata first and only fetches transcripts when the title/description/metadata has a Blazers keyword hit.

Feeds can opt into completed livestream discovery with `scan_streams: true`. This uses the YouTube Data API search endpoint, so enable it only for channels where archived streams matter.

Bluesky repost candidates are stored in `bluesky_repost_candidates`. Posts below the like threshold remain candidates and can be reposted by a later scan after their like count rises.

## Local checks

- Validate configured YouTube feeds without posting:

  ```bash
  python tools/validate_youtube_feeds.py config/feeds.youtube.yaml
  ```

- Run unit tests:

  ```bash
  python -m unittest discover -s tests
  node --test tests/postText.test.mjs
  ```

## Notes

- Free public proxies are best-effort only. Missed transcript access should be retried later, not treated as guaranteed infrastructure.
- Keep the worker transcript-only. Reintroducing audio download will bring back the bandwidth problem this rebuild is avoiding.

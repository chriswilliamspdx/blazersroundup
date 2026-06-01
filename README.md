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
- If the newest YouTube entry is an upcoming live event, the worker skips it and tries the next newest entry from that channel.
- Successfully handled newest videos advance that feed's baseline.
- Transcript failures do not advance the feed baseline; the episode stays eligible for a later retry.
- Transcript provider order is:
  1. `youtube-transcript-api`
  2. `yt-dlp` caption-only fallback (`skip_download=True`)
  3. Optional rotating proxy retry when `TRANSCRIPT_PROXY_ENABLED=1`
- No audio or video files are downloaded.
- Dedupe is tracked by RSS `guid` and YouTube video ID in Postgres.

### Posting logic

- **National NBA podcasts**: post only when a Blazers mention is detected.
  1. Post 1: show name and episode title, then timestamped YouTube segment link, max 300 chars.
  2. Post 2: neutral segment summary, max 300 chars.
- **Blazers-specific podcasts**: summarize the newest episode.
  1. Post 1: show name and episode title, then YouTube episode link, max 300 chars.
  2. Post 2: neutral episode summary, max 300 chars.

### Formatting and constraints

- Neutral tone, no emojis, no hashtags.
- Link facets are applied by `web`; replies use `reply.root` and `reply.parent` to form a thread.
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
- `GEMINI_MODEL` = `gemini-2.5-flash-lite` (optional default)
- `POLL_INTERVAL_SECONDS` = 600 (optional)
- `TIMEZONE` = `America/Los_Angeles` (optional)
- `DRY_RUN` = 1 to log planned posts without posting or marking episodes seen
- `DRY_RUN_RECORD_TRANSCRIPT_RETRIES` = 1 to still back off blocked transcripts during dry-run
- `FORCE_TRANSCRIPT_RETRY` = 1 to ignore saved transcript cooldowns for one test run
- `RESET_FEED_STATE` = 1 to clear feed baselines and transcript retry state on startup; remove after one deploy
- `FEED_MODE` = `all`, `national`, or `blazers` (optional, use `blazers` while testing)
- `MAX_VIDEOS_PER_FEED` = 1 (optional; the worker only considers the newest episode per feed)
- `MAX_FEED_CANDIDATE_FALLBACKS` = 5 (optional; only used to step past upcoming live videos)
- `MAX_VIDEOS_PER_POLL` = 40 (optional, lower to 5-10 while testing)
- `SCAN_PAUSE_SECONDS` = 2.0 (optional, increase to slow requests)
- `TRANSCRIPT_RETRY_MINUTES` = 60 (optional)
- `TRANSCRIPT_MAX_ATTEMPTS` = 5 (optional)
- `TRANSCRIPT_PROXY_ENABLED` = 0 or 1 (optional)
- `TRANSCRIPT_PROXY_SOURCES` = `swiftshadow` or `swiftshadow,1proxy` (optional)
- `TRANSCRIPT_PROXY_ATTEMPTS` = 2 (optional)
- `TRANSCRIPT_PROXY_TIMEOUT_SECONDS` = 10.0 (optional)
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

Use a dedicated YouTube account for cookies, not your primary personal account.

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

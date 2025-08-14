# blazersroundup (Bluesky bot)

Two-service Railway app:

- **web/** (Node): Bluesky OAuth (confidential client) + `/post-thread` API using @atproto OAuth + Agent.
- **worker/** (Python): Polls RSS, transcribes with faster-whisper, uses Gemini 2.5 Flash-Lite, calls web to post.

## One-time setup
See the step-by-step in our conversation notes. In short:
1) Host OAuth client metadata & JWKS on GitHub Pages (`/docs`).
2) Deploy **web** and complete Bluesky OAuth sign-in once.
3) Deploy **worker** with Spotify + Gemini credentials.

## Behavior
- The worker **always looks at the latest episodes**:
  - On the very first run, it processes **the single most recent episode per feed** and sets a **baseline** for that feed.
  - On subsequent runs, it processes **only episodes newer than that baseline** (no backlog), regardless of calendar date.
- Dedupe: tracked by RSS `guid` and Spotify episode ID in Postgres.

### Posting logic
- **National NBA podcasts**: If a Blazers mention is detected:
  1) Post 1: Spotify episode link **with (MM:SS)** of the Blazers segment + a short topic (≤300 chars)
  2) Post 2: ≤300-char neutral summary of that segment
- **Blazers-specific podcasts**:
  1) Post 1: Spotify episode link
  2) Post 2: ≤300-char neutral episode summary

### Formatting & constraints
- Neutral tone, **no emojis**, no hashtags.
- Link facets are applied automatically; replies use `reply.root`/`reply.parent` to form a thread.
- Max **300 characters** per post.

## Environment (Railway)
**Web**:
- `DATABASE_URL`
- `CLIENT_METADATA_URL` = `https://chriswilliamspdx.github.io/blazersroundup/bsky-client.json`
- `BSKY_OAUTH_PRIVATE_KEY_PEM` = (PEM from `scripts/generate-jwk.mjs`)
- `BSKY_OAUTH_KID` = (kid from `scripts/generate-jwk.mjs`)
- `INTERNAL_API_TOKEN` = (random string)
- `BSKY_EXPECTED_HANDLE` = `@blazersroundup.bsky.social`
- `PORT` = 8080 (optional)

**Worker**:
- `DATABASE_URL`
- `WEB_BASE_URL` = `https://<your-web>.up.railway.app`
- `INTERNAL_API_TOKEN` = (same as web)
- `SPOTIFY_CLIENT_ID` / `SPOTIFY_CLIENT_SECRET`
- `GEMINI_API_KEY`
- `POLL_INTERVAL_SECONDS` = 600
- `TIMEZONE` = `America/Los_Angeles`
- `WHISPER_MODEL` = `small-int8`

## Notes
- Per-feed **baseline** prevents backlog spam and is independent of calendar day.
- If a feed republishes an episode with an older timestamp, dedupe by GUID/Spotify ID still prevents reposts.

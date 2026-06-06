-- Shared worker state
create table if not exists state (
  key text primary key,
  value text not null
);

-- Tracks processed episodes. For the YouTube-only worker, spotify_episode_id stores the YouTube video ID.
create table if not exists seen_episodes (
  id bigserial primary key,
  feed_url text not null,
  rss_guid text,
  spotify_episode_id text,
  published_at timestamptz,
  first_seen_at timestamptz default now()
);

create unique index if not exists uq_seen
  on seen_episodes (
    feed_url,
    coalesce(rss_guid, ''),
    coalesce(spotify_episode_id, '')
  );

-- Transcript retry/backoff state for transient YouTube blocks.
create table if not exists transcript_attempts (
  video_id text primary key,
  last_attempt_at timestamptz not null default now(),
  attempt_count integer not null default 0,
  last_error_type text,
  next_retry_at timestamptz
);

-- Gemini retry/backoff state for summary generation failures.
create table if not exists summary_attempts (
  video_id text primary key,
  last_attempt_at timestamptz not null default now(),
  attempt_count integer not null default 0,
  last_error_type text,
  next_retry_at timestamptz
);

-- Persistent health/reputation memory for free transcript proxies.
create table if not exists proxy_health (
  proxy_url text primary key,
  source text not null default 'unknown',
  status text not null default 'candidate',
  success_count integer not null default 0,
  failure_count integer not null default 0,
  blocked_count integer not null default 0,
  last_success_at timestamptz,
  last_failure_at timestamptz,
  last_error_type text,
  cooldown_until timestamptz,
  retired_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_proxy_health_status_cooldown
  on proxy_health(status, cooldown_until);

-- Tracks popular Bluesky posts discovered for simple reposting.
create table if not exists bluesky_repost_candidates (
  uri text primary key,
  cid text not null,
  author_did text,
  author_handle text,
  text text,
  indexed_at timestamptz,
  like_count integer not null default 0,
  repost_count integer not null default 0,
  quote_count integer not null default 0,
  matched_query text,
  status text not null default 'candidate',
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  reposted_at timestamptz,
  last_error text
);

create index if not exists idx_bluesky_repost_candidates_status
  on bluesky_repost_candidates(status, last_seen_at);

-- Tracks external news links discovered through RSS and Google News RSS.
create table if not exists news_seen_links (
  canonical_url text primary key,
  original_url text,
  source_name text,
  source_type text,
  source_trust text,
  title text,
  summary text,
  published_at timestamptz,
  matched_keyword text,
  status text not null default 'candidate',
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  posted_at timestamptz,
  last_error text
);

create index if not exists idx_news_seen_links_status
  on news_seen_links(status, last_seen_at);

create index if not exists idx_news_seen_links_posted_at
  on news_seen_links(posted_at);

-- OAuth session for the bot web service.
create table if not exists oauth_sessions (
  sub text primary key,
  session_json jsonb not null,
  updated_at timestamptz not null default now()
);

-- Temporary OAuth state for the bot web service.
create table if not exists oauth_state (
  key text primary key,
  value jsonb not null,
  created_at timestamptz not null default now()
);

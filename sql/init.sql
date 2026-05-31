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

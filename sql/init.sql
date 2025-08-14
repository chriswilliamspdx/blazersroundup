-- Shared DB
create table if not exists state (
  key text primary key,
  value text not null
);

-- Tracks processed episodes (dedupe forever)
create table if not exists seen_episodes (
  id bigserial primary key,
  feed_url text not null,
  rss_guid text,
  spotify_episode_id text,
  published_at timestamptz,
  first_seen_at timestamptz default now(),
  constraint uq_seen unique (feed_url, coalesce(rss_guid, ''), coalesce(spotify_episode_id, ''))
);

-- OAuth session for the bot (web service)
create table if not exists oauth_sessions (
  did text primary key,
  handle text not null,
  issuer text not null,
  pds_url text not null,
  session_json jsonb not null, -- persisted Session from @atproto/oauth-client (contains refresh token, etc.)
  updated_at timestamptz default now()
);

-- Temporary OAuth state (web service)
create table if not exists oauth_state (
  k text primary key,
  v jsonb not null,
  created_at timestamptz default now()
);

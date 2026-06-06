// web/server.js (ESM) - Bluesky OAuth + Posting API
import express from 'express';
import { Pool } from 'pg';
import pkg from '@atproto/oauth-client-node';
const { NodeOAuthClient } = pkg;
import { JoseKey } from '@atproto/jwk-jose';
import { Agent } from '@atproto/api';
import { buildPost } from './postText.js';

const {
  PORT = 8080,
  DATABASE_URL,
  CLIENT_METADATA_URL,
  WEB_BASE_URL,
  BSKY_OAUTH_PRIVATE_KEY_JWK,
  BSKY_OAUTH_KID,
  BSKY_EXPECTED_HANDLE,
  INTERNAL_API_TOKEN,
  POST_CHAR_LIMIT = '300',
} = process.env;

if (!DATABASE_URL) throw new Error('Missing DATABASE_URL');
if (!CLIENT_METADATA_URL) throw new Error('Missing CLIENT_METADATA_URL');
if (!WEB_BASE_URL) throw new Error('Missing WEB_BASE_URL');
if (!BSKY_OAUTH_PRIVATE_KEY_JWK) throw new Error('Missing BSKY_OAUTH_PRIVATE_KEY_JWK');
if (!INTERNAL_API_TOKEN) throw new Error('Missing INTERNAL_API_TOKEN');

const pg = new Pool({ connectionString: DATABASE_URL });

await pg.query(`
CREATE TABLE IF NOT EXISTS oauth_state (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oauth_sessions (
  sub TEXT PRIMARY KEY,
  session_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
`);

const stateStore = {
  async set(key, internalState) {
    await pg.query(
      `INSERT INTO oauth_state(key, value)
       VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
      [key, internalState],
    );
  },
  async get(key) {
    const res = await pg.query(`SELECT value FROM oauth_state WHERE key = $1`, [key]);
    return res.rows[0]?.value;
  },
  async del(key) {
    await pg.query(`DELETE FROM oauth_state WHERE key = $1`, [key]);
  },
};

const sessionStore = {
  async set(sub, sessionData) {
    await pg.query(
      `INSERT INTO oauth_sessions(sub, session_json, updated_at)
       VALUES ($1, $2, now())
       ON CONFLICT (sub)
       DO UPDATE SET session_json = EXCLUDED.session_json, updated_at = now()`,
      [sub, sessionData],
    );
  },
  async get(sub) {
    const res = await pg.query(`SELECT session_json FROM oauth_sessions WHERE sub = $1`, [sub]);
    return res.rows[0]?.session_json;
  },
  async del(sub) {
    await pg.query(`DELETE FROM oauth_sessions WHERE sub = $1`, [sub]);
  },
};

const rawKeyJwk = JSON.parse(BSKY_OAUTH_PRIVATE_KEY_JWK);
const keyId = BSKY_OAUTH_KID || rawKeyJwk.kid;
if (!keyId) throw new Error('Missing BSKY_OAUTH_KID or private JWK kid');
const keyJwk = {
  ...rawKeyJwk,
  kid: keyId,
  alg: 'ES256',
  key_ops: ['sign'],
};
delete keyJwk.use;
const signingKey = await JoseKey.fromImportable(keyJwk, keyId);

const clientMetadataResponse = await fetch(CLIENT_METADATA_URL);
if (!clientMetadataResponse.ok) {
  throw new Error(`Failed to fetch client metadata: ${clientMetadataResponse.statusText}`);
}
const clientMetadata = await clientMetadataResponse.json();
clientMetadata.scope = 'atproto transition:generic';

const requestLock = async (key, fn) => {
  const c = await pg.connect();
  try {
    await c.query('SELECT pg_advisory_lock(1, hashtext($1))', [key]);
    return await fn();
  } finally {
    try {
      await c.query('SELECT pg_advisory_unlock(1, hashtext($1))', [key]);
    } catch {}
    c.release();
  }
};

const client = new NodeOAuthClient({
  clientMetadata,
  keyset: [signingKey],
  stateStore,
  sessionStore,
  requestLock,
});

const app = express();
app.use(express.json());

const postCharLimit = Number.parseInt(POST_CHAR_LIMIT, 10) || 300;
const embedThumbMaxBytes = 1_000_000;

app.get('/', (_req, res) => res.type('text/plain').send('ok'));

async function sessionStatus() {
  const row = await pg.query(`SELECT sub, updated_at FROM oauth_sessions ORDER BY updated_at DESC LIMIT 1`);
  return { haveSession: row.rowCount > 0, session: row.rows[0] || null };
}

function cleanCardText(value, fallback = '') {
  return String(value || fallback)
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 300);
}

function parseYouTubeVideoId(url) {
  try {
    const parsed = new URL(url);
    if (parsed.hostname === 'youtu.be') return parsed.pathname.split('/').filter(Boolean)[0] || null;
    if (parsed.hostname.endsWith('youtube.com')) return parsed.searchParams.get('v');
  } catch {}
  return null;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 10000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

async function uploadThumbnailBlob(agent, thumbnailUrl) {
  if (!thumbnailUrl) return null;
  const response = await fetchWithTimeout(thumbnailUrl, {}, 10000);
  if (!response.ok) throw new Error(`thumbnail fetch failed: ${response.status}`);

  const contentType = response.headers.get('content-type') || 'image/jpeg';
  if (!contentType.startsWith('image/')) throw new Error(`thumbnail was not an image: ${contentType}`);

  const contentLength = Number.parseInt(response.headers.get('content-length') || '0', 10);
  if (contentLength > embedThumbMaxBytes) throw new Error(`thumbnail too large: ${contentLength}`);

  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > embedThumbMaxBytes) throw new Error(`thumbnail too large: ${bytes.byteLength}`);

  const { data } = await agent.uploadBlob(bytes, { encoding: contentType });
  return data.blob;
}

async function buildExternalEmbed(agent, embedRequest) {
  const uri = cleanCardText(embedRequest?.uri);
  if (!uri || !uri.startsWith('https://')) return null;

  const card = {
    uri,
    title: cleanCardText(embedRequest?.title, 'YouTube video'),
    description: cleanCardText(embedRequest?.description, 'YouTube'),
  };

  let thumbnailUrl = null;
  try {
    const oembedUrl = `https://www.youtube.com/oembed?url=${encodeURIComponent(uri)}&format=json`;
    const response = await fetchWithTimeout(oembedUrl, {}, 10000);
    if (response.ok) {
      const data = await response.json();
      card.title = cleanCardText(data.title, card.title);
      card.description = cleanCardText(
        data.author_name ? `YouTube video by ${data.author_name}` : card.description,
        card.description,
      );
      thumbnailUrl = data.thumbnail_url || null;
    }
  } catch (err) {
    console.warn('[post-thread] YouTube oEmbed failed:', err.message);
  }

  if (!thumbnailUrl) {
    const videoId = parseYouTubeVideoId(uri);
    if (videoId) thumbnailUrl = `https://i.ytimg.com/vi/${videoId}/hqdefault.jpg`;
  }

  try {
    const thumb = await uploadThumbnailBlob(agent, thumbnailUrl);
    if (thumb) card.thumb = thumb;
  } catch (err) {
    console.warn('[post-thread] thumbnail upload failed:', err.message);
  }

  return {
    $type: 'app.bsky.embed.external',
    external: card,
  };
}

async function restoreBotAgent() {
  const row = await pg.query(`SELECT sub FROM oauth_sessions ORDER BY updated_at DESC LIMIT 1`);
  if (!row.rowCount) {
    const err = new Error('OAuth session not found. Visit /auth/start to connect.');
    err.statusCode = 401;
    throw err;
  }

  const did = row.rows[0].sub;
  const oauthSession = await client.restore(did);
  if (!oauthSession) {
    const err = new Error('OAuth session restore failed. Re-authorization required.');
    err.statusCode = 401;
    throw err;
  }

  return new Agent(oauthSession);
}

async function createRepost(agent, uri, cid) {
  const payload = {
    repo: agent.did,
    collection: 'app.bsky.feed.repost',
    record: {
      subject: { uri, cid },
      createdAt: new Date().toISOString(),
    },
  };
  if (agent.com?.atproto?.repo?.createRecord) {
    return agent.com.atproto.repo.createRecord(payload);
  }
  if (agent.api?.com?.atproto?.repo?.createRecord) {
    return agent.api.com.atproto.repo.createRecord(payload);
  }
  throw new Error('ATProto createRecord client is unavailable');
}

async function searchPosts(agent, params) {
  if (agent.app?.bsky?.feed?.searchPosts) {
    return agent.app.bsky.feed.searchPosts(params);
  }
  if (agent.api?.app?.bsky?.feed?.searchPosts) {
    return agent.api.app.bsky.feed.searchPosts(params);
  }
  throw new Error('Bluesky searchPosts client is unavailable');
}

app.get('/session/status', async (_req, res) => {
  res.json(await sessionStatus());
});

app.get('/session/debug', async (req, res) => {
  const token = req.get('X-Internal-Token') || '';
  if (token !== INTERNAL_API_TOKEN) return res.status(403).json({ error: 'forbidden' });
  res.json(await sessionStatus());
});

app.get('/auth/start', async (req, res, next) => {
  try {
    const handle = (req.query.handle || BSKY_EXPECTED_HANDLE)?.toString().replace(/^@/, '');
    if (!handle) return res.status(400).send('missing ?handle');

    const url = await client.authorize(handle);
    return res.redirect(url);
  } catch (err) {
    return next(err);
  }
});

app.get('/oauth/callback', async (req, res, next) => {
  try {
    const params = new URLSearchParams(req.url.split('?')[1] || '');
    const { session } = await client.callback(params);

    const agent = new Agent(session);
    const profile = await agent.getProfile({ actor: agent.did }).catch(() => null);

    res
      .type('text/plain')
      .send(
        `SUCCESS! OAuth complete for DID: ${session.did}\n` +
        (profile ? `Logged in as: ${profile.data.handle}\n` : '') +
        `You can now close this window. The bot is authorized.`,
      );
  } catch (err) {
    return next(err);
  }
});

app.post('/post-thread', async (req, res, next) => {
  try {
    const token = req.get('X-Internal-Token') || '';
    if (token !== INTERNAL_API_TOKEN) return res.status(403).json({ error: 'forbidden' });

    const { firstText, secondText, firstEmbed } = req.body;
    if (!firstText || !secondText) {
      return res.status(400).json({ error: 'missing firstText or secondText' });
    }

    const agent = await restoreBotAgent();
    const embed = firstEmbed ? await buildExternalEmbed(agent, firstEmbed) : null;
    const firstPost = await agent.post(buildPost(firstText, undefined, postCharLimit, embed));
    await agent.post(buildPost(secondText, { root: firstPost, parent: firstPost }, postCharLimit));

    return res.json({ ok: true });
  } catch (err) {
    console.error('[post-thread] error:', err);
    return next(err);
  }
});

app.post('/search-posts', async (req, res, next) => {
  try {
    const token = req.get('X-Internal-Token') || '';
    if (token !== INTERNAL_API_TOKEN) return res.status(403).json({ error: 'forbidden' });

    const q = String(req.body?.q || '').trim();
    if (!q) return res.status(400).json({ error: 'missing q' });

    const limit = Math.max(1, Math.min(100, Number.parseInt(req.body?.limit || '50', 10) || 50));
    const sort = ['top', 'latest'].includes(req.body?.sort) ? req.body.sort : 'top';
    const params = { q, limit, sort };
    if (req.body?.since) params.since = String(req.body.since);

    const agent = await restoreBotAgent();
    const result = await searchPosts(agent, params);
    return res.json({
      ok: true,
      posts: result?.data?.posts || result?.posts || [],
      cursor: result?.data?.cursor || result?.cursor || null,
      hitsTotal: result?.data?.hitsTotal ?? result?.hitsTotal ?? null,
    });
  } catch (err) {
    console.error('[search-posts] error:', err);
    return next(err);
  }
});

app.post('/repost', async (req, res, next) => {
  try {
    const token = req.get('X-Internal-Token') || '';
    if (token !== INTERNAL_API_TOKEN) return res.status(403).json({ error: 'forbidden' });

    const { uri, cid, authorDid } = req.body;
    if (!uri || !cid) {
      return res.status(400).json({ error: 'missing uri or cid' });
    }

    const agent = await restoreBotAgent();
    if (authorDid && authorDid === agent.did) {
      return res.status(400).json({ error: 'will not repost the bot itself' });
    }

    const result = await createRepost(agent, String(uri), String(cid));
    return res.json({ ok: true, uri: result?.data?.uri, cid: result?.data?.cid });
  } catch (err) {
    console.error('[repost] error:', err);
    return next(err);
  }
});

app.use((err, _req, res, _next) => {
  console.error('--- unhandled error ---');
  console.error(err);
  res.status(err.statusCode || 500).json({
    error: err.name || 'ServerError',
    message: err.message,
  });
});

app.listen(PORT, () => {
  console.log(`web listening on :${PORT}`);
});

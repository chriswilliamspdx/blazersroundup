// server.js — Node 20+, ESM

import express from 'express';
import { Pool } from 'pg';
import { importPKCS8, exportJWK } from 'jose';
import { NodeOAuthClient } from '@atproto/oauth-client-node';
import { AtpAgent } from '@atproto/api';

// ---------- Config ----------
const PORT = process.env.PORT || 8080;
const DATABASE_URL = process.env.DATABASE_URL;
const CLIENT_METADATA_URL = process.env.CLIENT_METADATA_URL; // e.g. https://chriswilliamspdx.github.io/blazersroundup/bsky-client.json
const PRIVATE_KEY_PEM = process.env.BSKY_OAUTH_PRIVATE_KEY_PEM; // PKCS#8 EC P-256

if (!DATABASE_URL) throw new Error('Missing DATABASE_URL');
if (!CLIENT_METADATA_URL) throw new Error('Missing CLIENT_METADATA_URL');
if (!PRIVATE_KEY_PEM) throw new Error('Missing BSKY_OAUTH_PRIVATE_KEY_PEM');

// Build HTTPS callback from the live Railway hostname
function getCallbackUrl(req) {
  const host =
    process.env.RAILWAY_PUBLIC_DOMAIN ||
    req.headers['x-forwarded-host'] ||
    req.headers.host;
  return `https://${host}/auth/callback`;
}

// ---------- DB ----------
const pool = new Pool({ connectionString: DATABASE_URL });

// Create simple KV tables the OAuth client stores will use
async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS oauth_state (
      key TEXT PRIMARY KEY,
      val JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS oauth_sessions (
      key TEXT PRIMARY KEY,          -- DID (subject)
      val JSONB NOT NULL,            -- tokenSet + metadata
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

// Tiny KV helper
const kv = {
  async get(table, key) {
    const { rows } = await pool.query(
      `SELECT val FROM ${table} WHERE key=$1`,
      [key],
    );
    return rows[0]?.val ?? null;
  },
  async set(table, key, val) {
    await pool.query(
      `INSERT INTO ${table} (key, val) VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET val = EXCLUDED.val, updated_at = now()`,
      [key, val],
    );
  },
  async del(table, key) {
    await pool.query(`DELETE FROM ${table} WHERE key=$1`, [key]);
  },
  async all(table) {
    const { rows } = await pool.query(
      `SELECT key, val FROM ${table} ORDER BY key`,
    );
    return rows;
  },
  async clear(table) {
    await pool.query(`TRUNCATE ${table}`);
  },
};

// Stores wired into the OAuth client
const stateStore = {
  get: (key) => kv.get('oauth_state', key),
  set: (key, val) => kv.set('oauth_state', key, val),
  del: (key) => kv.del('oauth_state', key),
};

const tokenStore = {
  get: (key) => kv.get('oauth_sessions', key), // key is DID
  set: (key, val) => kv.set('oauth_sessions', key, val),
  del: (key) => kv.del('oauth_sessions', key),
};

// ---------- OAuth client ----------
async function buildClient(callbackUrl) {
  // Use global fetch (Node 20) — no node-fetch import required
  const mdRes = await fetch(CLIENT_METADATA_URL);
  if (!mdRes.ok) {
    throw new Error(`Failed to fetch client metadata: ${mdRes.status}`);
  }
  const clientMetadata = await mdRes.json();

  // Ensure our live callback is listed
  if (!clientMetadata.redirect_uris?.includes(callbackUrl)) {
    clientMetadata.redirect_uris = [callbackUrl];
  }

  // Import your ES256 private key (PKCS#8) for DPoP
  const keyLike = await importPKCS8(PRIVATE_KEY_PEM, 'ES256');
  const dpopJwk = await exportJWK(keyLike);
  dpopJwk.alg = 'ES256';
  dpopJwk.use = 'sig';

  return new NodeOAuthClient({
    clientMetadata,
    stateStore,
    tokenStore,
    dpopKey: keyLike,
  });
}

// Get an authenticated AT agent using the freshest tokens from the store
async function getAgent(oauth) {
  const rows = await kv.all('oauth_sessions');
  if (!rows.length) {
    throw new Error('No OAuth session found. Visit /auth/start first.');
  }

  // If you only authorize one account, first row is fine.
  const { key: did } = rows[0];

  // Ask the client for the tokenSet (it will refresh if needed)
  const tokenSet = await oauth.getTokenSet(did);
  if (!tokenSet?.access_token) {
    throw new Error('OAuth session expired/cleared. Visit /auth/start to reconnect.');
  }

  const agent = new AtpAgent({ service: 'https://bsky.social' });
  await agent.resumeSession({
    accessJwt: tokenSet.access_token,
    refreshJwt: tokenSet.refresh_token,
    did,
    handle: tokenSet.handle ?? undefined,
  });
  return agent;
}

// ---------- App ----------
const app = express();
app.use(express.json());

app.get('/', (_req, res) => res.type('text/plain').send('OK'));

// Start OAuth
app.get('/auth/start', async (req, res) => {
  try {
    await ensureSchema();
    const callbackUrl = getCallbackUrl(req);
    const oauth = await buildClient(callbackUrl);

    const handle = (req.query.handle || '').toString() || undefined;
    const prompt = (req.query.prompt || '').toString() || undefined;

    const url = await oauth.authorize('https://bsky.social', {
      redirectUri: callbackUrl,
      scope: 'atproto',
      login_hint: handle,
      prompt, // 'consent' to force approval
    });

    res.redirect(url.toString());
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'auth start failed' });
  }
});

// OAuth callback
app.get('/auth/callback', async (req, res) => {
  try {
    await ensureSchema();
    const callbackUrl = getCallbackUrl(req);
    const oauth = await buildClient(callbackUrl);

    // Library reads state & code from req.url and persists the tokenSet under DID
    await oauth.callback('https://bsky.social', req.url);

    res.type('text/plain').send('OAuth complete. You can close this window.');
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'oauth callback failed' });
  }
});

// Debug current saved sessions
app.get('/session/debug', async (_req, res) => {
  const rows = await kv.all('oauth_sessions');
  res.json({ haveSession: rows.length > 0, rows });
});

// Hard reset stores
app.post('/admin/clear-session', async (_req, res) => {
  await kv.clear('oauth_sessions');
  await kv.clear('oauth_state');
  res.json({ cleared: true });
});

// Simple post test
app.post('/post', async (req, res) => {
  try {
    const callbackUrl = getCallbackUrl(req);
    const oauth = await buildClient(callbackUrl);
    const agent = await getAgent(oauth);

    const text = (req.body?.text || '').toString().slice(0, 300) || 'hello from OAuth bot';
    const result = await agent.post({ text });
    res.json({ ok: true, uri: result.uri });
  } catch (err) {
    const msg = (err?.message || '').toLowerCase();
    if (msg.includes('no oauth session') || msg.includes('expired/cleared')) {
      return res.status(401).json({ error: 'reauth required' });
    }
    console.error(err);
    res.status(500).json({ error: 'post failed' });
  }
});

app.listen(PORT, () => console.log(`web listening on :${PORT}`));

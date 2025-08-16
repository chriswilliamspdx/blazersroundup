// server.js (full file)
// Node 20+, type:module in package.json

import express from 'express';
import fetch from 'node-fetch';
import { Pool } from 'pg';
import { importPKCS8, exportJWK } from 'jose';
import {
  NodeOAuthClient,
} from '@atproto/oauth-client-node';
import { AtpAgent } from '@atproto/api';

// ---------- Config ----------
const PORT = process.env.PORT || 8080;
const DATABASE_URL = process.env.DATABASE_URL;
const CLIENT_METADATA_URL = process.env.CLIENT_METADATA_URL; // e.g. https://chriswilliamspdx.github.io/blazersroundup/bsky-client.json
const PRIVATE_KEY_PEM = process.env.BSKY_OAUTH_PRIVATE_KEY_PEM; // PKCS#8 EC P-256

if (!DATABASE_URL) throw new Error('Missing DATABASE_URL');
if (!CLIENT_METADATA_URL) throw new Error('Missing CLIENT_METADATA_URL');
if (!PRIVATE_KEY_PEM) throw new Error('Missing BSKY_OAUTH_PRIVATE_KEY_PEM');

// Your deployed HTTPS callback
function getCallbackUrl(req) {
  // Trust Railway/X-Forwarded-Proto; always build HTTPS URL
  const host = process.env.RAILWAY_PUBLIC_DOMAIN || req.headers['x-forwarded-host'] || req.headers.host;
  return `https://${host}/auth/callback`;
}

// ---------- DB ----------
const pool = new Pool({ connectionString: DATABASE_URL });

// KV tables that the stores below use
async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS oauth_state (
      key TEXT PRIMARY KEY,
      val JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS oauth_sessions (
      key TEXT PRIMARY KEY,
      val JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // If you previously created mismatched columns, it’s safest to keep only key/val.
  // These ALTERs will no-op if extra columns don’t exist.
  await pool.query(`DO $$
  BEGIN
    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_name = 'oauth_sessions' AND column_name IN ('did','issuer','token_set','tokenSet','sub')
    ) THEN
      -- We won't drop columns automatically to avoid surprises, but we will ignore them.
      NULL;
    END IF;
  END$$;`);
}

// Simple key/value helpers
const kv = {
  async get(table, key) {
    const { rows } = await pool.query(`SELECT val FROM ${table} WHERE key=$1`, [key]);
    return rows[0]?.val ?? null;
  },
  async set(table, key, val) {
    await pool.query(
      `INSERT INTO ${table} (key,val) VALUES ($1,$2)
       ON CONFLICT (key) DO UPDATE SET val=EXCLUDED.val, updated_at=COALESCE(oauth_sessions.updated_at, now())`,
      [key, val],
    );
  },
  async del(table, key) {
    await pool.query(`DELETE FROM ${table} WHERE key=$1`, [key]);
  },
  async all(table) {
    const { rows } = await pool.query(`SELECT key, val FROM ${table} ORDER BY key`);
    return rows;
  },
  async clear(table) {
    await pool.query(`TRUNCATE ${table}`);
  },
};

// Stores the OAuth client will use
const stateStore = {
  get: (key) => kv.get('oauth_state', key),
  set: (key, val) => kv.set('oauth_state', key, val),
  del: (key) => kv.del('oauth_state', key),
};

const tokenStore = {
  get: (key) => kv.get('oauth_sessions', key),   // key is the DID (sub)
  set: (key, val) => kv.set('oauth_sessions', key, val),
  del: (key) => kv.del('oauth_sessions', key),
};

// ---------- OAuth client ----------
async function buildClient(callbackUrl) {
  // Load client metadata (your GitHub Pages JSON)
  const mdRes = await fetch(CLIENT_METADATA_URL);
  if (!mdRes.ok) throw new Error(`Failed to fetch client metadata: ${mdRes.status}`);
  const clientMetadata = await mdRes.json();

  // Replace redirect_uris with our live Railway callback (metadata can list many;
  // here we ensure the one we’ll use is present)
  if (!clientMetadata.redirect_uris?.includes(callbackUrl)) {
    clientMetadata.redirect_uris = [callbackUrl];
  }

  // Import your ES256 private key and convert to JWK for DPoP
  const keyLike = await importPKCS8(PRIVATE_KEY_PEM, 'ES256');
  const dpopJwk = await exportJWK(keyLike);
  dpopJwk.alg = 'ES256';
  dpopJwk.use = 'sig';

  const client = new NodeOAuthClient({
    clientMetadata,
    // Persisted stores
    stateStore,
    tokenStore,
    // DPoP signing key
    dpopKey: keyLike,
  });

  return client;
}

// Helper to get an Agent with the freshest tokens.
// If no tokens or they’re expired, we throw a clear error so the route can redirect you to /auth/start.
async function getAgent(oauth) {
  // Tokens are stored per subject (DID). Fetch the most recent row.
  const rows = await kv.all('oauth_sessions');
  if (!rows.length) {
    throw new Error('No OAuth session found. Visit /auth/start first.');
  }

  // If you only ever authorize one account for this app, using the first row is fine.
  const { key: did, val: tokenSet } = rows[0];

  // Ask the client to refresh if needed and re-save; fall back to existing tokenSet if still valid.
  const fresh = await oauth.getTokenSet(did).catch(() => null);
  const use = fresh || tokenSet;

  // Minimal sanity check
  if (!use?.access_token) {
    throw new Error('OAuth session expired/cleared. Visit /auth/start to reconnect.');
    }

  const agent = new AtpAgent({ service: 'https://bsky.social' });
  // AtpAgent “resume” with OAuth: set tokens directly
  await agent.resumeSession({
    accessJwt: use.access_token,
    refreshJwt: use.refresh_token,
    did,
    handle: use.handle ?? undefined,
  });

  return agent;
}

// ---------- App ----------
const app = express();
app.use(express.json());

app.get('/', (_req, res) => {
  res.type('text/plain').send('OK');
});

// 1) Start OAuth
//    Optional query:
//      ?handle=@blazersroundup.bsky.social
//      &prompt=consent   (force consent screen)
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
      login_hint: handle,  // pre-fill the account
      prompt,              // pass "consent" to force approval UI
    });

    // Save a small breadcrumb so we can reuse the same client on callback
    // (clientMetadata + callback are deterministic, so we can rebuild too)
    res.redirect(url.toString());
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'auth start failed' });
  }
});

// 2) OAuth callback (Bluesky will redirect here)
app.get('/auth/callback', async (req, res) => {
  try {
    await ensureSchema();
    const callbackUrl = getCallbackUrl(req);
    const oauth = await buildClient(callbackUrl);

    // The node client reads the full query string (state & code) and
    // stores the tokenSet in tokenStore using the subject (DID) as key.
    const { subject, tokenSet } = await oauth.callback('https://bsky.social', req.url);

    // tokenStore.set(subject, tokenSet) is already done internally, but we rely on it being there.
    res.type('text/plain').send('OAuth complete. You can close this window.');
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'oauth callback failed' });
  }
});

// 3) Tiny debug helpers
app.get('/session/debug', async (_req, res) => {
  const rows = await kv.all('oauth_sessions');
  res.json({
    haveSession: rows.length > 0,
    rows,
  });
});

app.post('/admin/clear-session', async (_req, res) => {
  await kv.clear('oauth_sessions');
  await kv.clear('oauth_state');
  res.json({ cleared: true });
});

// 4) Smoke-test posting (will return a clear error if not logged in)
app.post('/post', async (req, res) => {
  try {
    const callbackUrl = getCallbackUrl(req);
    const oauth = await buildClient(callbackUrl);
    const agent = await getAgent(oauth);

    const text = (req.body?.text || '').toString().slice(0, 300) || 'hello from OAuth bot';
    const result = await agent.post({
      text,
    });
    res.json({ ok: true, uri: result.uri });
  } catch (err) {
    const msg = (err?.message || '').toLowerCase();
    if (msg.includes('no oauth session')) {
      return res.status(401).json({ error: 'reauth required' });
    }
    if (msg.includes('expired/cleared')) {
      return res.status(401).json({ error: 'reauth required' });
    }
    console.error(err);
    res.status(500).json({ error: 'post failed' });
  }
});

app.listen(PORT, () => {
  console.log(`web listening on :${PORT}`);
});


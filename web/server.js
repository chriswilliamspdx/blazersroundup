// web/server.js (ESM) - Self-Contained OAuth Server
import express from 'express';
import { Pool } from 'pg';
import { randomUUID } from 'node:crypto';
import pkg from '@atproto/oauth-client-node';
const { NodeOAuthClient } = pkg;
import { JoseKey } from '@atproto/jwk-jose';
import { Agent } from '@atproto/api';

// ------------------------------
// Env Variables
// ------------------------------
const {
  PORT = 8080,
  DATABASE_URL,
  CLIENT_METADATA_URL, // The public URL of THIS server's /bsky-client.json endpoint
  BSKY_OAUTH_PRIVATE_KEY_JWK,
  BSKY_OAUTH_KID,
  BSKY_EXPECTED_HANDLE,
  INTERNAL_API_TOKEN,
} = process.env;

if (!DATABASE_URL || !CLIENT_METADATA_URL || !BSKY_OAUTH_PRIVATE_KEY_JWK || !INTERNAL_API_TOKEN) {
  throw new Error('Missing one or more required environment variables.');
}

// ------------------------------
// Postgres Setup
// ------------------------------
const pg = new Pool({ connectionString: DATABASE_URL });

await pg.query(`
CREATE TABLE IF NOT EXISTS oauth_state ( key TEXT PRIMARY KEY, value JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS oauth_sessions ( sub TEXT PRIMARY KEY, value JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
`);

const stateStore = {
  async set(key, internalState) { await pg.query(`INSERT INTO oauth_state(key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, [key, internalState]); },
  async get(key) { const res = await pg.query(`SELECT value FROM oauth_state WHERE key = $1`, [key]); return res.rows[0]?.value; },
  async del(key) { await pg.query(`DELETE FROM oauth_state WHERE key = $1`, [key]); },
};
const sessionStore = {
  async set(sub, sessionData) { await pg.query(`INSERT INTO oauth_sessions(sub, value, updated_at) VALUES ($1, $2, now()) ON CONFLICT (sub) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, [sub, sessionData]); },
  async get(sub) { const res = await pg.query(`SELECT value FROM oauth_sessions WHERE sub = $1`, [sub]); return res.rows[0]?.value; },
  async del(sub) { await pg.query(`DELETE FROM oauth_sessions WHERE sub = $1`, [sub]); },
};

// ------------------------------
// OAuth Client Setup
// ------------------------------
const keyJwk = JSON.parse(BSKY_OAUTH_PRIVATE_KEY_JWK);
const signingKey = await JoseKey.fromImportable(keyJwk, BSKY_OAUTH_KID);
const publicJwk = await signingKey.toPublicJwk();
if (!publicJwk.kid) publicJwk.kid = signingKey.kid

const webBaseUrl = new URL(CLIENT_METADATA_URL).origin;
const redirectUri = new URL('/oauth/callback', webBaseUrl).toString();
const jwksUri = new URL('/jwks.json', webBaseUrl).toString();

const clientMetadata = {
  client_id: CLIENT_METADATA_URL,
  client_name: 'Blazers Roundup Bot',
  redirect_uris: [redirectUri],
  jwks_uri: jwksUri,
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  scope: 'atproto',
  token_endpoint_auth_method: 'private_key_jwt',
  token_endpoint_auth_signing_alg: 'ES256',
};

const client = new NodeOAuthClient({
  clientMetadata,
  keyset: [signingKey],
  stateStore,
  sessionStore,
});

const app = express();
app.use(express.json());

// ------------------------------
// NEW: Serve Self-Hosted Metadata
// ------------------------------
app.get('/bsky-client.json', (_req, res) => {
  res.json(clientMetadata);
});

app.get('/jwks.json', (_req, res) => {
  res.json({ keys: [publicJwk] });
});

// ------------------------------
// Routes
// ------------------------------
app.get('/', (_req, res) => res.type('text/plain').send('ok'));

app.get('/session/debug', async (_req, res) => {
  const row = await pg.query(`SELECT sub, value, updated_at FROM oauth_sessions ORDER BY updated_at DESC LIMIT 1`);
  res.json({ haveSession: row.rowCount > 0, session: row.rows[0] || null });
});

app.get('/auth/start', async (req, res, next) => {
  try {
    const handle = (req.query.handle || BSKY_EXPECTED_HANDLE)?.toString();
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
    await sessionStore.set(session.did, session);
    const agent = new Agent({ service: 'https://bsky.social', ...session });
    const profile = await agent.getProfile({ actor: session.did }).catch(() => null);
    
    res.type('text/plain').send(
      `✅ SUCCESS! OAuth complete for DID: ${session.did}\n` +
      (profile ? `Logged in as: ${profile.data.handle}\n` : '') +
      `You can now close this window. The bot is authorized.`
    );
  } catch (err) {
    return next(err);
  }
});

app.post('/post-thread', async (req, res, next) => {
  try {
    const token = req.get('X-Internal-Token') || '';
    if (token !== INTERNAL_API_TOKEN) {
      return res.status(403).json({ error: 'forbidden' });
    }
    
    const { firstText, secondText } = req.body;
    if (!firstText || !secondText) {
      return res.status(400).json({ error: 'missing firstText or secondText' });
    }
    
    const row = await pg.query(`SELECT sub FROM oauth_sessions ORDER BY updated_at DESC LIMIT 1`);
    if (!row.rowCount) {
      return res.status(401).json({ error: 'OAuth session not found. Visit /auth/start to connect.' });
    }
    
    const session = await client.restore(row.rows[0].sub);
    const agent = new Agent({ service: 'https://bsky.social', ...session });
    
    const firstPost = await agent.post({ text: firstText });
    await agent.post({
      text: secondText,
      reply: { root: firstPost, parent: firstPost }
    });
    
    return res.json({ ok: true });
  } catch(err) {
    return next(err);
  }
});

app.use((err, _req, res, _next) => {
  console.error('--- unhandled error ---');
  console.error(err);
  res.status(500).json({ error: err.name || 'ServerError', message: err.message });
});

app.listen(PORT, () => {
  console.log(`web listening on :${PORT}`);
});

app.listen(PORT, () => {
  console.log(`web listening on :${PORT}`);
});

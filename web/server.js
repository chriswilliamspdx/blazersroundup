// web/server.js (ESM) - Bluesky OAuth + Posting API
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
  CLIENT_METADATA_URL,
  WEB_BASE_URL,
  BSKY_OAUTH_PRIVATE_KEY_JWK,
  BSKY_OAUTH_KID,
  BSKY_EXPECTED_HANDLE,
  INTERNAL_API_TOKEN,
} = process.env;

if (!DATABASE_URL) throw new Error('Missing DATABASE_URL');
if (!CLIENT_METADATA_URL) throw new Error('Missing CLIENT_METADATA_URL');
if (!WEB_BASE_URL) throw new Error('Missing WEB_BASE_URL');
if (!BSKY_OAUTH_PRIVATE_KEY_JWK) throw new Error('Missing BSKY_OAUTH_PRIVATE_KEY_JWK');
if (!INTERNAL_API_TOKEN) throw new Error('Missing INTERNAL_API_TOKEN');

// ------------------------------
// Postgres Setup
// ------------------------------
const pg = new Pool({ connectionString: DATABASE_URL });

await pg.query(`
CREATE TABLE IF NOT EXISTS oauth_state ( key TEXT PRIMARY KEY, value JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS oauth_sessions ( sub TEXT PRIMARY KEY, value JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
`);

const stateStore = {
  async set(key, internalState) { await pg.query(`INSERT INTO oauth_state(k, v) VALUES ($1, $2) ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v`, [key, internalState]); },
  async get(key) { const res = await pg.query(`SELECT v FROM oauth_state WHERE k = $1`, [key]); return res.rows[0]?.v; },
  async del(key) { await pg.query(`DELETE FROM oauth_state WHERE k = $1`, [key]); },
};
const sessionStore = {
  async set(sub, sessionData) { await pg.query(`INSERT INTO oauth_sessions(sub, session_json, updated_at) VALUES ($1, $2, now()) ON CONFLICT (sub) DO UPDATE SET session_json = EXCLUDED.session_json, updated_at = now()`, [sub, sessionData]); },
  async get(sub) { const res = await pg.query(`SELECT session_json FROM oauth_sessions WHERE sub = $1`, [sub]); return res.rows[0]?.session_json; },
  async del(sub) { await pg.query(`DELETE FROM oauth_sessions WHERE sub = $1`, [sub]); },
};

// ------------------------------
// OAuth Client Setup
// ------------------------------
const keyJwk = JSON.parse(BSKY_OAUTH_PRIVATE_KEY_JWK);
const signingKey = await JoseKey.fromImportable(keyJwk, BSKY_OAUTH_KID);

const clientMetadataResponse = await fetch(CLIENT_METADATA_URL);
if (!clientMetadataResponse.ok) {
  throw new Error(`Failed to fetch client metadata: ${clientMetadataResponse.statusText}`)
}
const clientMetadata = await clientMetadataResponse.json();

const client = new NodeOAuthClient({
  clientMetadata,
  keyset: [signingKey],
  stateStore,
  sessionStore,
});

const app = express();
app.use(express.json());

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

// FIX: This route is the only part that has been changed.
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
    
    // FIX: Instead of using client.restore(), we will fetch the session data directly.
    const row = await pg.query(`SELECT session_json FROM oauth_sessions ORDER BY updated_at DESC LIMIT 1`);
    if (!row.rowCount) {
      return res.status(401).json({ error: 'OAuth session not found. Please authorize the bot again.' });
    }
    
    // FIX: Create the agent directly from the session data stored in the database.
    // This is a more direct and reliable method that avoids the TokenRefreshError.
    const agent = new Agent({ service: 'https://bsky.social', ...row.rows[0].session_json });
    
    const firstPost = await agent.post({ text: firstText });
    await agent.post({
      text: secondText,
      reply: {
        root: firstPost,
        parent: firstPost
      }
    });
    
    return res.json({ ok: true });
  } catch(err) {
    return next(err);
  }
});

app.use((err, _req, res, _next) => {
  console.error('--- unhandled error ---');
  console.error(err);
  res.status(500).json({ 
    error: err.name || 'ServerError',
    message: err.message,
  });
});

app.listen(PORT, () => {
  console.log(`web listening on :${PORT}`);
});

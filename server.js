// Node 20+, ESM
import express from 'express';
import { Pool } from 'pg';
import { NodeOAuthClient, NodeDpopStore } from '@atproto/oauth-client-node';
import { JoseKey } from '@atproto/jwk-jose';

// ---- Env expectations -------------------------------------------------------
// DATABASE_URL                 -> Railway Postgres URL (private connection) 
// CLIENT_METADATA_URL          -> https://<your-gh-username>.github.io/<repo>/bsky-client.json
// BSKY_OAUTH_PRIVATE_KEY_PEM   -> Your ES256 (P-256) private key in PKCS#8 PEM
// BSKY_OAUTH_KID               -> kid that matches the public key in your jwks.json
// PORT (optional)              -> Railway sets PORT; default 8080
// ---------------------------------------------------------------------------

const {
  DATABASE_URL,
  CLIENT_METADATA_URL,
  BSKY_OAUTH_PRIVATE_KEY_PEM,
  BSKY_OAUTH_KID,
  PORT = 8080,
} = process.env;

if (!DATABASE_URL) throw new Error('Missing DATABASE_URL');
if (!CLIENT_METADATA_URL) throw new Error('Missing CLIENT_METADATA_URL');
if (!BSKY_OAUTH_PRIVATE_KEY_PEM) throw new Error('Missing BSKY_OAUTH_PRIVATE_KEY_PEM');
if (!BSKY_OAUTH_KID) throw new Error('Missing BSKY_OAUTH_KID');

const app = express();

// ---- Postgres setup & schema ------------------------------------------------
const pool = new Pool({ connectionString: DATABASE_URL });

async function ensureSchema() {
  await pool.query(`
    create table if not exists oauth_state (
      id text primary key,
      value jsonb not null,
      updated_at timestamptz not null default now()
    );
  `);
  await pool.query(`
    create table if not exists oauth_sessions (
      sub text primary key,
      issuer text not null,
      session jsonb not null,
      updated_at timestamptz not null default now()
    );
  `);
  // Keep track of "current" user for this single-user app
  await pool.query(`
    create table if not exists oauth_current (
      id smallint primary key default 1,
      sub text
    );
  `);
}
await ensureSchema();

// ---- SimpleStore helpers (must have get/set/del) ---------------------------
// These stores satisfy the SimpleStore<T> shape expected by @atproto/* libs.
const stateStore = {
  async get(id) {
    const r = await pool.query('select value from oauth_state where id=$1', [id]);
    return r.rows[0]?.value;
  },
  async set(id, value) {
    await pool.query(
      `insert into oauth_state(id,value,updated_at)
       values ($1,$2,now())
       on conflict(id) do update set value=excluded.value, updated_at=now()`,
      [id, value]
    );
  },
  async del(id) {
    await pool.query('delete from oauth_state where id=$1', [id]);
  },
};

const sessionStore = {
  // key is "sub" (the user's DID). value is the SessionData JSON.
  async get(sub) {
    const r = await pool.query('select session from oauth_sessions where sub=$1', [sub]);
    return r.rows[0]?.session;
  },
  async set(sub, sessionData) {
    // issuer isn’t included in SessionData; pull from stored state if present
    const issuer = sessionData?.issuer ?? 'https://bsky.social';
    await pool.query(
      `insert into oauth_sessions(sub,issuer,session,updated_at)
       values ($1,$2,$3,now())
       on conflict(sub) do update set issuer=$2, session=$3, updated_at=now()`,
      [sub, issuer, sessionData]
    );
    await pool.query(
      `insert into oauth_current(id,sub) values (1,$1)
       on conflict(id) do update set sub=excluded.sub`,
      [sub]
    );
  },
  async del(sub) {
    await pool.query('delete from oauth_sessions where sub=$1', [sub]);
    await pool.query('update oauth_current set sub=null where id=1');
  },
};

// ---- Load client metadata & signing key (ES256) -----------------------------
// The docs require Authorization Code + PKCE + PAR and private_key_jwt using ES256.
// Your bsky-client.json + jwks.json should reflect that.  
async function loadClientMetadata(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch client metadata: ${res.status}`);
  const json = await res.json();
  // Minimal sanity checks
  if (!Array.isArray(json.redirect_uris) || json.redirect_uris.length === 0) {
    throw new Error('client metadata missing redirect_uris');
  }
  return json;
}

function summarizeKey(jwk) {
  return {
    type: typeof jwk,
    kty: jwk.kty,
    crv: jwk.crv,
    has_d: !!jwk.d,
    kid_type: typeof jwk.kid,
  };
}

const clientMetadata = await loadClientMetadata(CLIENT_METADATA_URL);

// Import your ES256 private key (PKCS#8 PEM) and wrap it for the library
// (This matches the library’s expected "keyset" usage.)
const privateKey = await JoseKey.fromPKCS8(BSKY_OAUTH_PRIVATE_KEY_PEM, 'ES256', {
  kid: BSKY_OAUTH_KID,
});
console.log('Loaded JWK summary:', summarizeKey(privateKey.toJWK(true)));
console.log(`Private key imported. kid=${BSKY_OAUTH_KID}`);

// ---- Build OAuth client -----------------------------------------------------
// IMPORTANT: dpopStore must be a valid SimpleStore<NodeDpopKey> (with get/set/del).
// Using the official memory() store avoids the “reading 'del'” crash.  
const oauthClient = new NodeOAuthClient({
  metadata: clientMetadata,
  keyset: [privateKey],            // used for private_key_jwt and DPoP signing (ES256)
  dpopStore: NodeDpopStore.memory(), // or NodeDpopStore.sqlite('/data/dpop.sqlite')
  stateStore,                      // persists PAR/PKCE state across the redirect
  sessionStore,                    // persists user session (access/refresh JWTs)
});

console.log('Loaded client metadata summary:', {
  has_jwks: !!clientMetadata.jwks,
  has_jwks_uri: !!clientMetadata.jwks_uri,
  token_auth_method: clientMetadata.token_endpoint_auth_method,
  signing_alg: clientMetadata.token_endpoint_auth_signing_alg,
});

// ---- Helpers to fetch current session & agent -------------------------------
async function getCurrentSub() {
  const r = await pool.query('select sub from oauth_current where id=1');
  return r.rows[0]?.sub;
}

async function getAgent() {
  const sub = await getCurrentSub();
  if (!sub) {
    throw new Error('No OAuth session found. Visit /auth/start first.');
  }
  const sess = await sessionStore.get(sub);
  if (!sess) {
    throw new Error('OAuth session expired/cleared. Visit /auth/start to reconnect.');
  }
  // NodeOAuthClient constructs an agent on-demand from stored session
  return oauthClient.getAgent({ sub });
}

// ---- Routes -----------------------------------------------------------------

// Health
app.get('/health', (_req, res) => res.type('text/plain').send('ok'));

// Begin OAuth (expects ?handle=@yourname.bsky.social, though it’s optional)
app.get('/auth/start', async (req, res) => {
  try {
    const handle = (req.query.handle || '').toString().trim();
    const url = await oauthClient.authorize({
      // If you pass a handle, the server may use it as login hint.
      handle: handle || undefined,
      // Use the first (https) redirect URI from your client metadata
      redirectUri: clientMetadata.redirect_uris[0],
      // Bluesky scope is "atproto"
      scope: 'atproto',
    });
    return res.redirect(url);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'failed to start auth' });
  }
});

// OAuth callback (the redirect_uri you registered)
app.get('/oauth/callback', async (req, res) => {
  try {
    // Reconstruct full URL for the library so it can read code/state/iss
    const fullUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
    const { sub } = await oauthClient.callback(fullUrl); // stores session via sessionStore.set(sub, ...)
    // Mark this as the active session for our single-user app
    await pool.query(
      `insert into oauth_current(id,sub) values (1,$1)
       on conflict(id) do update set sub=excluded.sub`,
      [sub]
    );
    return res.type('text/plain').send('OAuth complete. You can close this window.');
  } catch (err) {
    console.error(err);
    return res.status(400).json({ error: 'oauth callback failed' });
  }
});

// Clear current session (manual logout/reset)
app.post('/auth/logout', async (_req, res) => {
  try {
    const sub = await getCurrentSub();
    if (sub) await sessionStore.del(sub);
    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'logout failed' });
  }
});

// Debug – shows whether we have a session in DB
app.get('/session/debug', async (_req, res) => {
  const sub = await getCurrentSub();
  if (!sub) return res.json({ haveSession: false });
  const row = await sessionStore.get(sub);
  return res.json({ haveSession: !!row, row: row ? { sub, updated_at: new Date().toISOString() } : null });
});

// Example protected action (post a plain note)
app.post('/post/test', express.json(), async (req, res) => {
  try {
    const agent = await getAgent();
    const text = (req.body?.text || 'Hello from OAuth client').toString();
    const r = await agent.post({
      $type: 'app.bsky.feed.post',
      text,
      createdAt: new Date().toISOString(),
    });
    return res.json({ ok: true, uri: r?.uri });
  } catch (err) {
    console.error(err);
    return res.status(401).json({ error: 'post failed' });
  }
});

app.listen(PORT, () => {
  console.log(`web listening on :${PORT}`);
});

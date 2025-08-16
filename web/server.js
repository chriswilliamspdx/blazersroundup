import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import { Pool } from 'pg';
import { NodeOAuthClient } from '@atproto/oauth-client-node';
import { JoseKey } from '@atproto/jwk-jose';
import { Agent } from '@atproto/api';

const {
  DATABASE_URL,
  CLIENT_METADATA_URL,
  BSKY_OAUTH_PRIVATE_KEY_JWK, // preferred: private EC/P-256 JWK (contains "d")
  BSKY_OAUTH_PRIVATE_KEY_PEM, // optional fallback: PKCS8 private key
  BSKY_OAUTH_KID,             // optional override if your JWK has no kid
  INTERNAL_API_TOKEN,
  BSKY_EXPECTED_HANDLE,       // optional: safety check
  PORT = 8080
} = process.env;

function die(msg) { console.error(msg); process.exit(1); }

if (!DATABASE_URL || !CLIENT_METADATA_URL || !INTERNAL_API_TOKEN) {
  die('Missing required env vars: DATABASE_URL, CLIENT_METADATA_URL, INTERNAL_API_TOKEN.');
}

// ---- Postgres ----
const pool = new Pool({ connectionString: DATABASE_URL, max: 5 });

async function ensureSchema() {
  // Store session only by OAuth subject (sub)
  const sql = `
  create table if not exists oauth_sessions_v2 (
    sub text primary key,
    session_json jsonb not null,
    updated_at timestamptz default now()
  );

  create table if not exists oauth_state (
    k text primary key,
    v jsonb not null,
    created_at timestamptz default now()
  );
  `;
  await pool.query(sql);
}
await ensureSchema();

// ---- Load PRIVATE signing key (must be EC/P-256) ----
let keyImportable = null;
let jwkKid = null;

if (BSKY_OAUTH_PRIVATE_KEY_JWK && BSKY_OAUTH_PRIVATE_KEY_JWK.trim()) {
  let jwk;
  try {
    jwk = JSON.parse(BSKY_OAUTH_PRIVATE_KEY_JWK);
  } catch {
    die('BSKY_OAUTH_PRIVATE_KEY_JWK is not valid JSON.');
  }
  if (jwk && typeof jwk === 'object' && Array.isArray(jwk.keys)) {
    console.warn('Looks like a JWKS; taking keys[0].');
    jwk = jwk.keys[0];
  }
  console.log('Loaded JWK summary:', {
    type: typeof jwk, kty: jwk?.kty, crv: jwk?.crv, has_d: !!jwk?.d, kid_type: typeof jwk?.kid
  });
  if (!jwk || typeof jwk !== 'object') die('Private JWK must be a JSON object.');
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    die(`Private JWK must be EC/P-256 for ES256. Got kty=${jwk.kty}, crv=${jwk.crv}.`);
  }
  if (!jwk.d) die('Private JWK is missing "d" — that means you pasted a PUBLIC key.');
  if (typeof jwk.kid === 'string') jwkKid = jwk.kid;
  else if (BSKY_OAUTH_KID) { jwk.kid = BSKY_OAUTH_KID; jwkKid = BSKY_OAUTH_KID; }
  keyImportable = jwk;
} else if (BSKY_OAUTH_PRIVATE_KEY_PEM && BSKY_OAUTH_PRIVATE_KEY_PEM.trim()) {
  const pem = BSKY_OAUTH_PRIVATE_KEY_PEM.replace(/\r\n/g, '\n').replace(/\\n/g, '\n').trim();
  if (!pem.includes('-----BEGIN PRIVATE KEY-----')) {
    die('BSKY_OAUTH_PRIVATE_KEY_PEM must be PKCS8 (BEGIN/END PRIVATE KEY).');
  }
  console.log('Loaded PEM (PKCS8).');
  keyImportable = pem;
} else {
  die('Provide BSKY_OAUTH_PRIVATE_KEY_JWK (recommended) or BSKY_OAUTH_PRIVATE_KEY_PEM.');
}

const keyset = [ await JoseKey.fromImportable(keyImportable) ];
console.log(`Private key imported. kid=${jwkKid ?? BSKY_OAUTH_KID ?? '(none)'}`);

// ---- Fetch and validate client metadata JSON ----
let clientMetadata;
try {
  const resp = await fetch(CLIENT_METADATA_URL, { redirect: 'follow' });
  if (!resp.ok) die(`Failed to fetch CLIENT_METADATA_URL (${resp.status} ${resp.statusText})`);
  clientMetadata = await resp.json();
} catch (e) {
  console.error(e);
  die('Could not load CLIENT_METADATA_URL JSON.');
}

if (!clientMetadata || typeof clientMetadata !== 'object') die('client metadata JSON is not an object.');
if (!clientMetadata.client_id) die('client metadata missing client_id.');
if (!clientMetadata.jwks && !clientMetadata.jwks_uri) die('client metadata must include jwks or jwks_uri.');
console.log('Loaded client metadata summary:', {
  has_jwks: !!clientMetadata.jwks,
  has_jwks_uri: !!clientMetadata.jwks_uri,
  token_auth_method: clientMetadata.token_endpoint_auth_method,
  signing_alg: clientMetadata.token_endpoint_auth_signing_alg,
});

// ---- Build OAuth client (Node runtime) ----
const oauth = new NodeOAuthClient({
  responseMode: 'query',
  clientMetadata,
  keyset,
  stateStore: {
    async set(k, v){
      await pool.query(
        'insert into oauth_state(k,v) values($1,$2) on conflict (k) do update set v=excluded.v, created_at=now()',
        [k, v]
      );
    },
    async get(k){
      const {rows} = await pool.query('select v from oauth_state where k=$1',[k]);
      return rows[0]?.v;
    },
    async del(k){
      await pool.query('delete from oauth_state where k=$1',[k]);
    },
  },
  sessionStore: {
    // Store raw session by subject (sub). No assumptions about fields inside.
    async set(sub, session){
      await pool.query(
        `insert into oauth_sessions_v2(sub, session_json, updated_at)
         values($1, $2, now())
         on conflict (sub) do update set session_json=excluded.session_json, updated_at=now()`,
        [sub, session]
      );
    },
    async get(sub){
      const {rows} = await pool.query('select session_json from oauth_sessions_v2 where sub=$1',[sub]);
      return rows[0]?.session_json;
    },
    async del(sub){
      await pool.query('delete from oauth_sessions_v2 where sub=$1',[sub]);
    },
  },
});

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Home
app.get('/', async (_req, res) => {
  const { rows } = await pool.query('select sub, updated_at from oauth_sessions_v2 limit 1');
  const status = rows[0] ? `Connected (sub ${rows[0].sub})` : 'Not connected';
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(`<h1>Blazers Roundup Bot</h1><p>${status}</p>
    <p><a href="/auth/start?handle=${encodeURIComponent(BSKY_EXPECTED_HANDLE ? BSKY_EXPECTED_HANDLE.replace(/^@/, '') : 'blazersroundup.bsky.social')}">Sign in with Bluesky</a></p>`);
});

// Start OAuth (handle WITHOUT "@")
app.get('/auth/start', async (req, res) => {
  try {
    const handle = (req.query.handle?.toString() || 'blazersroundup.bsky.social').replace(/^@/, '');
    const url = await oauth.authorize(handle, { scope: 'atproto' });
    res.redirect(url);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to start auth');
  }
});

// Callback
app.get('/oauth/callback', async (req, res) => {
  try {
    const result = await oauth.callback(new URLSearchParams(req.url.split('?')[1] ?? ''));
    if (BSKY_EXPECTED_HANDLE && result.session?.handle && result.session.handle !== BSKY_EXPECTED_HANDLE) {
      return res.status(400).send('Unexpected handle');
    }
    res.send('OAuth complete. You can close this window.');
  } catch (e) {
    console.error(e);
    res.status(500).send('OAuth callback failed.');
  }
});

// --- Build a logged-in Agent from stored OAuth session ---
async function getAgent() {
  const { rows } = await pool.query('select session_json from oauth_sessions_v2 limit 1');
  if (!rows[0]) throw new Error('No OAuth session found. Visit /auth/start first.');
  const s = rows[0].session_json || {};

  // Determine service origin (PDS) from session, fallback to bsky.social
  let service = 'https://bsky.social';
  if (s.pdsUrl) {
    try { service = new URL(s.pdsUrl).origin; } catch {}
  }

  if (!s.accessJwt || !s.refreshJwt || !s.did) {
    throw new Error('OAuth session missing accessJwt/refreshJwt/did');
  }

  const agent = new Agent({ service });

  // Prefer resumeSession if present; otherwise setSession; final fallback sets property.
  const atpSession = {
    accessJwt: s.accessJwt,
    refreshJwt: s.refreshJwt,
    did: s.did,
    handle: s.handle ?? undefined,
  };

  if (typeof agent.resumeSession === 'function') {
    const ok = await agent.resumeSession(atpSession);
    if (!ok) throw new Error('resumeSession returned false');
  } else if (typeof agent.setSession === 'function') {
    agent.setSession(atpSession);
  } else {
    // very old versions fallback (should not be needed)
    agent.session = atpSession;
  }

  return agent;
}

const linkFacets = (text) => {
  const spans = [];
  const re = /https?:\/\/\S+/g;
  let m;
  while ((m = re.exec(text))) spans.push({ start: m.index, end: m.index + m[0].length, url: m[0] });
  return spans.map((s) => ({
    index: {
      byteStart: Buffer.byteLength(text.slice(0, s.start), 'utf8'),
      byteEnd: Buffer.byteLength(text.slice(0, s.end), 'utf8'),
    },
    features: [{ $type: 'app.bsky.richtext.facet#link', uri: s.url }],
  }));
};

app.post('/post-thread', async (req, res) => {
  try {
    // Auth header must match our internal token
    const token = req.headers['x-internal-token'];
    if (token !== INTERNAL_API_TOKEN) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    const { firstText, secondText } = req.body;
    if (!firstText || !secondText) return res.status(400).json({ error: 'firstText and secondText required' });

    const agent = await getAgent();
    const createdAt = new Date().toISOString();

    const first = await agent.post({ text: firstText, facets: linkFacets(firstText), createdAt });
    const reply = await agent.post({
      text: secondText,
      facets: linkFacets(secondText),
      createdAt: new Date().toISOString(),
      reply: { root: { uri: first.uri, cid: first.cid }, parent: { uri: first.uri, cid: first.cid } },
    });

    res.json({ ok: true, first, reply });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'post failed' });
  }
});

app.listen(PORT, () => console.log(`web listening on :${PORT}`));


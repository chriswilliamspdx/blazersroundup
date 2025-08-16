// web/server.js — FULL FILE (paste everything)

// Imports
import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import { Pool } from 'pg';
import { NodeOAuthClient } from '@atproto/oauth-client-node';
import { JoseKey } from '@atproto/jwk-jose';
import { Agent } from '@atproto/api';

// Env
const {
  DATABASE_URL,
  CLIENT_METADATA_URL,          // e.g. https://chriswilliamspdx.github.io/blazersroundup/bsky-client.json
  BSKY_OAUTH_PRIVATE_KEY_JWK,   // private EC/P-256 JWK (with "d") OR:
  BSKY_OAUTH_PRIVATE_KEY_PEM,   // PKCS8 private key (BEGIN/END PRIVATE KEY)
  BSKY_OAUTH_KID,               // optional kid override if your JWK has no kid
  INTERNAL_API_TOKEN,           // shared secret for protected endpoints
  BSKY_EXPECTED_HANDLE,         // optional safety check, e.g. @blazersroundup.bsky.social
  PORT = 8080,
} = process.env;

// Helpers
function die(msg) {
  console.error(msg);
  process.exit(1);
}

// Basic env checks
if (!DATABASE_URL || !CLIENT_METADATA_URL || !INTERNAL_API_TOKEN) {
  die('Missing required env vars: DATABASE_URL, CLIENT_METADATA_URL, INTERNAL_API_TOKEN.');
}

// Postgres
const pool = new Pool({ connectionString: DATABASE_URL, max: 5 });

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS oauth_sessions (
      sub          text PRIMARY KEY,
      session_json jsonb NOT NULL,
      created_at   timestamptz DEFAULT now(),
      updated_at   timestamptz DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS oauth_state (
      k text PRIMARY KEY,
      v jsonb NOT NULL,
      created_at timestamptz DEFAULT now()
    );
  `);
}
await ensureSchema();

// === PRIVATE KEY LOADING (must be EC/P-256) ===
let keyImportable = null;
let jwkKid = null;

if (BSKY_OAUTH_PRIVATE_KEY_JWK && BSKY_OAUTH_PRIVATE_KEY_JWK.trim()) {
  let jwk;
  try {
    jwk = JSON.parse(BSKY_OAUTH_PRIVATE_KEY_JWK);
  } catch {
    die('BSKY_OAUTH_PRIVATE_KEY_JWK is not valid JSON.');
  }

  // If a JWKS was pasted, use the first key
  if (jwk && typeof jwk === 'object' && Array.isArray(jwk.keys)) {
    console.warn('Detected JWKS; using keys[0].');
    jwk = jwk.keys[0];
  }

  console.log('Loaded JWK summary:', {
    type: typeof jwk,
    kty: jwk?.kty,
    crv: jwk?.crv,
    has_d: !!jwk?.d,
    kid_type: typeof jwk?.kid,
  });

  if (!jwk || typeof jwk !== 'object') die('Private JWK must be a JSON object.');
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') die(`Private JWK must be EC/P-256. Got kty=${jwk.kty}, crv=${jwk.crv}.`);
  if (!jwk.d) die('Private JWK is missing "d" — you pasted a PUBLIC key.');
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
  die('Provide BSKY_OAUTH_PRIVATE_KEY_JWK (preferred) or BSKY_OAUTH_PRIVATE_KEY_PEM.');
}

const keyset = [await JoseKey.fromImportable(keyImportable)];
console.log(`Private key imported. kid=${jwkKid ?? BSKY_OAUTH_KID ?? '(none)'}\n`);

// === CLIENT METADATA ===
let clientMetadata;
try {
  const r = await fetch(CLIENT_METADATA_URL, { redirect: 'follow' });
  if (!r.ok) die(`Failed to fetch CLIENT_METADATA_URL (${r.status} ${r.statusText})`);
  clientMetadata = await r.json();
} catch (e) {
  console.error(e);
  die('Could not load CLIENT_METADATA_URL JSON.');
}

if (!clientMetadata || typeof clientMetadata !== 'object') die('client metadata is not an object.');
if (!clientMetadata.client_id) die('client metadata missing client_id.');
if (!clientMetadata.jwks && !clientMetadata.jwks_uri) die('client metadata must include jwks or jwks_uri.');

console.log('Loaded client metadata summary:', {
  has_jwks: !!clientMetadata.jwks,
  has_jwks_uri: !!clientMetadata.jwks_uri,
  token_auth_method: clientMetadata.token_endpoint_auth_method,
  signing_alg: clientMetadata.token_endpoint_auth_signing_alg,
});

// === OAUTH CLIENT ===
const oauth = new NodeOAuthClient({
  responseMode: 'query',
  clientMetadata,
  keyset,
  stateStore: {
    async set(k, v) {
      await pool.query(
        `INSERT INTO oauth_state(k, v) VALUES ($1,$2)
         ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v, created_at=now()`,
        [k, v],
      );
    },
    async get(k) {
      const { rows } = await pool.query('SELECT v FROM oauth_state WHERE k=$1', [k]);
      return rows[0]?.v;
    },
    async del(k) {
      await pool.query('DELETE FROM oauth_state WHERE k=$1', [k]);
    },
  },
  sessionStore: {
    async set(sub, session) {
      await pool.query(
        `INSERT INTO oauth_sessions(sub, session_json, created_at, updated_at)
         VALUES ($1,$2, now(), now())
         ON CONFLICT (sub) DO UPDATE SET session_json=EXCLUDED.session_json, updated_at=now()`,
        [sub, session],
      );
    },
    async get(sub) {
      const { rows } = await pool.query('SELECT session_json FROM oauth_sessions WHERE sub=$1', [sub]);
      return rows[0]?.session_json;
    },
    async del(sub) {
      await pool.query('DELETE FROM oauth_sessions WHERE sub=$1', [sub]);
    },
  },
});

// === EXPRESS APP ===
const app = express();
app.use(cors());
app.use(bodyParser.json());

// Home
app.get('/', async (_req, res) => {
  const { rows } = await pool.query('SELECT sub, updated_at FROM oauth_sessions ORDER BY updated_at DESC LIMIT 1');
  const status = rows[0] ? `Connected (sub ${rows[0].sub})` : 'Not connected';
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(
    `<h1>Blazers Roundup Bot</h1><p>${status}</p>
     <p><a href="/auth/start?handle=${encodeURIComponent(
       (BSKY_EXPECTED_HANDLE || '@blazersroundup.bsky.social').replace(/^@/, ''),
     )}">Sign in with Bluesky</a></p>`,
  );
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

// OAuth callback
app.get('/oauth/callback', async (req, res) => {
  try {
    const params = new URLSearchParams(req.url.split('?')[1] ?? '');
    const { session } = await oauth.callback(params);

    // Optional: lock to expected handle
    if (BSKY_EXPECTED_HANDLE && session?.handle && session.handle !== BSKY_EXPECTED_HANDLE) {
      return res.status(400).send(`Unexpected handle: ${session.handle}`);
    }

    await pool.query(
      `INSERT INTO oauth_sessions(sub, session_json, created_at, updated_at)
       VALUES ($1,$2, now(), now())
       ON CONFLICT (sub) DO UPDATE SET session_json=EXCLUDED.session_json, updated_at=now()`,
      [session.sub, session],
    );

    res.send('OAuth complete. You can close this window.');
  } catch (e) {
    console.error(e);
    res.status(500).send('OAuth callback failed.');
  }
});

// Build an authenticated Agent from stored OAuth session
async function getAgent() {
  const { rows } = await pool.query(
    `SELECT sub, session_json
       FROM oauth_sessions
      ORDER BY updated_at DESC NULLS LAST, created_at DESC
      LIMIT 1`,
  );
  if (!rows.length) throw new Error('No OAuth session found. Visit /auth/start first.');

  const saved = rows[0];
  const sub =
    saved.sub ||
    saved.session_json?.sub ||
    saved.session_json?.session?.sub ||
    saved.session_json?.did;

  if (!sub) throw new Error('Stored OAuth session missing "sub"');

  const live = await oauth.restore(sub);

  // Determine service origin (PDS)
  let service = 'https://bsky.social';
  if (live?.pdsUrl) {
    try { service = new URL(live.pdsUrl).origin; } catch {}
  }

  const agent = new Agent({ service, auth: live });
  if (typeof agent.assertAuthenticated === 'function') agent.assertAuthenticated();
  return agent;
}

// Link facets helper
function linkFacets(text) {
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
}

// Protected: post a two-note thread
app.post('/post-thread', async (req, res) => {
  try {
    const token = req.headers['x-internal-token'];
    if (token !== INTERNAL_API_TOKEN) return res.status(401).json({ error: 'unauthorized' });

    const { firstText, secondText } = req.body || {};
    if (!firstText || !secondText) return res.status(400).json({ error: 'firstText and secondText required' });

    const agent = await getAgent();

    const createdAt = new Date().toISOString();
    const first = await agent.post({ text: firstText, facets: linkFacets(firstText), createdAt });
    const reply = await agent.post({
      text: secondText,
      facets: linkFacets(secondText),
      createdAt: new Date().toISOString(),
      reply: {
        root: { uri: first.uri, cid: first.cid },
        parent: { uri: first.uri, cid: first.cid },
      },
    });

    res.json({ ok: true, first, reply });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'post failed' });
  }
});

// Debug: show whether we have a session
app.get('/session/debug', async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT sub, (session_json->>'handle') AS handle, updated_at
       FROM oauth_sessions
      ORDER BY updated_at DESC
      LIMIT 1`,
  );
  res.json({ haveSession: !!rows[0], row: rows[0] ?? null });
});

// --- ONE-TIME DB MIGRATION (protected) ---
// Call with header: x-internal-token: <INTERNAL_API_TOKEN>
app.post('/admin/migrate', async (req, res) => {
  try {
    const token = req.headers['x-internal-token'];
    if (token !== INTERNAL_API_TOKEN) return res.status(401).json({ error: 'unauthorized' });

    await pool.query(`
      CREATE TABLE IF NOT EXISTS oauth_sessions (
        sub          text,
        session_json jsonb,
        created_at   timestamptz DEFAULT now(),
        updated_at   timestamptz DEFAULT now()
      );

      ALTER TABLE oauth_sessions ADD COLUMN IF NOT EXISTS sub          text;
      ALTER TABLE oauth_sessions ADD COLUMN IF NOT EXISTS session_json jsonb;
      ALTER TABLE oauth_sessions ADD COLUMN IF NOT EXISTS created_at   timestamptz DEFAULT now();
      ALTER TABLE oauth_sessions ADD COLUMN IF NOT EXISTS updated_at   timestamptz DEFAULT now();

      UPDATE oauth_sessions
         SET sub = COALESCE(sub, session_json->>'sub', session_json->>'did', sub)
       WHERE sub IS NULL;

      CREATE UNIQUE INDEX IF NOT EXISTS oauth_sessions_sub_unique ON oauth_sessions(sub);

      CREATE TABLE IF NOT EXISTS oauth_state (
        k text PRIMARY KEY,
        v jsonb NOT NULL,
        created_at timestamptz DEFAULT now()
      );
    `);

    res.json({ ok: true, message: 'migration complete' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

// Start server
app.listen(PORT, () => console.log(`web listening on :${PORT}`));


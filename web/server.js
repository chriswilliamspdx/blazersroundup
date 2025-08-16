// web/server.js — FULL FILE (replace everything)

import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import { Pool } from 'pg';
import { NodeOAuthClient } from '@atproto/oauth-client-node';
import { JoseKey } from '@atproto/jwk-jose';
import { Agent } from '@atproto/api';

const {
  DATABASE_URL,
  CLIENT_METADATA_URL,          // e.g. https://chriswilliamspdx.github.io/blazersroundup/bsky-client.json
  BSKY_OAUTH_PRIVATE_KEY_JWK,   // preferred: EC/P-256 private JWK (must include "d")
  BSKY_OAUTH_PRIVATE_KEY_PEM,   // alternative: PKCS8 private key PEM
  BSKY_OAUTH_KID,               // optional kid override if your JWK has no kid
  INTERNAL_API_TOKEN,           // required for admin + post routes
  BSKY_EXPECTED_HANDLE,         // optional, sanity check
  PORT = 8080,
} = process.env;

function die(msg) {
  console.error(msg);
  process.exit(1);
}

if (!DATABASE_URL || !CLIENT_METADATA_URL || !INTERNAL_API_TOKEN) {
  die('Missing required env vars: DATABASE_URL, CLIENT_METADATA_URL, INTERNAL_API_TOKEN.');
}

const pool = new Pool({ connectionString: DATABASE_URL, max: 5 });

// Minimal schema we expect
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

// ------- Load private key (MUST be EC/P-256) -------
let keyImportable = null;
let jwkKid = null;

if (BSKY_OAUTH_PRIVATE_KEY_JWK && BSKY_OAUTH_PRIVATE_KEY_JWK.trim()) {
  let jwk;
  try {
    jwk = JSON.parse(BSKY_OAUTH_PRIVATE_KEY_JWK);
  } catch {
    die('BSKY_OAUTH_PRIVATE_KEY_JWK is not valid JSON.');
  }
  if (Array.isArray(jwk?.keys)) {
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
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    die(`Private JWK must be EC/P-256. Got kty=${jwk.kty}, crv=${jwk.crv}.`);
  }
  if (!jwk.d) die('Private JWK missing "d" (this looks like a PUBLIC key).');
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

// ------- Load client metadata -------
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

// ------- OAuth client -------
const oauth = new NodeOAuthClient({
  responseMode: 'query',
  clientMetadata,
  keyset,
  stateStore: {
    async set(k, v) {
      await pool.query(
        `INSERT INTO oauth_state(k, v)
         VALUES ($1,$2)
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
      // Ensure table shape then upsert
      await ensureSchema();
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

// ------- Web app -------
const app = express();
app.use(cors());
app.use(bodyParser.json());

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

// Start OAuth
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

// ---------- Helpers ----------
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

  let live;
  try {
    // This can throw TokenRefreshError if the row vanished mid-refresh
    live = await oauth.restore(sub);
  } catch (e) {
    const msg = String(e?.message || '');
    if (e?.name === 'TokenRefreshError' || /deleted by another process/i.test(msg)) {
      // Defensive: purge any partial row and ask user to re-auth
      await pool.query('DELETE FROM oauth_sessions WHERE sub=$1', [sub]);
      throw new Error('OAuth session expired/cleared. Visit /auth/start to reconnect.');
    }
    throw e;
  }

  let service = 'https://bsky.social';
  if (live?.pdsUrl) {
    try { service = new URL(live.pdsUrl).origin; } catch {}
  }
  const agent = new Agent({ service, auth: live });
  if (typeof agent.assertAuthenticated === 'function') agent.assertAuthenticated();
  return agent;
}

// ---------- Protected endpoints ----------

// post a two-message thread
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
    const msg = /OAuth session expired\/cleared/.test(String(e)) ? 'reauth required' : 'post failed';
    res.status(500).json({ error: msg });
  }
});

// ---------- Debug & Admin ----------

app.get('/session/debug', async (_req, res) => {
  const { rows } = await pool.query(
    `SELECT sub, (session_json->>'handle') AS handle, updated_at
       FROM oauth_sessions
      ORDER BY updated_at DESC
      LIMIT 1`,
  );
  res.json({ haveSession: !!rows[0], row: rows[0] ?? null });
});

// Hard migrate legacy columns (kept from previous step)
app.post('/admin/migrate-hard', async (req, res) => {
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

      UPDATE oauth_sessions
         SET sub = COALESCE(sub, session_json->>'sub', session_json->>'did', sub)
       WHERE sub IS NULL;

      ALTER TABLE oauth_sessions DROP COLUMN IF EXISTS issuer;
      ALTER TABLE oauth_sessions DROP COLUMN IF EXISTS did;
      ALTER TABLE oauth_sessions DROP COLUMN IF EXISTS access_jwt;
      ALTER TABLE oauth_sessions DROP COLUMN IF EXISTS refresh_jwt;
      ALTER TABLE oauth_sessions DROP COLUMN IF EXISTS handle;
      ALTER TABLE oauth_sessions DROP COLUMN IF EXISTS audience;
      ALTER TABLE oauth_sessions DROP COLUMN IF EXISTS scope;
      ALTER TABLE oauth_sessions DROP COLUMN IF EXISTS expires_at;
      ALTER TABLE oauth_sessions DROP COLUMN IF EXISTS pds_url;

      DELETE FROM oauth_sessions WHERE sub IS NULL;

      CREATE TABLE IF NOT EXISTS oauth_sessions__clean (
        sub          text PRIMARY KEY,
        session_json jsonb NOT NULL,
        created_at   timestamptz DEFAULT now(),
        updated_at   timestamptz DEFAULT now()
      );

      INSERT INTO oauth_sessions__clean (sub, session_json, created_at, updated_at)
      SELECT sub, COALESCE(session_json, '{}'::jsonb), COALESCE(created_at, now()), COALESCE(updated_at, now())
      FROM oauth_sessions
      ON CONFLICT (sub) DO UPDATE SET
        session_json = EXCLUDED.session_json,
        updated_at   = now();

      DROP TABLE oauth_sessions;
      ALTER TABLE oauth_sessions__clean RENAME TO oauth_sessions;

      CREATE UNIQUE INDEX IF NOT EXISTS oauth_sessions_sub_unique ON oauth_sessions(sub);

      CREATE TABLE IF NOT EXISTS oauth_state (
        k text PRIMARY KEY,
        v jsonb NOT NULL,
        created_at timestamptz DEFAULT now()
      );
    `);

    res.json({ ok: true, message: 'hard migration complete' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

// Clear session & state (quick fix for token refresh conflicts)
app.post('/admin/clear-session', async (req, res) => {
  try {
    const token = req.headers['x-internal-token'];
    if (token !== INTERNAL_API_TOKEN) return res.status(401).json({ error: 'unauthorized' });

    await pool.query('DELETE FROM oauth_sessions;');
    await pool.query('DELETE FROM oauth_state;');
    res.json({ ok: true, message: 'cleared oauth_sessions & oauth_state; run /auth/start again' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: String(e.message || e) });
  }
});

// Last resort: drop & recreate
app.post('/admin/reset-oauth-sessions', async (req, res) => {
  try {
    const token = req.headers['x-internal-token'];
    if (token !== INTERNAL_API_TOKEN) return res.status(401).json({ error: 'unauthorized' });

    const suffix = Math.floor(Date.now() / 1000);
    await pool.query(`
      DO $$
      BEGIN
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'oauth_sessions') THEN
          EXECUTE 'ALTER TABLE oauth_sessions RENAME TO oauth_sessions_backup_' || ${suffix};
        END IF;
      END$$;

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

      CREATE UNIQUE INDEX IF NOT EXISTS oauth_sessions_sub_unique ON oauth_sessions(sub);
    `);

    res.json({ ok: true, message: 'oauth_sessions reset; run /auth/start again' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: String(err.message || err) });
  }
});

// Start server
app.listen(PORT, () => console.log(`web listening on :${PORT}`));


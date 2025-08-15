import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import { Pool } from 'pg';
// oauth-client is CJS → import default and destructure
import oauthPkg from '@atproto/oauth-client';
const { OAuthClient } = oauthPkg;

import { JoseKey } from '@atproto/jwk-jose';
import { Agent } from '@atproto/api';

const {
  DATABASE_URL,
  CLIENT_METADATA_URL,
  BSKY_OAUTH_PRIVATE_KEY_PEM,
  BSKY_OAUTH_KID,
  INTERNAL_API_TOKEN,
  BSKY_EXPECTED_HANDLE,
  PORT = 8080,
} = process.env;

function die(msg) {
  console.error(msg);
  process.exit(1);
}

if (!DATABASE_URL || !CLIENT_METADATA_URL || !BSKY_OAUTH_PRIVATE_KEY_PEM || !BSKY_OAUTH_KID || !INTERNAL_API_TOKEN) {
  die('Missing required env vars.');
}

const pool = new Pool({ connectionString: DATABASE_URL, max: 5 });

async function ensureSchema() {
  const sql = `
  create table if not exists oauth_sessions (
    did text primary key,
    handle text not null,
    issuer text not null,
    pds_url text not null,
    session_json jsonb not null,
    updated_at timestamptz default now()
  );

  create table if not exists oauth_state (
    k text primary key,
    v jsonb not null,
    created_at timestamptz default now()
  );`;
  await pool.query(sql);
}
await ensureSchema();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// --- Stores for @atproto/oauth-client ---
const stateStore = {
  async set(key, internalState) {
    await pool.query(
      'insert into oauth_state(k, v) values ($1, $2) on conflict (k) do update set v=excluded.v, created_at=now()',
      [key, internalState],
    );
  },
  async get(key) {
    const { rows } = await pool.query('select v from oauth_state where k=$1', [key]);
    return rows[0]?.v;
  },
  async del(key) {
    await pool.query('delete from oauth_state where k=$1', [key]);
  },
};

const sessionStore = {
  async set(sub, session) {
    const { did, handle, issuer, pdsUrl } = session;
    await pool.query(
      `insert into oauth_sessions(did, handle, issuer, pds_url, session_json, updated_at)
       values($1,$2,$3,$4,$5, now())
       on conflict (did) do update set handle=excluded.handle, issuer=excluded.issuer, pds_url=excluded.pds_url, session_json=excluded.session_json, updated_at=now()`,
      [did, handle, issuer, pdsUrl, session],
    );
  },
  async get(sub) {
    const { rows } = await pool.query('select session_json from oauth_sessions where did=$1', [sub]);
    return rows[0]?.session_json;
  },
  async del(sub) {
    await pool.query('delete from oauth_sessions where did=$1', [sub]);
  },
};

// Normalize PEM: support both real newlines and literal "\n"
const PEM_CLEAN = BSKY_OAUTH_PRIVATE_KEY_PEM
  .replace(/\r\n/g, '\n')
  .replace(/\\n/g, '\n')
  .trim();

if (!PEM_CLEAN.includes('-----BEGIN PRIVATE KEY-----') || !PEM_CLEAN.includes('-----END PRIVATE KEY-----')) {
  die('BSKY_OAUTH_PRIVATE_KEY_PEM does not look like a PKCS8 PEM. Make sure it begins with "-----BEGIN PRIVATE KEY-----" and ends with "-----END PRIVATE KEY-----".');
}

const keyset = [
  await JoseKey.fromImportable(PEM_CLEAN, { kid: BSKY_OAUTH_KID }),
];

const oauth = new OAuthClient({
  responseMode: 'query',
  clientMetadata: {
    client_id: CLIENT_METADATA_URL,
    jwks_uri: CLIENT_METADATA_URL.replace(/bsky-client\.json$/, 'jwks.json'),
  },
  keyset,
  stateStore,
  sessionStore,
});

// Simple home
app.get('/', async (_req, res) => {
  const { rows } = await pool.query('select did, handle, updated_at from oauth_sessions limit 1');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  const row = rows[0];
  const status = row ? `Connected as <b>${row.handle}</b> (DID ${row.did})` : 'Not connected';
  res.end(`<h1>Blazers Roundup Bot</h1><p>${status}</p>
    <p><a href="/auth/start?handle=${encodeURIComponent(BSKY_EXPECTED_HANDLE ?? '')}">Sign in with Bluesky</a></p>`);
});

// Start OAuth
app.get('/auth/start', async (req, res) => {
  const handle = req.query.handle?.toString();
  try {
    const url = await oauth.authorize(handle ?? '', { scope: 'atproto' });
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
    if (BSKY_EXPECTED_HANDLE && result.session.handle !== BSKY_EXPECTED_HANDLE) {
      return res.status(400).send('Unexpected handle');
    }
    res.send('OAuth complete. You can close this window.');
  } catch (e) {
    console.error(e);
    res.status(500).send('OAuth callback failed.');
  }
});

// Internal helper: get agent from stored OAuth session
async function getAgent() {
  const { rows } = await pool.query('select session_json from oauth_sessions limit 1');
  if (!rows[0]) throw new Error('No OAuth session found. Visit /auth/start');
  const session = rows[0].session_json;
  return new Agent(session);
}

// POST /post-thread  { firstText, secondText }
app.post('/post-thread', async (req, res) => {
  try {
    if (req.headers['x-internal-token'] !== INTERNAL_API_TOKEN) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    const { firstText, secondText } = req.body;
    if (!firstText || !secondText) {
      return res.status(400).json({ error: 'firstText and secondText required' });
    }
    const agent = await getAgent();

    // Build link facets
    const parseUrls = (text) => {
      const spans = [];
      const urlRe = /https?:\/\/[^\s]+/g;
      let m;
      while ((m = urlRe.exec(text)) !== null) {
        spans.push({ start: m.index, end: m.index + m[0].length, url: m[0] });
      }
      return spans;
    };
    const makeFacets = (text) => {
      const spans = parseUrls(text);
      return spans.map((s) => ({
        index: {
          byteStart: Buffer.byteLength(text.slice(0, s.start), 'utf8'),
          byteEnd: Buffer.byteLength(text.slice(0, s.end), 'utf8'),
        },
        features: [{ $type: 'app.bsky.richtext.facet#link', uri: s.url }],
      }));
    };

    const createdAt = new Date().toISOString();

    const first = await agent.post({
      text: firstText,
      facets: makeFacets(firstText),
      createdAt,
    });

    const reply = await agent.post({
      text: secondText,
      facets: makeFacets(secondText),
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

app.listen(PORT, () => console.log(`web listening on :${PORT}`));

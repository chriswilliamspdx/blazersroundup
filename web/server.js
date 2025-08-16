import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import { Pool } from 'pg';
import oauthPkg from '@atproto/oauth-client';
const { OAuthClient } = oauthPkg;

import { JoseKey } from '@atproto/jwk-jose';
import { Agent } from '@atproto/api';

const {
  DATABASE_URL,
  CLIENT_METADATA_URL,
  // Prefer private JWK; fall back to PEM
  BSKY_OAUTH_PRIVATE_KEY_JWK,
  BSKY_OAUTH_PRIVATE_KEY_PEM,
  BSKY_OAUTH_KID,
  INTERNAL_API_TOKEN,
  BSKY_EXPECTED_HANDLE,
  PORT = 8080,
} = process.env;

function die(msg) { console.error(msg); process.exit(1); }

if (!DATABASE_URL || !CLIENT_METADATA_URL || !BSKY_OAUTH_KID || !INTERNAL_API_TOKEN) {
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

// ---- Load private key (JWK preferred), with clear diagnostics ----
let keyImportable = null;
let keySource = 'none';

if (BSKY_OAUTH_PRIVATE_KEY_JWK && BSKY_OAUTH_PRIVATE_KEY_JWK.trim()) {
  keySource = 'JWK';
  let jwk;
  try {
    jwk = JSON.parse(BSKY_OAUTH_PRIVATE_KEY_JWK);
  } catch {
    die('BSKY_OAUTH_PRIVATE_KEY_JWK is not valid JSON. Paste the **PRIVATE JWK (JSON)** printed by the generator (not the public JWKS).');
  }
  // If someone pasted a JWKS, unwrap the first key
  if (jwk && typeof jwk === 'object' && Array.isArray(jwk.keys)) {
    console.warn('BSKY_OAUTH_PRIVATE_KEY_JWK looks like a JWKS set; using keys[0].');
    jwk = jwk.keys[0];
  }
  // Show a safe summary of what we received
  const summary = {
    type: typeof jwk,
    kty: jwk?.kty,
    crv: jwk?.crv,
    has_d: !!jwk?.d,
    kid_type: typeof jwk?.kid,
  };
  console.log('Loaded JWK summary:', summary);

  if (!jwk || typeof jwk !== 'object') die('Private JWK must be a JSON object.');
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
    die(`Private JWK must be OKP/Ed25519. Got kty=${jwk.kty}, crv=${jwk.crv}. Did you paste the public JWKS or an EC key by mistake?`);
  }
  if (!jwk.d) die('Private JWK is missing "d" (that means you pasted a **public** key; paste the PRIVATE JWK).');
  if (typeof jwk.kid !== 'string') {
    console.warn('Private JWK "kid" is not a string; setting it from BSKY_OAUTH_KID.');
    jwk.kid = BSKY_OAUTH_KID;
  }
  if (jwk.kid !== BSKY_OAUTH_KID) {
    console.warn(`Private JWK kid (${jwk.kid}) != env BSKY_OAUTH_KID (${BSKY_OAUTH_KID}); using env kid.`);
    jwk.kid = BSKY_OAUTH_KID;
  }
  keyImportable = jwk;
} else if (BSKY_OAUTH_PRIVATE_KEY_PEM && BSKY_OAUTH_PRIVATE_KEY_PEM.trim()) {
  keySource = 'PEM';
  const pem = BSKY_OAUTH_PRIVATE_KEY_PEM.replace(/\r\n/g, '\n').replace(/\\n/g, '\n').trim();
  if (!pem.includes('-----BEGIN PRIVATE KEY-----') || !pem.includes('-----END PRIVATE KEY-----')) {
    die('BSKY_OAUTH_PRIVATE_KEY_PEM does not look like a PKCS8 PEM (must include BEGIN/END PRIVATE KEY).');
  }
  console.log('Loaded PEM (PKCS8).');
  keyImportable = pem;
} else {
  die('Provide either BSKY_OAUTH_PRIVATE_KEY_JWK (recommended) or BSKY_OAUTH_PRIVATE_KEY_PEM.');
}

const keyset = [ await JoseKey.fromImportable(keyImportable, { kid: BSKY_OAUTH_KID }) ];
console.log(`Private key imported from ${keySource}. kid=${BSKY_OAUTH_KID}`);

// Use full client metadata from URL
const oauth = new OAuthClient({
  responseMode: 'query',
  clientMetadataUrl: CLIENT_METADATA_URL,
  keyset,
  stateStore: {
    async set(k, v){ await pool.query('insert into oauth_state(k,v) values($1,$2) on conflict (k) do update set v=excluded.v, created_at=now()', [k,v]); },
    async get(k){ const {rows}=await pool.query('select v from oauth_state where k=$1',[k]); return rows[0]?.v; },
    async del(k){ await pool.query('delete from oauth_state where k=$1',[k]); },
  },
  sessionStore: {
    async set(sub, session){ const {did,handle,issuer,pdsUrl}=session; await pool.query(
      `insert into oauth_sessions(did,handle,issuer,pds_url,session_json,updated_at)
       values($1,$2,$3,$4,$5,now())
       on conflict (did) do update set handle=excluded.handle, issuer=excluded.issuer, pds_url=excluded.pds_url, session_json=excluded.session_json, updated_at=now()`,
      [did,handle,issuer,pdsUrl,session]); },
    async get(sub){ const {rows}=await pool.query('select session_json from oauth_sessions where did=$1',[sub]); return rows[0]?.session_json; },
    async del(sub){ await pool.query('delete from oauth_sessions where did=$1',[sub]); },
  },
});

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.get('/', async (_req, res) => {
  const { rows } = await pool.query('select did, handle, updated_at from oauth_sessions limit 1');
  const status = rows[0] ? `Connected as <b>${rows[0].handle}</b> (DID ${rows[0].did})` : 'Not connected';
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(`<h1>Blazers Roundup Bot</h1><p>${status}</p>
    <p><a href="/auth/start?handle=${encodeURIComponent(BSKY_EXPECTED_HANDLE ?? '')}">Sign in with Bluesky</a></p>`);
});

app.get('/auth/start', async (req, res) => {
  try {
    const handle = req.query.handle?.toString();
    const url = await oauth.authorize(handle ?? '', { scope: 'atproto' });
    res.redirect(url);
  } catch (e) {
    console.error(e);
    res.status(500).send('Failed to start auth');
  }
});

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

async function getAgent() {
  const { rows } = await pool.query('select session_json from oauth_sessions limit 1');
  if (!rows[0]) throw new Error('No OAuth session found. Visit /auth/start');
  return new Agent(rows[0].session_json);
}

app.post('/post-thread', async (req, res) => {
  try {
    if (req.headers['x-internal-token'] !== INTERNAL_API_TOKEN) return res.status(401).json({ error: 'unauthorized' });
    const { firstText, secondText } = req.body;
    if (!firstText || !secondText) return res.status(400).json({ error: 'firstText and secondText required' });

    const agent = await getAgent();

    const linkFacets = (text) => {
      const spans = []; const re=/https?:\/\/\S+/g; let m;
      while ((m = re.exec(text))) spans.push({ start:m.index, end:m.index+m[0].length, url:m[0] });
      return spans.map(s=>({ index:{ byteStart:Buffer.byteLength(text.slice(0,s.start),'utf8'), byteEnd:Buffer.byteLength(text.slice(0,s.end),'utf8') }, features:[{ $type:'app.bsky.richtext.facet#link', uri:s.url }] }));
    };

    const createdAt = new Date().toISOString();
    const first = await agent.post({ text:firstText, facets:linkFacets(firstText), createdAt });
    const reply = await agent.post({
      text:secondText, facets:linkFacets(secondText), createdAt:new Date().toISOString(),
      reply:{ root:{ uri:first.uri, cid:first.cid }, parent:{ uri:first.uri, cid:first.cid } }
    });
    res.json({ ok:true, first, reply });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'post failed' });
  }
});

app.listen(PORT, () => console.log(`web listening on :${PORT}`));


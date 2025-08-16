// server.js (ESM)
// Node 20+ (global fetch available)

import express from 'express'
import { Pool } from 'pg'
import { randomUUID } from 'node:crypto'
import { NodeOAuthClient } from '@atproto/oauth-client-node'
import { JoseKey } from '@atproto/jwk-jose'
import { Agent } from '@atproto/api'

// ------------------------------
// Env
// ------------------------------
const {
  PORT = 8080,
  DATABASE_URL,
  // The public URL where THIS service serves your metadata (must be HTTPS)
  // e.g. https://<your-railway-domain>/client-metadata.json
  CLIENT_METADATA_URL,

  // Private signing key (PKCS8 PEM or JWK JSON string)
  BSKY_OAUTH_PRIVATE_KEY,
  // KID you’ll advertise in jwks.json and use for client assertions
  BSKY_OAUTH_KID,

  // Optional convenience defaults
  BSKY_EXPECTED_HANDLE, // e.g. @yourhandle.bsky.social
  APP_NAME = 'Blazers Roundup Bot',
  APP_SITE = 'https://example.com',
  APP_LOGO = 'https://example.com/logo.png',
  APP_TOS = 'https://example.com/tos',
  APP_POLICY = 'https://example.com/privacy',
} = process.env

if (!DATABASE_URL) throw new Error('Missing DATABASE_URL')
if (!CLIENT_METADATA_URL) throw new Error('Missing CLIENT_METADATA_URL (must be the full https URL to /client-metadata.json)')
if (!BSKY_OAUTH_PRIVATE_KEY) throw new Error('Missing BSKY_OAUTH_PRIVATE_KEY (PKCS8 PEM or JWK)')
if (!BSKY_OAUTH_KID) throw new Error('Missing BSKY_OAUTH_KID')

// ------------------------------
// Postgres
// ------------------------------
const pg = new Pool({ connectionString: DATABASE_URL })

// Create tables if they don’t exist (minimal, flexible schema)
await pg.query(`
CREATE TABLE IF NOT EXISTS oauth_state (
  key        text PRIMARY KEY,
  value      jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS oauth_sessions (
  sub        text PRIMARY KEY,
  value      jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
`)

// ------------------------------
// Simple stores expected by the Node OAuth client (get/set/del)
// ------------------------------
// See official interface example: https://www.npmjs.com/package/@atproto/oauth-client-node
// (stateStore and sessionStore must BOTH implement get/set/del)
const stateStore = {
  async set(key, internalState) {
    await pg.query(
      `INSERT INTO oauth_state(key, value) VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
      [key, internalState],
    )
  },
  async get(key) {
    const res = await pg.query(`SELECT value FROM oauth_state WHERE key = $1`, [key])
    return res.rows[0]?.value
  },
  async del(key) {
    await pg.query(`DELETE FROM oauth_state WHERE key = $1`, [key])
  },
}

const sessionStore = {
  async set(sub, sessionData) {
    await pg.query(
      `INSERT INTO oauth_sessions(sub, value, updated_at)
       VALUES ($1, $2, now())
       ON CONFLICT (sub) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
      [sub, sessionData],
    )
  },
  async get(sub) {
    const res = await pg.query(`SELECT value FROM oauth_sessions WHERE sub = $1`, [sub])
    return res.rows[0]?.value
  },
  async del(sub) {
    await pg.query(`DELETE FROM oauth_sessions WHERE sub = $1`, [sub])
  },
}

// ------------------------------
// Import private key and prepare keyset (ES256 / P-256)
// ------------------------------
const key = await JoseKey.fromImportable(BSKY_OAUTH_PRIVATE_KEY, BSKY_OAUTH_KID)
const keyset = [key]

// ------------------------------
// Build client metadata (served at /client-metadata.json)
// This must match Bluesky OAuth requirements for a *web* app.
// ------------------------------
const redirectUri = new URL(CLIENT_METADATA_URL)
redirectUri.pathname = '/oauth/callback'

const clientMetadata = {
  // client_id MUST equal the public URL where this metadata is served:
  client_id: CLIENT_METADATA_URL,
  client_name: APP_NAME,
  client_uri: APP_SITE,
  logo_uri: APP_LOGO,
  tos_uri: APP_TOS,
  policy_uri: APP_POLICY,

  // web app + code flow + refresh tokens
  application_type: 'web',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  scope: 'atproto',
  dpop_bound_access_tokens: true,

  // OAuth client auth via private_key_jwt using ES256 (P-256)
  token_endpoint_auth_method: 'private_key_jwt',
  token_endpoint_auth_signing_alg: 'ES256',

  // Must be the exact HTTPS URL of this service’s callback
  redirect_uris: [redirectUri.toString()],

  // Public JWKS URL you control (this service)
  // The KID here must match the private key’s kid above.
  jwks_uri: new URL('/jwks.json', CLIENT_METADATA_URL).toString(),
}

// ------------------------------
// Construct the Node OAuth client
// ------------------------------
const client = new NodeOAuthClient({
  clientMetadata,
  keyset,
  stateStore,
  sessionStore,
  // requestLock is optional if you only run a single instance
})

// ------------------------------
// HTTP app
// ------------------------------
const app = express()

// Health
app.get('/', (_req, res) => res.type('text/plain').send('ok'))

// Public metadata & JWKS (the OAuth server will fetch these)
app.get('/client-metadata.json', (_req, res) => res.json(client.clientMetadata))
app.get('/jwks.json', (_req, res) => res.json(client.jwks))

// Debug: show if we have a session
app.get('/session/debug', async (_req, res) => {
  // In a real app you’d look this up by user id;
// for now, list the first stored session (if any)
  const row = await pg.query(`SELECT sub, value, updated_at FROM oauth_sessions ORDER BY updated_at DESC LIMIT 1`)
  res.json({ haveSession: !!row.rowCount, row: row.rows[0] || null })
})

// Admin: clear a session by ?sub=did:plc:xxxxx
app.post('/admin/clear-session', express.json(), async (req, res) => {
  const sub = (req.query.sub || req.body?.sub)?.toString()
  if (!sub) return res.status(400).json({ error: 'missing sub' })
  await sessionStore.del(sub)
  res.json({ ok: true })
})

// Start OAuth – GET /auth/start?handle=@yourhandle.bsky.social
app.get('/auth/start', async (req, res, next) => {
  try {
    const handle = (req.query.handle || BSKY_EXPECTED_HANDLE)?.toString()
    if (!handle) return res.status(400).send('missing ?handle')
    const state = randomUUID()

    // optional: abort if client disconnects
    const ac = new AbortController()
    req.on('close', () => ac.abort())

    const url = await client.authorize(handle, { state, signal: ac.signal })
    res.redirect(url)
  } catch (err) {
    next(err)
  }
})

// OAuth callback – Bluesky redirects here
app.get('/oauth/callback', async (req, res, next) => {
  try {
    const params = new URLSearchParams(req.url.split('?')[1] || '')
    const { session } = await client.callback(params)

    // Success — you now have a saved OAuth session in Postgres (via sessionStore).
    // Optional: immediately test an authenticated call:
    const agent = new Agent(session)
    const me = await agent.getProfile({ actor: agent.did }).catch(() => null)

    res.type('text/plain').send(
      `OAuth complete for ${session.did}\n` +
      (me ? `Profile: ${me.data.displayName || me.data.handle}\n` : ''),
    )
  } catch (err) {
    next(err)
  }
})

// Example protected action — POST /post { text }
app.post('/post', express.json(), async (req, res) => {
  // In a real app you’ll look up the caller’s DID; here we just use the latest one:
  const row = await pg.query(`SELECT sub FROM oauth_sessions ORDER BY updated_at DESC LIMIT 1`)
  if (!row.rowCount) return res.status(401).json({ error: 'reauth required' })

  const session = await client.restore(row.rows[0].sub)
  const agent = new Agent(session)

  const text = (req.body?.text || '').toString().trim()
  if (!text) return res.status(400).json({ error: 'missing text' })

  try {
    await agent.post({ text })
    res.json({ ok: true })
  } catch (e) {
    res.status(500).json({ error: 'post failed' })
  }
})

// Error handler
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error(err)
  res.status(500).json({ error: err?.message || 'server error' })
})

app.listen(PORT, () => {
  console.log(`web listening on :${PORT}`)
})

app.listen(PORT, () => {
  console.log(`web listening on :${PORT}`);
});

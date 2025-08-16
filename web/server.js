// server.js (ESM) - Bluesky OAuth + Posting API
import express from 'express'
import { Pool } from 'pg'
import { randomUUID } from 'node:crypto'
import { NodeOAuthClient } from '@atproto/oauth-client-node'
import { JoseKey } from '@atproto/jwk-jose'
import { Agent } from '@atproto/api'

// ------------------------------
// Env Variables
// ------------------------------
const {
  PORT = 8080,
  DATABASE_URL,
  CLIENT_METADATA_URL,        // Full URL to your hosted bsky-client.json
  BSKY_OAUTH_PRIVATE_KEY,     // Private key (PKCS8 PEM or JWK JSON string)
  BSKY_OAUTH_KID,             // KID for the above private key
  BSKY_EXPECTED_HANDLE,       // e.g. @yourhandle.bsky.social (optional)
  INTERNAL_API_TOKEN,         // Shared secret token for internal API calls
  APP_NAME = 'Blazers Roundup Bot',
  APP_SITE = 'https://example.com',
  APP_LOGO = 'https://example.com/logo.png',
  APP_TOS = 'https://example.com/tos',
  APP_POLICY = 'https://example.com/privacy',
} = process.env

// Required env checks
if (!DATABASE_URL) throw new Error('Missing DATABASE_URL')
if (!CLIENT_METADATA_URL) throw new Error('Missing CLIENT_METADATA_URL (URL to /bsky-client.json)')
if (!BSKY_OAUTH_PRIVATE_KEY) throw new Error('Missing BSKY_OAUTH_PRIVATE_KEY (your private key PEM or JWK)')
if (!BSKY_OAUTH_KID) throw new Error('Missing BSKY_OAUTH_KID')
if (!INTERNAL_API_TOKEN) throw new Error('Missing INTERNAL_API_TOKEN')

// ------------------------------
// Postgres Setup
// ------------------------------
const pg = new Pool({ connectionString: DATABASE_URL })
// Create tables for OAuth state and sessions (if not exist)
await pg.query(`
CREATE TABLE IF NOT EXISTS oauth_state (
  key        TEXT PRIMARY KEY,
  value      JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS oauth_sessions (
  sub        TEXT PRIMARY KEY,
  value      JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
`)

// ------------------------------
// Implement stateStore and sessionStore for NodeOAuthClient
// ------------------------------
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
// Import private key and prepare keyset (ES256 / P-256 key for client auth)
// ------------------------------
const key = await JoseKey.fromImportable(BSKY_OAUTH_PRIVATE_KEY, BSKY_OAUTH_KID)
const keyset = [key]

// ------------------------------
// Build OAuth client metadata object and NodeOAuthClient
// ------------------------------
const redirectUri = new URL(CLIENT_METADATA_URL)
redirectUri.pathname = '/oauth/callback'

const clientMetadata = {
  client_id: CLIENT_METADATA_URL,
  client_name: APP_NAME,
  client_uri: APP_SITE,
  logo_uri: APP_LOGO,
  tos_uri: APP_TOS,
  policy_uri: APP_POLICY,
  application_type: 'web',
  grant_types: ['authorization_code', 'refresh_token'],
  response_types: ['code'],
  scope: 'atproto',
  dpop_bound_access_tokens: true,
  token_endpoint_auth_method: 'private_key_jwt',
  token_endpoint_auth_signing_alg: 'ES256',
  redirect_uris: [redirectUri.toString()],
  jwks_uri: new URL('/jwks.json', CLIENT_METADATA_URL).toString(),
}

const client = new NodeOAuthClient({
  clientMetadata,
  keyset,
  stateStore,
  sessionStore,
  // (Optional: requestLock can be provided for multi-instance deployments)
})

// ------------------------------
// Express HTTP Server Setup
// ------------------------------
const app = express()

// Health check endpoint
app.get('/', (_req, res) => res.type('text/plain').send('ok'))

// Serve public client metadata and JWKS (Bluesky OAuth server will fetch these)
app.get('/client-metadata.json', (_req, res) => res.json(client.clientMetadata))
app.get('/jwks.json', (_req, res) => res.json(client.jwks))

// Debug endpoint: show if we have a session stored
app.get('/session/debug', async (_req, res) => {
  const row = await pg.query(`SELECT sub, value, updated_at FROM oauth_sessions ORDER BY updated_at DESC LIMIT 1`)
  res.json({ haveSession: row.rowCount > 0, session: row.rows[0] || null })
})

// Admin endpoint: clear a session (POST with ?sub=<did> or JSON body)
app.post('/admin/clear-session', express.json(), async (req, res) => {
  const sub = (req.query.sub || req.body?.sub || '').toString()
  if (!sub) return res.status(400).json({ error: 'missing sub' })
  await sessionStore.del(sub)
  res.json({ ok: true })
})

// Step 1 of OAuth: start authentication (redirect user to Bluesky for login)
app.get('/auth/start', async (req, res, next) => {
  try {
    const handle = (req.query.handle || BSKY_EXPECTED_HANDLE)?.toString()
    if (!handle) return res.status(400).send('missing ?handle')
    const state = randomUUID()
    // If client disconnects, abort the request to prevent hanging
    const ac = new AbortController()
    req.on('close', () => ac.abort())
    // Get the Bluesky OAuth URL and redirect user to it
    const url = await client.authorize(handle, { state, signal: ac.signal })
    return res.redirect(url)
  } catch (err) {
    return next(err)
  }
})

// Step 2 of OAuth: callback for Bluesky OAuth (handles the code exchange)
app.get('/oauth/callback', async (req, res, next) => {
  try {
    const params = new URLSearchParams(req.url.split('?')[1] || '')
    const { session } = await client.callback(params)
    // OAuth successful – session is saved in Postgres.
    const agent = new Agent(session)
    const profile = await agent.getProfile({ actor: agent.did }).catch(() => null)
    res.type('text/plain').send(
      `OAuth complete for DID: ${session.did}\n` +
      (profile ? `Logged in as: ${profile.data.handle || profile.data.displayName}\n` : '') +
      `You can close this window.`
    )
  } catch (err) {
    return next(err)
  }
})

// Protected endpoint: internal API to post a simple status update (text-only)
app.post('/post', express.json(), async (req, res) => {
  // Verify internal token
  const token = req.get('X-Internal-Token') || ''
  if (token !== INTERNAL_API_TOKEN) {
    return res.status(403).json({ error: 'forbidden' })
  }
  const text = (req.body?.text || '').toString().trim()
  if (!text) return res.status(400).json({ error: 'missing text' })
  // Get the latest OAuth session from DB
  const row = await pg.query(`SELECT sub FROM oauth_sessions ORDER BY updated_at DESC LIMIT 1`)
  if (!row.rowCount) {
    return res.status(401).json({ error: 'OAuth session not found. Visit /auth/start to connect.' })
  }
  const sub = row.rows[0].sub
  let session
  try {
    session = await client.restore(sub)  // may trigger refresh if needed
  } catch (err) {
    console.error('Restore session failed:', err)
    return res.status(401).json({ error: 'OAuth session expired or invalid. Visit /auth/start to reconnect.' })
  }
  const agent = new Agent(session)
  try {
    await agent.post({ text })
    return res.json({ ok: true })
  } catch (err) {
    console.error('Post failed:', err)
    return res.status(500).json({ error: 'post failed' })
  }
})

// Protected endpoint: internal API to post a thread (two posts in a thread)
app.post('/post-thread', express.json(), async (req, res) => {
  // Verify internal token
  const token = req.get('X-Internal-Token') || ''
  if (token !== INTERNAL_API_TOKEN) {
    return res.status(403).json({ error: 'forbidden' })
  }
  const firstText = (req.body?.firstText || '').toString().trim()
  const secondText = (req.body?.secondText || '').toString().trim()
  if (!firstText || !secondText) {
    return res.status(400).json({ error: 'missing text' })
  }
  // Get the latest OAuth session
  const row = await pg.query(`SELECT sub FROM oauth_sessions ORDER BY updated_at DESC LIMIT 1`)
  if (!row.rowCount) {
    return res.status(401).json({ error: 'OAuth session not found. Visit /auth/start to connect.' })
  }
  const sub = row.rows[0].sub
  let session
  try {
    session = await client.restore(sub)
  } catch (err) {
    console.error('Restore session failed:', err)
    return res.status(401).json({ error: 'OAuth session expired or invalid. Visit /auth/start to reconnect.' })
  }
  const agent = new Agent(session)
  try {
    // Create the first post
    const firstPost = await agent.post({ text: firstText })
    const firstUri = firstPost.uri
    const firstCid = firstPost.cid
    // Create the second post as a reply to the first
    await agent.post({
      text: secondText,
      reply: {
        root: { uri: firstUri, cid: firstCid },
        parent: { uri: firstUri, cid: firstCid }
      }
    })
    return res.json({ ok: true })
  } catch (err) {
    console.error('Post-thread failed:', err)
    return res.status(500).json({ error: 'post-thread failed' })
  }
})

// Global error handler (for any uncaught errors in routes)
app.use((err, _req, res, _next) => {
  console.error(err)
  res.status(500).json({ error: err?.message || 'server error' })
})

// Start the server
app.listen(PORT, () => {
  console.log(`web listening on :${PORT}`)
})

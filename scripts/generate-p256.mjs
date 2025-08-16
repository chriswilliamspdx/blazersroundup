// scripts/generate-p256.mjs
// Node 20+ with ESM. Generates an EC P-256 (ES256) keypair.
// Prints: public JWKS (for docs/jwks.json), PRIVATE JWK (Railway env),
// optional PEM, and KID.
//
// Run:  node scripts/generate-p256.mjs
import { randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK, exportPKCS8 } from 'jose';

const kid = randomUUID();

// 1) Generate ES256 (aka P-256)
const { publicKey, privateKey } = await generateKeyPair('ES256');

// 2) Export to JWKs
const pubJwk = await exportJWK(publicKey);
const privJwk = await exportJWK(privateKey);

// 3) Annotate and normalize
const PUBLIC_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: pubJwk.x,
  y: pubJwk.y,
  use: 'sig',
  kid,
};

const PRIVATE_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: pubJwk.x,
  y: pubJwk.y,
  d: privJwk.d, // secret
  use: 'sig',
  kid,
};

// 4) Optional PEM (fallback)
const privPem = await exportPKCS8(privateKey);

// 5) Print outputs
console.log('--- JWKS (public) -> paste into docs/jwks.json ---');
console.log(JSON.stringify({ keys: [PUBLIC_JWK] }, null, 2));
console.log('\n--- PRIVATE JWK (JSON) -> Railway var BSKY_OAUTH_PRIVATE_KEY_JWK ---');
console.log(JSON.stringify(PRIVATE_JWK, null, 2));
console.log('\n--- PRIVATE KEY (PEM) -> Railway var BSKY_OAUTH_PRIVATE_KEY_PEM (optional) ---');
console.log(privPem);
console.log('\n--- KID -> Railway var BSKY_OAUTH_KID ---');
console.log(kid);

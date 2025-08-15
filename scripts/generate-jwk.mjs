// scripts/generate-jwk.mjs
// Node 20+
// Usage: node scripts/generate-jwk.mjs
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { exportJWK, exportPKCS8 } from 'jose';

// Generate Ed25519 keypair (OKP)
const { publicKey, privateKey } = generateKeyPairSync('ed25519');

// Convert to the formats we need
const pubJwk = await exportJWK(publicKey);     // public JWK
const privPem = await exportPKCS8(privateKey); // PKCS8 PEM (private)

// Add required fields
const kid = randomUUID();
pubJwk.kty = 'OKP';
pubJwk.use = 'sig';
pubJwk.kid = kid;
pubJwk.crv = 'Ed25519'; // OKP curves: Ed25519 | Ed448

// Print outputs to copy-paste
console.log('--- JWKS (public) -> paste into docs/jwks.json ---');
console.log(JSON.stringify({ keys: [pubJwk] }, null, 2));
console.log('\n--- PRIVATE KEY (PEM) -> Railway var BSKY_OAUTH_PRIVATE_KEY_PEM ---');
console.log(privPem);
console.log('\n--- KID -> Railway var BSKY_OAUTH_KID ---');
console.log(kid);

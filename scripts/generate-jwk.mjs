// scripts/generate-jwk.mjs
// Node 20+
// Usage: node scripts/generate-jwk.mjs
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { exportJWK, exportPKCS8 } from 'jose';

// Generate an EC P-256 keypair
const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

// Export formats Bluesky expects
const pubJwk = await exportJWK(publicKey);   // JWK (public)
const privPem = await exportPKCS8(privateKey); // PKCS8 PEM (private)

// Add required fields
const kid = randomUUID();
pubJwk.kty = 'EC';
pubJwk.use = 'sig';
pubJwk.kid = kid;
pubJwk.crv = 'P-256';

// Print what you need to copy/paste
console.log('--- JWKS (public) -> paste into docs/jwks.json ---');
console.log(JSON.stringify({ keys: [pubJwk] }, null, 2));
console.log('\n--- PRIVATE KEY (PEM) -> Railway var BSKY_OAUTH_PRIVATE_KEY_PEM ---');
console.log(privPem);
console.log('\n--- KID -> Railway var BSKY_OAUTH_KID ---');
console.log(kid);

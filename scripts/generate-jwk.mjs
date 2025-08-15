// scripts/generate-jwk.mjs
// Node 20+
// Usage: node scripts/generate-jwk.mjs
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { exportJWK, exportPKCS8 } from 'jose';

// Generate Ed25519 keypair (OKP)
const { publicKey, privateKey } = generateKeyPairSync('ed25519');

// Convert to formats
const pubJwk = await exportJWK(publicKey);      // public JWK (no 'd')
const privJwk = await exportJWK(privateKey);    // private JWK (has 'd')
const privPem = await exportPKCS8(privateKey);  // PKCS8 PEM

// Annotate
const kid = randomUUID();
for (const j of [pubJwk, privJwk]) {
  j.kty = 'OKP';
  j.use = 'sig';
  j.kid = kid;
  j.crv = 'Ed25519';
}

console.log('--- JWKS (public) -> paste into docs/jwks.json ---');
console.log(JSON.stringify({ keys: [pubJwk] }, null, 2));

console.log('\n--- PRIVATE JWK (JSON) -> Railway var BSKY_OAUTH_PRIVATE_KEY_JWK ---');
console.log(JSON.stringify(privJwk, null, 2));

console.log('\n--- PRIVATE KEY (PEM) -> Railway var BSKY_OAUTH_PRIVATE_KEY_PEM (optional) ---');
console.log(privPem);

console.log('\n--- KID -> Railway var BSKY_OAUTH_KID ---');
console.log(kid);

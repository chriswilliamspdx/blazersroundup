// Node 20+
// Usage: node scripts/generate-jwk.mjs
import { generateKeyPair } from 'node:crypto';
import { exportJWK, exportPKCS8, importJWK } from 'jose';

function b64url(u8) { return Buffer.from(u8).toString('base64url'); }

generateKeyPair('ec', { namedCurve: 'P-256' }, async (err, keypair) => {
  if (err) throw err;
  const pub = await exportJWK(keypair.publicKey);
  const privPem = await exportPKCS8(keypair.privateKey);
  const kid = crypto.randomUUID();
  pub.kid = kid;
  pub.use = 'sig';
  console.log('--- JWKS (public) -> docs/jwks.json ---');
  console.log(JSON.stringify({ keys: [pub] }, null, 2));
  console.log('\n--- PRIVATE KEY (PEM) -> Railway var BSKY_OAUTH_PRIVATE_KEY_PEM ---');
  console.log(privPem);
  console.log('\n--- KID -> Railway var BSKY_OAUTH_KID ---');
  console.log(kid);
});

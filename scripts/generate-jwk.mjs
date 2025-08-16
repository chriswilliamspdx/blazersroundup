// scripts/generate-jwk.mjs
// Node 20+
// Usage: node scripts/generate-jwk.mjs
import { generateKeyPairSync, randomUUID, createPublicKey } from 'node:crypto';

/**
 * Generate an EC P-256 keypair suitable for OAuth private_key_jwt (ES256).
 * Prints:
 *  - JWKS (public)     -> docs/jwks.json
 *  - PRIVATE JWK (JSON)-> Railway var BSKY_OAUTH_PRIVATE_KEY_JWK
 *  - PRIVATE KEY (PEM) -> (optional fallback) Railway var BSKY_OAUTH_PRIVATE_KEY_PEM
 *  - KID               -> Railway var BSKY_OAUTH_KID  (must match JWKS kid)
 */

// 1) Generate P-256 keypair
const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const publicKey = createPublicKey(privateKey);

// 2) Export to JWK (we’ll do it manually to avoid extra deps)
function base64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function ecPointXY(pubKey) {
  const spki = pubKey.export({ type: 'spki', format: 'der' });
  // Very small ASN.1 parser to grab uncompressed point:
  // Last bytes should be: 0x03 0x42 0x00 0x04 || X(32) || Y(32)
  // We'll search for 0x04 that begins the uncompressed point.
  const idx = spki.lastIndexOf(0x04);
  if (idx < 0 || idx + 65 > spki.length) throw new Error('Failed to parse EC public key point');
  const X = spki.subarray(idx + 1, idx + 33);
  const Y = spki.subarray(idx + 33, idx + 65);
  return { x: base64url(X), y: base64url(Y) };
}

const kid = randomUUID();
const { x, y } = ecPointXY(publicKey);

// Private JWK (has "d")
const pkcs8Der = privateKey.export({ type: 'pkcs8', format: 'der' });
/* PKCS#8 EC private-key structure:
   The "d" (private scalar) is contained in an OCTET STRING. A robust ASN.1
   parser is overkill here; instead, export a JWK using the runtime:
*/
import('jose').then(async ({ exportJWK, exportPKCS8 }) => {
  const privJwk = await exportJWK(privateKey);
  const pubJwk  = await exportJWK(publicKey);
  // Normalize to expected fields & annotate
  const PRIVATE_JWK = {
    kty: 'EC',
    crv: 'P-256',
    x,
    y,
    d: privJwk.d,        // secret
    use: 'sig',
    kid
  };
  const PUBLIC_JWK = {
    kty: 'EC',
    crv: 'P-256',
    x,
    y,
    use: 'sig',
    kid
  };
  const privPem = await exportPKCS8(privateKey);

  console.log('--- JWKS (public) -> paste into docs/jwks.json ---');
  console.log(JSON.stringify({ keys: [PUBLIC_JWK] }, null, 2));
  console.log('\n--- PRIVATE JWK (JSON) -> Railway var BSKY_OAUTH_PRIVATE_KEY_JWK ---');
  console.log(JSON.stringify(PRIVATE_JWK, null, 2));
  console.log('\n--- PRIVATE KEY (PEM) -> Railway var BSKY_OAUTH_PRIVATE_KEY_PEM (optional) ---');
  console.log(privPem);
  console.log('\n--- KID -> Railway var BSKY_OAUTH_KID ---');
  console.log(kid);
}).catch((e) => {
  console.error(e);
  process.exit(1);
});

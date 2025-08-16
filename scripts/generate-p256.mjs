// scripts/generate-p256.mjs
// Generates an ES256 (P-256) keypair for Bluesky OAuth:
// 1) Prints PRIVATE JWK (with "d") for BSKY_OAUTH_PRIVATE_KEY
// 2) Prints JWKS (public only) for jwks.json
// 3) Prints a bsky-client.json template (you'll paste in your redirect URI and metadata URLs)
// No external libraries required. Requires Node.js v18+ (uses global WebCrypto).

import { webcrypto, randomUUID } from 'node:crypto';

const subtle = webcrypto.subtle;

// helpers ----------
const abToB64 = (ab) => Buffer.from(ab).toString('base64');
const toPem = (derBuf, label) => {
  const b64 = abToB64(derBuf);
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
};

// main ------------
(async () => {
  // 1) Generate a P-256 keypair for ECDSA signing (ES256)
  const keyPair = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  // 2) Export JWKs
  const privJwk = await subtle.exportKey('jwk', keyPair.privateKey);
  const pubJwk  = await subtle.exportKey('jwk', keyPair.publicKey);

  // 3) Attach metadata required by OAuth servers/clients
  const kid = randomUUID();
  const privateJwkOut = {
    kty: 'EC',
    crv: 'P-256',
    x: pubJwk.x,
    y: pubJwk.y,
    d: privJwk.d,
    kid,
    use: 'sig',
    alg: 'ES256'
  };
  const publicJwkOut = {
    kty: 'EC',
    crv: 'P-256',
    x: pubJwk.x,
    y: pubJwk.y,
    kid,
    use: 'sig',
    alg: 'ES256'
  };
  const jwksOut = { keys: [publicJwkOut] };

  // 4) Also provide PEM (optional—your server accepts JWK; PEM is here just in case)
  const pkcs8 = await subtle.exportKey('pkcs8', keyPair.privateKey);
  const privatePem = toPem(pkcs8, 'PRIVATE KEY');

  // 5) Pretty print outputs
  const divider = (t) => `\n\n==================== ${t} ====================\n`;
  process.stdout.write(divider('PRIVATE_JWK (PUT IN Railway: BSKY_OAUTH_PRIVATE_KEY)'));
  process.stdout.write(JSON.stringify(privateJwkOut, null, 2));

  process.stdout.write(divider('PRIVATE_PKCS8_PEM (optional, not required if using the JWK)'));
  process.stdout.write(privatePem);

  process.stdout.write(divider('JWKS (PUT IN GitHub Pages: jwks.json)'));
  process.stdout.write(JSON.stringify(jwksOut, null, 2));

  process.stdout.write(divider('CLIENT METADATA TEMPLATE (PUT IN GitHub Pages: bsky-client.json)'));
  // Fill these two values after printing:
  const JWKS_URI = 'https://chriswilliamspdx.github.io/blazersroundup/jwks.json';
  const REDIRECT_URI = 'https://YOUR-RAILWAY-APP.up.railway.app/oauth/callback'; // <- REPLACE THIS
  const clientMetadata = {
    client_name: "Blazers Roundup Bot (Web OAuth)",
    client_uri: "https://blazersroundup-production.up.railway.app",            // optional but good practice
    policy_uri: "https://blazersroundup-production.up.railway.app/policy",     // optional
    tos_uri: "https://blazersroundup-production.up.railway.app/tos",           // optional
    redirect_uris: [REDIRECT_URI],                                    // must be https for web apps
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "private_key_jwt",
    token_endpoint_auth_signing_alg: "ES256",
    jwks_uri: JWKS_URI
  };
  process.stdout.write(JSON.stringify(clientMetadata, null, 2));
  process.stdout.write('\n');
})();

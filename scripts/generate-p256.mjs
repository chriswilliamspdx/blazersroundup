// scripts/generate-p256.mjs
// Generates an ES256 (P-256) keypair for Bluesky OAuth:
// 1) Prints PRIVATE JWK for Railway
// 2) Prints JWKS (public only) for jwks.json
// 3) Prints a bsky-client.json template

import { webcrypto, randomUUID } from 'node:crypto';

const subtle = webcrypto.subtle;

const abToB64 = (ab) => Buffer.from(ab).toString('base64');
const toPem = (derBuf, label) => {
  const b64 = abToB64(derBuf);
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
};

(async () => {
  const keyPair = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  const privJwk = await subtle.exportKey('jwk', keyPair.privateKey);
  const pubJwk = await subtle.exportKey('jwk', keyPair.publicKey);

  const kid = randomUUID();
  const privateJwkOut = {
    kty: 'EC',
    crv: 'P-256',
    x: pubJwk.x,
    y: pubJwk.y,
    d: privJwk.d,
    kid,
    alg: 'ES256',
    key_ops: ['sign']
  };
  const publicJwkOut = {
    kty: 'EC',
    crv: 'P-256',
    x: pubJwk.x,
    y: pubJwk.y,
    kid,
    alg: 'ES256',
    key_ops: ['verify']
  };
  const jwksOut = { keys: [publicJwkOut] };

  const pkcs8 = await subtle.exportKey('pkcs8', keyPair.privateKey);
  const privatePem = toPem(pkcs8, 'PRIVATE KEY');

  const divider = (t) => `\n\n==================== ${t} ====================\n`;
  process.stdout.write(divider('PRIVATE_JWK (PUT IN Railway: BSKY_OAUTH_PRIVATE_KEY_JWK)'));
  process.stdout.write(JSON.stringify(privateJwkOut, null, 2));

  process.stdout.write(divider('PRIVATE_PKCS8_PEM (optional, not required if using the JWK)'));
  process.stdout.write(privatePem);

  process.stdout.write(divider('JWKS (PUT IN GitHub Pages: jwks.json)'));
  process.stdout.write(JSON.stringify(jwksOut, null, 2));

  process.stdout.write(divider('CLIENT METADATA TEMPLATE (PUT IN GitHub Pages: bsky-client.json)'));
  const JWKS_URI = 'https://chriswilliamspdx.github.io/blazersroundup/jwks.json';
  const REDIRECT_URI = 'https://YOUR-RAILWAY-APP.up.railway.app/oauth/callback';
  const clientMetadata = {
    client_name: "Blazers Roundup Bot (Web OAuth)",
    client_uri: "https://blazersroundup-production.up.railway.app",
    policy_uri: "https://blazersroundup-production.up.railway.app/policy",
    tos_uri: "https://blazersroundup-production.up.railway.app/tos",
    redirect_uris: [REDIRECT_URI],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "private_key_jwt",
    token_endpoint_auth_signing_alg: "ES256",
    jwks_uri: JWKS_URI
  };
  process.stdout.write(JSON.stringify(clientMetadata, null, 2));
  process.stdout.write('\n');
})();

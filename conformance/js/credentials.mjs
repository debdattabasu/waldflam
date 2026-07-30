// Credentials against a *verifying* server (WALDFLAM_AUTH=verify).
//
// Every other suite runs in emulator mode, where nothing is verified and
// `Bearer owner` is admin. This one runs where signatures are required, and
// covers the whole credential path with no external identity provider in it:
// a service-account key file signs an assertion, that becomes an access
// token, the access token vouches for a uid, and waldflam issues the ID token
// the user then reads and writes with.
//
// Deliberately built on plain fetch() and node:crypto rather than the Admin
// SDK, so what is being checked is the *wire contract* — the assertion shape
// a Google auth library produces and the responses it expects back — rather
// than one library's behaviour.

import { createSign, createPrivateKey } from 'node:crypto';
import { readFileSync } from 'node:fs';

const host = process.env.WALDFLAM_HOST || '127.0.0.1';
const port = parseInt(process.env.WALDFLAM_PORT || '8099', 10);
const base = `http://${host}:${port}`;
const keyFile = JSON.parse(readFileSync(process.env.WALDFLAM_KEY_FILE, 'utf8'));
const project = keyFile.project_id;

const assert = (cond, msg) => { if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); } };
const b64 = (value) => Buffer.from(value).toString('base64url');
const now = () => Math.floor(Date.now() / 1000);

// The JWT a Google auth library builds from a service-account key file.
function signJwt(claims, key = keyFile) {
  const header = b64(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: key.private_key_id }));
  const payload = b64(JSON.stringify(claims));
  const signer = createSign('RSA-SHA256');
  signer.update(`${header}.${payload}`);
  return `${header}.${payload}.${b64(signer.sign(createPrivateKey(key.private_key)))}`;
}

const assertion = (audience) => signJwt({
  iss: keyFile.client_email,
  sub: keyFile.client_email,
  aud: audience,
  iat: now(),
  exp: now() + 3600,
});

const docPath = (path) => `projects/${project}/databases/(default)/documents/${path}`;

async function firestore(method, body, token) {
  const res = await fetch(`${base}/v1/projects/${project}/databases/(default)/documents:${method}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}

const write = (path, fields, token) =>
  firestore('commit', { writes: [{ update: { name: docPath(path), fields } }] }, token);
const read = (path, token) => firestore('batchGet', { documents: [docPath(path)] }, token);

// ---- the deployment advertises itself as an issuer -----------------------

const discovery = await (await fetch(`${base}/.well-known/openid-configuration`)).json();
assert(discovery.issuer === base, `issuer ${discovery.issuer} should be ${base}`);
assert(discovery.token_endpoint === keyFile.token_uri, 'discovery must match the key file');

const jwks = await (await fetch(`${base}/.well-known/jwks.json`)).json();
assert(jwks.keys?.length >= 1 && jwks.keys[0].kty === 'RSA', 'JWKS must publish an RSA key');
assert(jwks.keys.every((k) => k.kid && k.n && k.e && !k.d), 'JWKS must never carry a private key');
console.log('CRED DISCOVERY ok:', discovery.issuer, `${jwks.keys.length} key(s)`);

// ---- the emulator's backdoors must not exist here ------------------------

assert((await read('any/doc', 'owner')).status === 401, '`owner` must not authenticate');
const unsigned = `${b64(JSON.stringify({ alg: 'none' }))}.${b64(JSON.stringify({ sub: 'alice' }))}.`;
assert((await read('any/doc', unsigned)).status === 401, 'an unsigned token must be refused');
console.log('CRED BACKDOORS ok: `owner` and unsigned tokens are refused');

// ---- OAuth2 JWT-bearer grant --------------------------------------------

const tokenRes = await fetch(keyFile.token_uri, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: assertion(keyFile.token_uri),
  }),
});
const granted = await tokenRes.json();
assert(tokenRes.ok, `token exchange: ${tokenRes.status} ${JSON.stringify(granted)}`);
assert(granted.token_type === 'Bearer' && granted.expires_in > 0, 'OAuth2 response shape');
const accessToken = granted.access_token;
console.log('CRED EXCHANGE ok: access token expires in', granted.expires_in);

const badGrant = await fetch(keyFile.token_uri, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    // Right shape, wrong signature.
    assertion: `${assertion(keyFile.token_uri).slice(0, -6)}AAAAA`,
  }),
});
assert(badGrant.status === 400, 'a bad assertion must not be exchanged');
assert((await badGrant.json()).error === 'invalid_grant', 'OAuth2 error shape');
console.log('CRED EXCHANGE ok: a forged assertion is refused');

// ---- the access token is admin: it can load rules, and bypass them -------

const rules = `
  rules_version = '2';
  service cloud.firestore {
    match /databases/{db}/documents {
      match /users/{uid} { allow read, write: if request.auth.uid == uid; }
      match /editors/{doc} { allow read, write: if request.auth.token.role == 'editor'; }
      match /locked/{doc} { allow read, write: if false; }
    }
  }`;
const loadRules = (token) => fetch(`${base}/emulator/v1/projects/${project}:securityRules`, {
  method: 'PUT',
  headers: {
    'content-type': 'application/json',
    ...(token ? { authorization: `Bearer ${token}` } : {}),
  },
  body: JSON.stringify({ rules: { files: [{ name: 'f.rules', content: rules }] } }),
});

// These endpoints load rules and erase databases. Open in emulator mode,
// which is a local dev tool; never open on a server anyone can reach.
assert((await loadRules(null)).status === 403, 'the admin API must reject anonymous callers');
assert((await loadRules(accessToken)).ok, 'a service account may load rules');
console.log('CRED ADMIN API ok: closed to anonymous, open to a service account');

const bypass = await write('locked/doc', { ok: { booleanValue: true } }, accessToken);
assert(bypass.status === 200, `admin must bypass rules: ${JSON.stringify(bypass.body)}`);
console.log('CRED ADMIN ok: a service account bypasses security rules');

// The assertion works as a bearer token directly, too — which auth library
// versions do instead of the exchange, and a server cannot dictate which.
const direct = await write('locked/direct', { ok: { booleanValue: true } }, assertion(base));
assert(direct.status === 200, `a self-signed assertion must authenticate: ${direct.status}`);
console.log('CRED ASSERTION ok: a self-signed assertion is accepted directly');

// ---- a service account vouches for a user; waldflam issues the identity --

const customToken = signJwt({
  iss: keyFile.client_email,
  sub: keyFile.client_email,
  aud: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
  iat: now(),
  exp: now() + 3600,
  uid: 'alice',
  claims: { role: 'editor' },
});
const signInRes = await fetch(`${base}/v1/accounts:signInWithCustomToken`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ token: customToken, returnSecureToken: true }),
});
const signIn = await signInRes.json();
assert(signInRes.ok, `sign in: ${signInRes.status} ${JSON.stringify(signIn)}`);
assert(signIn.kind === 'identitytoolkit#VerifyCustomTokenResponse', 'identitytoolkit shape');
assert(signIn.idToken && signIn.refreshToken, 'sign-in returns an ID and a refresh token');
console.log('CRED SIGN-IN ok: custom token exchanged for an ID token');

const idToken = signIn.idToken;
const claims = JSON.parse(Buffer.from(idToken.split('.')[1], 'base64url').toString());
assert(claims.sub === 'alice' && claims.user_id === 'alice', 'ID token identifies the uid');
assert(claims.aud === project && claims.iss === base, 'ID token is bound to project and issuer');
assert(claims.role === 'editor', 'custom claims survive into the ID token');

// ---- rules see that identity ---------------------------------------------

assert((await write('users/alice', { n: { integerValue: '1' } }, idToken)).status === 200,
  'alice may write her own document');
assert((await write('users/bob', { n: { integerValue: '1' } }, idToken)).status === 403,
  "alice may not write bob's document");
assert((await write('editors/post', { n: { integerValue: '1' } }, idToken)).status === 200,
  'a custom claim from the ID token reaches rules');
assert((await write('locked/doc', { n: { integerValue: '1' } }, idToken)).status === 403,
  'an ID token is a user, not an admin');
assert((await read('users/alice', null)).status === 403, 'anonymous reads stay denied');
console.log('CRED RULES ok: request.auth.uid and custom claims are enforced');

// A user's ID token must not open the admin API.
assert((await loadRules(idToken)).status === 403, 'a user must not reach the admin API');
console.log('CRED ADMIN API ok: a user identity is not admin');

// ---- refresh -------------------------------------------------------------

const refreshRes = await fetch(`${base}/v1/token`, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: signIn.refreshToken }),
});
const refreshed = await refreshRes.json();
assert(refreshRes.ok, `refresh: ${refreshRes.status} ${JSON.stringify(refreshed)}`);
assert(refreshed.user_id === 'alice' && refreshed.project_id === project, 'refresh response shape');
assert((await write('users/alice', { n: { integerValue: '2' } }, refreshed.id_token)).status === 200,
  'a refreshed ID token still authenticates');
// The refresh token itself is not a credential.
assert((await read('users/alice', signIn.refreshToken)).status === 401,
  'a refresh token must not authenticate requests');
console.log('CRED REFRESH ok: refreshed identity works, refresh token alone does not');

console.log('ALL JS CREDENTIALS CHECKS PASSED');
process.exit(0);

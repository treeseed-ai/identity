import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createAccessTokenVerifier, IdentityAuthenticationError } from '../dist/index.js';

const issuer = 'https://identity.example/realms/local';
const audience = 'https://api.example';
const now = 1_800_000_000;
const key = await generateKeyPair('RS256');
const other = await generateKeyPair('RS256');
const claims = { iss: issuer, sub: 'person-1', aud: audience, iat: now, exp: now + 300, typ: 'Bearer', scope: 'project:read' };
const sign = (overrides = {}, header = {}, signingKey = key.privateKey) => new SignJWT({ ...claims, ...overrides })
  .setProtectedHeader({ alg: 'RS256', typ: 'JWT', ...header }).sign(signingKey);
function fixture(options = {}) {
  const mapped = [];
  const verify = createAccessTokenVerifier({ issuer, audience, profile: 'keycloak', verificationKey: key.publicKey,
    now: () => new Date(now * 1000), resolvePrincipal: async (identity) => { mapped.push(identity); return { principalId: 'existing-user-id', kind: 'human' }; }, ...options });
  return { verify, mapped };
}

test('preserves local IDs and discards email, role and membership claims', async () => {
  const { verify, mapped } = fixture();
  const result = await verify(await sign({ email: 'owner@example', roles: ['owner'], teamId: 'other-team' }));
  assert.deepEqual(result, { principalId: 'existing-user-id', kind: 'human', identity: { issuer, subject: 'person-1' }, audience, scopes: ['project:read'] });
  assert.deepEqual(mapped, [{ issuer, subject: 'person-1' }]);
});

for (const [name, overrides] of Object.entries({
  issuer: { iss: 'https://untrusted.example' }, audience: { aud: 'https://market.example' },
  expired: { exp: now }, future: { iat: now + 1 }, longLived: { exp: now + 301 },
  idToken: { typ: 'ID' }, missingExpiry: { exp: undefined }, missingIssued: { iat: undefined },
  emptySubject: { sub: '' }, numericSubject: { sub: 7 },
  actor: { act: { sub: 'privileged-agent' } }, invalidScope: { scope: ['owner'] },
  duplicateScope: { scope: 'project:read project:read' },
})) {
  test(`rejects ${name} before local principal resolution`, async () => {
    const { verify, mapped } = fixture();
    await assert.rejects(verify(await sign(overrides)), IdentityAuthenticationError);
    assert.equal(mapped.length, 0);
  });
}

test('rejects forged signatures, malformed and oversized tokens with redacted errors', async () => {
  const { verify, mapped } = fixture();
  for (const token of [await sign({}, {}, other.privateKey), 'sensitive-invalid-input', 'a'.repeat(16385)]) {
    await assert.rejects(verify(token), (error) => error.code === 'identity_authentication_failed' && error.message === 'Identity authentication failed.');
  }
  assert.equal(mapped.length, 0);
});

test('rejects untrusted key URLs before invoking even an injected key resolver', async () => {
  let calls = 0;
  const { verify } = fixture({ verificationKey: async () => { calls++; return key.publicKey; } });
  await assert.rejects(verify(await sign({}, { jku: 'https://metadata.example/keys' })), IdentityAuthenticationError);
  assert.equal(calls, 0);
});

test('fails unknown local identity without email auto-enrollment', async () => {
  const { verify } = fixture({ resolvePrincipal: async () => null });
  await assert.rejects(verify(await sign({ email: 'existing@example.org' })), IdentityAuthenticationError);
});

test('accepts only access tokens in the RFC 9068 profile', async () => {
  const { verify } = fixture({ profile: 'rfc9068' });
  await verify(await sign({ typ: undefined }, { typ: 'at+jwt' }));
  await assert.rejects(verify(await sign()), IdentityAuthenticationError);
});

test('supports explicit trusted JWKS rotation without discovering token-supplied trust', async () => {
  const jwks = createLocalJWKSet({ keys: [
    { ...await exportJWK(key.publicKey), kid: 'old', alg: 'RS256' },
    { ...await exportJWK(other.publicKey), kid: 'new', alg: 'RS256' },
  ] });
  const { verify } = fixture({ verificationKey: jwks });
  await verify(await sign({}, { kid: 'old' }));
  await verify(await sign({}, { kid: 'new' }, other.privateKey));
});

test('rejects HMAC tokens even when the signature is cryptographically valid', async () => {
  const { verify } = fixture();
  const token = await new SignJWT(claims).setProtectedHeader({ alg: 'HS256' }).sign(new Uint8Array(32));
  await assert.rejects(verify(token), IdentityAuthenticationError);
});

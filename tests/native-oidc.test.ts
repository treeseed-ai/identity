import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createNativeOidcClient } from '../dist/native-oidc.js';

const issuer = 'https://identity.example.test/realms/local', resource = 'https://api.example.test';
const redirectUri = 'http://127.0.0.1:49831/callback';
const pair = await generateKeyPair('RS256');
const jwk = { ...await exportJWK(pair.publicKey), alg: 'RS256', kid: 'test-key', use: 'sig' };
async function fixture(options: { subject?: string; nonce?: string; audience?: string; redirect?: string } = {}) {
  let authorization: URL, requests = 0, now = Date.now();
  const transport: typeof fetch = async (url, init) => {
    assert.equal(init?.redirect, 'error');
    if (String(url).includes('.well-known')) return Response.json({ issuer, authorization_endpoint: `${issuer}/auth`, token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/certs`, code_challenge_methods_supported: ['S256'] });
    if (String(url).endsWith('/certs')) return Response.json({ keys: [jwk] });
    requests++;
    const body = new URLSearchParams(init?.body as string);
    assert.equal(body.get('client_id'), 'trsd'); assert.equal(body.has('client_secret'), false); assert.equal(body.has('client_assertion'), false);
    assert.equal(body.get('resource'), resource); assert.equal(body.get('redirect_uri'), redirectUri);
    assert.equal(createHash('sha256').update(body.get('code_verifier')!).digest('base64url'), authorization.searchParams.get('code_challenge'));
    const id = await new SignJWT({ nonce: options.nonce ?? authorization.searchParams.get('nonce') }).setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(issuer).setAudience('trsd').setSubject(options.subject ?? 'human').setIssuedAt().setExpirationTime('5m').sign(pair.privateKey);
    const access = await new SignJWT({ typ: 'Bearer', azp: 'trsd', scope: 'treeseed:read' }).setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(issuer).setAudience(options.audience ?? resource).setSubject('human').setIssuedAt().setExpirationTime('5m').sign(pair.privateKey);
    return Response.json({ access_token: access, id_token: id, token_type: 'Bearer', expires_in: 300 });
  };
  const client = await createNativeOidcClient({ issuer, clientId: 'trsd', redirectUri: options.redirect ?? redirectUri, resource, scopes: ['treeseed:read'],
    verificationKey: pair.publicKey, profile: 'keycloak', transport, now: () => now,
    resolvePrincipal: async () => ({ principalId: 'existing-user', kind: 'human' }) });
  const pending = await client.begin(); authorization = new URL(pending.authorizationUrl);
  const callback = () => new URL(`${redirectUri}?code=one-time&state=${authorization.searchParams.get('state')}&iss=${encodeURIComponent(issuer)}`);
  return { pending, authorization, callback, requests: () => requests, expire: () => { now += 300001; } };
}
test('native PKCE uses no client secret, keeps verifier private, and validates both signed identities', async () => {
  const f = await fixture(); assert.equal(f.authorization.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(f.authorization.searchParams.has('code_verifier'), false);
  const result = await f.pending.finish(f.callback()); assert.equal(result.principal.principalId, 'existing-user');
  await assert.rejects(f.pending.finish(f.callback())); assert.equal(f.requests(), 1);
});
test('rejects changed subject, nonce and API audience', async () => {
  for (const options of [{ subject: 'another-human' }, { nonce: 'wrong' }, { audience: 'https://another-market.test' }]) {
    const f = await fixture(options); await assert.rejects(f.pending.finish(f.callback()), { code: 'identity_authentication_failed' });
    await assert.rejects(f.pending.finish(f.callback())); assert.equal(f.requests(), 1);
  }
});
test('wrong state, duplicated state or wrong callback cannot exchange or erase a valid transaction', async () => {
  for (const mode of ['state', 'duplicate', 'port', 'path']) {
    const f = await fixture(), invalid = f.callback();
    if (mode === 'state') invalid.searchParams.set('state', 'wrong');
    if (mode === 'duplicate') invalid.searchParams.append('state', 'wrong');
    if (mode === 'port') invalid.port = '49832';
    if (mode === 'path') invalid.pathname = '/other';
    await assert.rejects(f.pending.finish(invalid)); assert.equal(f.requests(), 0);
    assert.equal((await f.pending.finish(f.callback())).principal.principalId, 'existing-user');
  }
});
test('expired and cancelled transactions never exchange; non-IP-loopback redirects are rejected', async () => {
  const f = await fixture(); f.expire(); await assert.rejects(f.pending.finish(f.callback())); assert.equal(f.requests(), 0);
  const g = await fixture(); g.pending.cancel(); await assert.rejects(g.pending.finish(g.callback())); assert.equal(g.requests(), 0);
  for (const redirect of ['http://localhost:4000/callback', 'http://0.0.0.0:4000/callback', 'https://example.test/callback', 'http://127.0.0.1/callback', 'http://127.0.0.1:4000/callback?extra=1'])
    await assert.rejects(fixture({ redirect }));
});

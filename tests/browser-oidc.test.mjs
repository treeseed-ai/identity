import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createBrowserOidcClient } from '../dist/browser-oidc.js';

const issuer = 'https://identity.example.test/realms/local';
const redirectUri = 'https://admin.example.test/auth/callback';
const pair = await generateKeyPair('RS256');
const jwk = { ...await exportJWK(pair.publicKey), alg: 'RS256', kid: 'test-key', use: 'sig' };
async function fixture({ metadata = {}, claims = {} } = {}) {
  const transactions = new Map(); let transaction; let calls = 0; let now = Date.now();
  const store = {
    async put(binding, value) { transaction = value; transactions.set(`${binding}:${value.state}`, value); },
    async consume(binding, state) { const key = `${binding}:${state}`; const value = transactions.get(key); transactions.delete(key); return value ?? null; },
  };
  const transport = async (url, init) => {
    assert.equal(init.redirect, 'error');
    if (String(url).includes('.well-known')) return Response.json({ issuer, authorization_endpoint: `${issuer}/auth`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/certs`, code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['private_key_jwt'], ...metadata });
    if (String(url).endsWith('/certs')) return Response.json({ keys: [jwk] });
    assert.equal(String(url), `${issuer}/token`); calls++;
    const parameters = new URLSearchParams(init.body);
    assert.equal(parameters.get('code_verifier'), transaction.verifier);
    assert.equal(parameters.get('redirect_uri'), redirectUri);
    assert.ok(parameters.get('client_assertion'));
    const id = await new SignJWT({ nonce: transaction.nonce, ...claims }).setProtectedHeader({ alg: 'RS256', kid: 'test-key' }).setIssuer(issuer).setAudience('admin').setSubject('existing-subject').setIssuedAt().setExpirationTime('5m').sign(pair.privateKey);
    return Response.json({ access_token: 'test-access', token_type: 'Bearer', expires_in: 60, id_token: id });
  };
  const client = await createBrowserOidcClient({ issuer, clientId: 'admin', redirectUri, privateKey: pair.privateKey, store, transport, now: () => now });
  return { client, callback: () => new URL(`${redirectUri}?code=one-time&state=${transaction.state}&iss=${encodeURIComponent(issuer)}`), calls: () => calls, expire: () => { now += 300_001; } };
}
test('PKCE confidential browser flow validates signed ID token and consumes callback once', async () => {
  const f = await fixture(); const url = new URL(await f.client.begin('browser-session'));
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.ok(url.searchParams.get('nonce')); assert.ok(url.searchParams.get('state'));
  assert.equal(url.searchParams.has('code_verifier'), false);
  const callback = f.callback();
  const result = await f.client.finish('browser-session', callback);
  assert.deepEqual(result.identity, { issuer, subject: 'existing-subject' });
  await assert.rejects(f.client.finish('browser-session', callback));
  assert.equal(f.calls(), 1);
});
test('browser binding, expiry, duplicate state and redirect mismatch reject before token exchange', async () => {
  for (const mode of ['binding', 'expiry', 'duplicate', 'redirect']) {
    const f = await fixture(); await f.client.begin('browser'); const callback = f.callback();
    if (mode === 'expiry') f.expire();
    if (mode === 'duplicate') callback.searchParams.append('state', 'extra');
    if (mode === 'redirect') callback.hostname = 'attacker.example.test';
    await assert.rejects(f.client.finish(mode === 'binding' ? 'other-browser' : 'browser', callback));
    assert.equal(f.calls(), 0);
  }
});
test('ID token nonce mismatch fails with redacted error', async () => {
  const f = await fixture({ claims: { nonce: 'wrong' } }); await f.client.begin('browser');
  await assert.rejects(f.client.finish('browser', f.callback()), error => error.code === 'identity_authentication_failed' && !error.message.includes('test-access'));
});
test('discovery rejects cross-origin credential endpoints, issuer mismatch and missing S256', async () => {
  for (const metadata of [{ issuer: 'https://other.example.test' }, { token_endpoint: 'https://attacker.example.test/token' }, { code_challenge_methods_supported: ['plain'] }]) await assert.rejects(fixture({ metadata }));
});

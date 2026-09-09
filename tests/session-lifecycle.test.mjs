import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createBrowserOidcClient } from '../dist/browser-oidc.js';

const issuer = 'https://identity.example.test/realms/local';
const pair = await generateKeyPair('RS256');
const jwk = { ...await exportJWK(pair.publicKey), alg: 'RS256', kid: 'key', use: 'sig' };
async function fixture({ subject = 'user', idToken = true, rejected = false, revocationEndpoint = `${issuer}/revoke` } = {}) {
  const calls = [];
  const transport = async (url, init) => {
    assert.equal(init.redirect, 'error');
    if (String(url).includes('.well-known')) return Response.json({ issuer, authorization_endpoint: `${issuer}/auth`, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/certs`, revocation_endpoint: revocationEndpoint, code_challenge_methods_supported: ['S256'] });
    if (String(url).endsWith('/certs')) return Response.json({ keys: [jwk] });
    calls.push(String(url)); const body = new URLSearchParams(init.body);
    assert.ok(body.get('client_assertion'));
    if (rejected) return Response.json({ error: 'invalid_grant', error_description: 'private-provider-detail' }, { status: 400 });
    if (String(url).endsWith('/revoke')) { assert.equal(body.get('token'), 'refresh'); return new Response(null, { status: 200 }); }
    assert.equal(body.get('grant_type'), 'refresh_token'); assert.equal(body.get('refresh_token'), 'refresh');
    const token = await new SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: 'key' }).setIssuer(issuer).setAudience('admin').setSubject(subject).setIssuedAt().setExpirationTime('5m').sign(pair.privateKey);
    return Response.json({ access_token: 'access-new', refresh_token: 'refresh-new', token_type: 'Bearer', expires_in: 60, ...(idToken ? { id_token: token } : {}) });
  };
  const client = await createBrowserOidcClient({ issuer, clientId: 'admin', redirectUri: 'https://admin.example.test/callback', privateKey: pair.privateKey,
    store: { async put() {}, async consume() { return null; } }, transport });
  return { client, calls };
}
test('refresh validates subject and returns rotated tokens only to server caller', async () => {
  for (const idToken of [true, false]) {
    const { client } = await fixture({ idToken });
    const result = await client.refresh('refresh', { issuer, subject: 'user' });
    assert.equal(result.identity.subject, 'user'); assert.equal(result.tokens.refresh_token, 'refresh-new');
  }
});
test('refresh rejects a changed subject or issuer without disclosing tokens', async () => {
  const { client, calls } = await fixture({ subject: 'other' });
  await assert.rejects(client.refresh('refresh', { issuer: 'https://other.test', subject: 'user' }));
  assert.equal(calls.length, 0);
  await assert.rejects(client.refresh('refresh', { issuer, subject: 'user' }), error => error.code === 'identity_authentication_failed');
});
test('revocation uses the client-bound endpoint and rejects provider errors cleanly', async () => {
  await (await fixture()).client.revoke('refresh');
  const { client } = await fixture({ rejected: true });
  await assert.rejects(client.revoke('refresh'), error => !error.message.includes('private-provider-detail'));
  await assert.rejects(fixture({ revocationEndpoint: 'https://attacker.test/revoke' }));
});

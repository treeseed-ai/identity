import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, SignJWT } from 'jose';
import { createPublicSessionClient } from '../dist/public-session.js';

const issuer = 'https://identity.example.test/realms/local', resource = 'https://api.example.test';
const pair = await generateKeyPair('RS256');
async function fixture(options: { subject?: string; audience?: string; clientId?: string; revoked?: boolean; revocationEndpoint?: string } = {}) {
  let requests = 0;
  const transport: typeof fetch = async (url, init) => {
    assert.equal(init?.redirect, 'error');
    if (String(url).includes('.well-known')) return Response.json({ issuer, token_endpoint: `${issuer}/token`, jwks_uri: `${issuer}/certs`, revocation_endpoint: options.revocationEndpoint ?? `${issuer}/revoke` });
    requests++;
    const body = new URLSearchParams(init?.body as string);
    assert.equal(body.get('client_id'), 'trsd'); assert.equal(body.has('client_secret'), false);
    if (String(url).endsWith('/revoke')) { assert.equal(body.get('token'), 'private-refresh'); return new Response(null, { status: 200 }); }
    assert.equal(body.get('resource'), resource); assert.equal(body.get('refresh_token'), 'private-refresh');
    const token = await new SignJWT({ typ: 'Bearer', azp: options.clientId ?? 'trsd', scope: 'treeseed:read' }).setProtectedHeader({ alg: 'RS256' })
      .setIssuer(issuer).setAudience(options.audience ?? resource).setSubject(options.subject ?? 'human').setIssuedAt().setExpirationTime('5m').sign(pair.privateKey);
    return Response.json({ access_token: token, token_type: 'Bearer', refresh_token: 'rotated-private-refresh', expires_in: 300 });
  };
  const client = await createPublicSessionClient({ issuer, clientId: 'trsd', resource, scopes: ['treeseed:read'], profile: 'keycloak', transport,
    verificationKey: pair.publicKey, resolvePrincipal: async () => options.revoked ? null : ({ principalId: 'existing-user', kind: 'human' }) });
  return { client, requests: () => requests };
}
test('public refresh keeps exact identity/resource and returns rotation only to secure-store caller', async () => {
  const f = await fixture(); const next = await f.client.refresh('private-refresh', { issuer, subject: 'human' });
  assert.equal(next.tokens.refresh_token, 'rotated-private-refresh'); assert.equal(next.resource, resource);
  assert.equal((await f.client.revoke('private-refresh')).revoked, true);
});
test('wrong issuer fails before network; changed subject, client, audience or revoked mapping fail closed', async () => {
  const f = await fixture(); await assert.rejects(f.client.refresh('private-refresh', { issuer: 'https://other.test', subject: 'human' })); assert.equal(f.requests(), 0);
  for (const options of [{ subject: 'other' }, { clientId: 'other' }, { audience: 'https://other.test' }, { revoked: true }]) {
    const f = await fixture(options); await assert.rejects(f.client.refresh('private-refresh', { issuer, subject: 'human' }), { code: 'identity_authentication_failed' });
  }
});
test('revocation cannot redirect credentials outside the configured issuer', async () => {
  await assert.rejects(fixture({ revocationEndpoint: 'https://attacker.test/revoke' }));
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, SignJWT } from 'jose';
import { createWorkloadCredentials } from '../dist/workload-credentials.js';

const issuer = 'https://identity.example.test/realms/local';
const resource = 'https://api.example.test';
const pair = await generateKeyPair('RS256');
async function fixture(options: { audience?: string; clientId?: string; kind?: 'human' | 'service'; scopes?: string; revoked?: boolean; endpoint?: string; failure?: boolean } = {}) {
  let requests = 0;
  const transport: typeof fetch = async (_url, init) => {
    assert.equal(init?.redirect, 'error');
    if (String(_url).includes('.well-known')) return Response.json({ issuer, token_endpoint: options.endpoint ?? `${issuer}/token` });
    requests++;
    const body = new URLSearchParams(init?.body as string);
    assert.equal(body.get('grant_type'), 'client_credentials');
    assert.equal(body.get('resource'), resource);
    assert.equal(body.get('scope'), 'library:read');
    assert.ok(body.get('client_assertion'));
    assert.equal(body.has('client_secret'), false);
    if (options.failure) return Response.json({ error: 'invalid_client', error_description: 'sensitive-provider-diagnostic' }, { status: 401 });
    const token = await new SignJWT({ typ: 'Bearer', azp: options.clientId ?? 'runner', scope: options.scopes ?? 'library:read' }).setProtectedHeader({ alg: 'RS256' })
      .setIssuer(issuer).setAudience(options.audience ?? resource).setSubject('runner').setIssuedAt().setExpirationTime('2m').sign(pair.privateKey);
    return Response.json({ access_token: token, token_type: 'Bearer', expires_in: 120 });
  };
  const client = await createWorkloadCredentials({ issuer, clientId: 'runner', privateKey: pair.privateKey, resources: [resource],
    verificationKey: pair.publicKey, profile: 'keycloak', transport,
    resolvePrincipal: async () => options.revoked ? null : ({ principalId: 'runner', kind: options.kind ?? 'service' }) });
  return { client, requests: () => requests };
}
test('asymmetric workload credentials are verified for one exact resource and current principal', async () => {
  const { client, requests } = await fixture();
  const result = await client.credentials({ resource, scopes: ['library:read'] });
  assert.equal(result.principal.kind, 'service');
  assert.equal(result.resource, resource);
  assert.equal(result.tokenType, 'Bearer');
  await client.credentials({ resource, scopes: ['library:read'] });
  assert.equal(requests(), 2);
});
test('unconfigured resource is denied before credential exchange', async () => {
  const { client, requests } = await fixture();
  await assert.rejects(client.credentials({ resource: 'https://another-market.test', scopes: ['library:read'] }));
  assert.equal(requests(), 0);
});
test('wrong audience, human principal, missing scope and revocation never produce credentials', async () => {
  for (const options of [{ audience: 'https://another-market.test' }, { clientId: 'other-client' }, { kind: 'human' as const }, { scopes: '' }, { revoked: true }]) {
    const { client } = await fixture(options);
    await assert.rejects(client.credentials({ resource, scopes: ['library:read'] }), { code: 'identity_authentication_failed' });
  }
});
test('provider failures are redacted and discovery cannot send assertions to another host', async () => {
  await assert.rejects(fixture({ endpoint: 'https://attacker.test/token' }), { code: 'identity_authentication_failed' });
  const { client } = await fixture({ failure: true });
  await assert.rejects(client.credentials({ resource, scopes: ['library:read'] }), error => error instanceof Error && !error.message.includes('sensitive-provider-diagnostic'));
});

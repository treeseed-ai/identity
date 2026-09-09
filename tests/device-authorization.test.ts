import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, SignJWT } from 'jose';
import { createDeviceAuthorizationClient } from '../dist/device-authorization.js';

const issuer = 'https://identity.example.test/realms/local', resource = 'https://api.example.test';
const pair = await generateKeyPair('RS256');
async function fixture(options: { error?: string; audience?: string; kind?: 'human' | 'service'; verification?: string; tokenEndpoint?: string } = {}) {
  let time = Date.now(), polls = 0;
  const transport: typeof fetch = async (url, init) => {
    assert.equal(init?.redirect, 'error');
    if (String(url).includes('.well-known')) return Response.json({ issuer, device_authorization_endpoint: `${issuer}/device`, token_endpoint: options.tokenEndpoint ?? `${issuer}/token` });
    const params = new URLSearchParams(init?.body as string);
    assert.equal(params.get('client_id'), 'cli');
    assert.equal(params.get('resource'), resource);
    assert.equal(params.has('client_secret'), false);
    if (String(url).endsWith('/device')) return Response.json({ device_code: 'private-device-code', user_code: 'ABCD', verification_uri: options.verification ?? `${issuer}/verify`, expires_in: 300, interval: 5 });
    polls++;
    assert.equal(params.get('device_code'), 'private-device-code');
    if (options.error) return Response.json({ error: options.error, error_description: 'sensitive diagnostic' }, { status: 400 });
    const access = await new SignJWT({ typ: 'Bearer', azp: 'cli', scope: 'library:read' }).setProtectedHeader({ alg: 'RS256' })
      .setIssuer(issuer).setAudience(options.audience ?? resource).setSubject('human').setIssuedAt().setExpirationTime('2m').sign(pair.privateKey);
    return Response.json({ access_token: access, token_type: 'Bearer', expires_in: 120, refresh_token: 'protected-refresh' });
  };
  const client = await createDeviceAuthorizationClient({ issuer, clientId: 'cli', resources: [resource], verificationKey: pair.publicKey,
    profile: 'keycloak', transport, now: () => time, resolvePrincipal: async () => ({ principalId: 'existing-user', kind: options.kind ?? 'human' }) });
  return { client, advance: (milliseconds: number) => { time += milliseconds; }, polls: () => polls };
}
test('device code stays private; polling is rate limited and authorization is single-use', async () => {
  const f = await fixture(), pending = await f.client.begin({ resource, scopes: ['library:read'] });
  assert.equal(JSON.stringify(pending).includes('private-device-code'), false);
  assert.equal((await pending.poll()).status, 'pending'); assert.equal(f.polls(), 0);
  f.advance(5000);
  const results = await Promise.all([pending.poll(), pending.poll()]);
  assert.equal(f.polls(), 1); assert.equal(results[1]?.status, 'pending');
  assert.equal(results[0]?.status, 'authorized');
  if (results[0]?.status === 'authorized') assert.equal(results[0].principal.principalId, 'existing-user');
  await assert.rejects(pending.poll());
});
test('pending and slow_down obey provider pacing without leaking diagnostics', async () => {
  for (const error of ['authorization_pending', 'slow_down']) {
    const f = await fixture({ error }), pending = await f.client.begin({ resource, scopes: [] });
    f.advance(5000); const result = await pending.poll(); assert.equal(result.status, 'pending');
    f.advance(error === 'slow_down' ? 9999 : 4999);
    await pending.poll(); assert.equal(f.polls(), 1);
    f.advance(1); await pending.poll(); assert.equal(f.polls(), 2);
    pending.cancel(); await assert.rejects(pending.poll());
  }
});
test('expiry, denial and cancellation are terminal', async () => {
  const f = await fixture(), expired = await f.client.begin({ resource, scopes: [] });
  f.advance(300000); assert.equal((await expired.poll()).status, 'expired'); assert.equal(f.polls(), 0);
  await assert.rejects(expired.poll());
  for (const error of ['access_denied', 'expired_token']) {
    const f = await fixture({ error }), pending = await f.client.begin({ resource, scopes: [] });
    f.advance(5000); assert.equal((await pending.poll()).status, error === 'access_denied' ? 'denied' : 'expired');
    await assert.rejects(pending.poll());
  }
});
test('wrong audience and non-human token are rejected and cannot be replayed', async () => {
  for (const options of [{ audience: 'https://other-market.test' }, { kind: 'service' as const }, { error: 'server_error' }]) {
    const f = await fixture(options), pending = await f.client.begin({ resource, scopes: ['library:read'] });
    f.advance(5000); await assert.rejects(pending.poll(), { code: 'identity_authentication_failed' });
    await assert.rejects(pending.poll());
  }
});
test('discovery, user verification and resource selection remain inside configured authority', async () => {
  await assert.rejects(fixture({ tokenEndpoint: 'https://attacker.test/token' }));
  const bad = await fixture({ verification: 'https://attacker.test/approve' });
  await assert.rejects(bad.client.begin({ resource, scopes: [] }));
  const f = await fixture(); await assert.rejects(f.client.begin({ resource: 'https://another.test', scopes: [] }));
});

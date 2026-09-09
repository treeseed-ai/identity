import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createKeycloakApplicationRegistry, type KeycloakApplication } from '../dist/keycloak-clients.js';

const issuer = 'https://identity.test/realms/local';
const application: KeycloakApplication = { clientId: 'admin-browser', kind: 'browser', resource: 'https://api.test',
  scopes: ['read'], certificate: 'A'.repeat(128), redirectUris: ['https://admin.test/auth/callback'] };
function fixture() {
  let record: Record<string, any> | null = null;
  const requests: { url: string; method: string; body?: Record<string, any> }[] = [];
  const registry = createKeycloakApplicationRegistry({ issuer,
    credentials: { async token(input) {
      assert.deepEqual(input, { resource: 'https://identity.test/admin/realms/local', scopes: [] }); return 'synthetic-token';
    } }, transport: async (url, init) => {
      assert.equal(init?.redirect, 'error'); assert.equal(init?.credentials, 'omit');
      assert.equal(new Headers(init?.headers).get('authorization'), 'Bearer synthetic-token');
      const request = { url: String(url), method: init?.method ?? 'GET', ...(init?.body ? { body: JSON.parse(String(init.body)) } : {}) };
      requests.push(request);
      if (request.method === 'POST') { record = { ...request.body, id: 'generated-id' }; return new Response(null, { status: 201 }); }
      return Response.json(record ? [record] : []);
    },
  });
  return { registry, requests, setRecord: (value: Record<string, any>) => { record = value; }, record: () => record! };
}
test('registers only public client metadata, reads back, and repeats noop', async () => {
  const f = fixture();
  assert.deepEqual(await f.registry.ensure(application), { action: 'create', clientId: application.clientId, id: 'generated-id' });
  assert.deepEqual(await f.registry.ensure(application), { action: 'noop', clientId: application.clientId, id: 'generated-id' });
  assert.equal(f.requests.filter(value => value.method === 'POST').length, 1);
  assert.equal(f.record().directAccessGrantsEnabled, false); assert.equal(f.record().implicitFlowEnabled, false);
  assert.equal(f.record().fullScopeAllowed, false); assert.equal(f.record().clientAuthenticatorType, 'client-jwt');
  assert.deepEqual(f.record().defaultClientScopes, ['basic']);
  assert.equal(JSON.stringify(f.requests).includes('synthetic-token'), false);
});
test('never adopts unmanaged existing clients or overwrites drift', async () => {
  const f = fixture(); f.setRecord({ id: 'existing', clientId: application.clientId, attributes: {} });
  await assert.rejects(f.registry.ensure(application), /not managed/); assert.equal(f.requests.length, 1);
  const managed = fixture(); await managed.registry.ensure(application);
  managed.record().directAccessGrantsEnabled = true;
  await assert.rejects(managed.registry.ensure(application), /drift in directAccessGrantsEnabled/);
  assert.equal(managed.requests.filter(value => value.method !== 'GET').length, 1);
});
test('rejects broadened audiences and scope grants on read-back', async () => {
  const f = fixture(); await f.registry.ensure(application);
  f.record().protocolMappers.push({ name: 'foreign-resource', protocol: 'openid-connect', protocolMapper: 'oidc-audience-mapper', config: {} });
  await assert.rejects(f.registry.ensure(application), /drift/);
});
test('declares real Keycloak mapper defaults and ignores only its generated mapper ID', async () => {
  const f = fixture(); await f.registry.ensure(application);
  const mapper = f.record().protocolMappers[0];
  assert.equal(mapper.consentRequired, false);
  assert.equal(mapper.config['userinfo.token.claim'], 'false');
  mapper.id = 'keycloak-generated-mapper-id';
  assert.equal((await f.registry.ensure(application)).action, 'noop');
  mapper.config['userinfo.token.claim'] = 'true';
  await assert.rejects(f.registry.ensure(application), /drift in protocolMappers/);
  mapper.config['userinfo.token.claim'] = 'false'; mapper.consentRequired = true;
  await assert.rejects(f.registry.ensure(application), /drift in protocolMappers/);
  assert.equal(f.requests.filter(value => value.method === 'POST').length, 1);
});
test('declares the Keycloak service-account scope only for asymmetric workload clients', async () => {
  const f = fixture();
  const workload = { ...application, kind: 'workload' as const, redirectUris: [] };
  await f.registry.ensure(workload);
  assert.deepEqual(f.record().defaultClientScopes, ['basic', 'service_account']);
  assert.equal((await f.registry.ensure(workload)).action, 'noop');
  f.record().defaultClientScopes.push('roles');
  await assert.rejects(f.registry.ensure(workload), /drift in defaultClientScopes/);
});
test('denies invalid redirects, direct secrets, privileged scopes and workload browser flows before transport', async () => {
  for (const input of [
    { ...application, redirectUris: ['https://admin.test/*'] },
    { ...application, redirectUris: ['http://admin.test/callback'] },
    { ...application, certificate: '-----BEGIN PRIVATE KEY-----' },
    { ...application, scopes: ['offline_access'] },
    { ...application, kind: 'workload' as const },
    { ...application, clientId: 'treeseed-identity-reconciler' },
  ]) { const f = fixture(); await assert.rejects(f.registry.ensure(input)); assert.equal(f.requests.length, 0); }
});
test('redacts provider and credential failures and refuses redirects', async () => {
  for (const source of ['credential', 'transport', 'redirect', 'oversized']) {
    const registry = createKeycloakApplicationRegistry({ issuer,
      credentials: { async token() { if (source === 'credential') throw new Error('private-material'); return 'synthetic-token'; } },
      transport: async () => {
        if (source === 'transport') throw new Error('private-material');
        if (source === 'oversized') return new Response('A'.repeat(262145));
        return new Response(null, { status: 302, headers: { location: 'https://foreign.test' } });
      },
    });
    await assert.rejects(registry.ensure(application), error => error instanceof Error && error.message === 'Identity application registry unavailable');
  }
});

test('registers public native PKCE and device clients with no client key or password grant', async () => {
  for (const redirectUris of [['http://127.0.0.1/callback'], ['http://[::1]/callback'], []]) {
    const f = fixture();
    const native: KeycloakApplication = { clientId: 'trsd', kind: 'native', resource: application.resource,
      scopes: ['read'], redirectUris, deviceAuthorization: true };
    assert.equal((await f.registry.ensure(native)).action, 'create');
    assert.equal((await f.registry.ensure(native)).action, 'noop');
    const record = f.record();
    assert.equal(record.publicClient, true); assert.equal(record.serviceAccountsEnabled, false);
    assert.equal(record.standardFlowEnabled, redirectUris.length > 0);
    assert.equal(record.directAccessGrantsEnabled, false); assert.equal(record.implicitFlowEnabled, false);
    assert.equal(record.attributes['pkce.code.challenge.method'], 'S256');
    assert.equal(record.attributes['oauth2.device.authorization.grant.enabled'], 'true');
    assert.equal(record.attributes['jwt.credential.certificate'], undefined);
    assert.equal(record.secret, undefined); assert.equal(record.consentRequired, true);
    assert.deepEqual(record.defaultClientScopes, ['basic']);
    record.publicClient = false;
    await assert.rejects(f.registry.ensure(native), /drift/);
  }
});

test('rejects nonliteral or broadened native callbacks before credential or HTTP access', async () => {
  for (const redirectUris of [['https://admin.test/callback'], ['http://localhost/callback'], ['http://127.0.0.1:*/*'],
    ['http://127.0.0.1:1234/callback'], ['http://127.0.0.1/callback?next=foreign'], ['http://127.0.0.1/../callback'], ['http://user@127.0.0.1/callback']]) {
    const f = fixture();
    await assert.rejects(f.registry.ensure({ clientId: 'trsd', kind: 'native', resource: application.resource,
      scopes: [], redirectUris, deviceAuthorization: true }));
    assert.equal(f.requests.length, 0);
  }
  const f = fixture();
  await assert.rejects(f.registry.ensure({ clientId: 'trsd', kind: 'native', resource: application.resource,
    scopes: [], redirectUris: [], deviceAuthorization: false }));
  assert.equal(f.requests.length, 0);
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createKeycloakAccountImporter, type KeycloakAccountImport } from '../dist/keycloak-account-import.js';

const input: KeycloakAccountImport = { sourceResource: 'https://api.example', sourceUserId: 'existing-user',
  username: 'person', email: 'person@example.test', emailVerified: true,
  credential: { type: 'password', temporary: false, credentialData: '{"algorithm":"pbkdf2-sha256"}', secretData: '{"value":"synthetic-verifier"}' } };
function fixture() {
  let profile: Record<string, unknown> = { attributes: [{ name: 'email' }] };
  const records: Array<Record<string, unknown>> = [], calls: Array<{ path: string; method: string; body: unknown }> = [];
  let failReadback = false;
  const transport: typeof fetch = async (url, init) => {
    const value = new URL(String(url));
    assert.equal(value.origin, 'https://identity.example');
    assert.equal(init?.redirect, 'error');
    const path = value.pathname, method = init?.method ?? 'GET';
    const body: unknown = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
    calls.push({ path, method, body });
    if (path.endsWith('/users/profile')) {
      if (method === 'PUT') { profile = body as Record<string, unknown>; return new Response(null, { status: 204 }); }
      return Response.json(profile);
    }
    if (method === 'POST') {
      records.push({ ...body as Record<string, unknown>, id: 'authoritative-subject' });
      return new Response(null, { status: 201 });
    }
    if (failReadback && records.length) { failReadback = false; return new Response(null, { status: 503 }); }
    const q = value.searchParams.get('q');
    return Response.json(records.filter(record => q
      ? (record.attributes as Record<string, string[]> | undefined)?.treeseedSourceAccount?.[0] === q.split(':')[1]
      : record.username === value.searchParams.get('username') || record.email === value.searchParams.get('email')));
  };
  return { records, calls, profile: (value: Record<string, unknown>) => { profile = value; },
    fail: () => { failReadback = true; },
    importer: createKeycloakAccountImporter({ issuer: 'https://identity.example/realms/treeseed', transport,
      credentials: { token: async request => { assert.deepEqual(request, { resource: 'https://identity.example/admin/realms/treeseed', scopes: [] }); return 'synthetic-token'; } } }) };
}

test('imports a supported verifier once, preserves the source identity and never overwrites it on replay', async () => {
  const f = fixture();
  const created = await f.importer.importAccount(input);
  assert.deepEqual(created, { issuer: 'https://identity.example/realms/treeseed', subject: 'authoritative-subject', sourceUserId: 'existing-user', action: 'create' });
  assert.equal((await f.importer.importAccount(input)).action, 'noop');
  assert.equal(f.calls.filter(call => call.path.endsWith('/users') && call.method === 'POST').length, 1);
  assert.deepEqual(f.records[0]?.credentials, [input.credential]);
  assert.equal(JSON.stringify(created).includes('synthetic'), false);
  assert.equal(JSON.stringify(created).includes(input.email), false);
});

test('recovers a create whose authoritative read-back was interrupted', async () => {
  const f = fixture(); f.fail();
  await assert.rejects(f.importer.importAccount(input), /request failed/);
  assert.equal((await f.importer.importAccount(input)).action, 'noop');
  assert.equal(f.records.length, 1);
});

test('never links by a matching username or email', async () => {
  for (const collision of [{ username: input.username }, { email: input.email }]) {
    const f = fixture(); f.records.push({ id: 'someone-else', enabled: true, ...collision });
    await assert.rejects(f.importer.importAccount(input), /explicit account linking/);
    assert.equal(f.calls.filter(call => call.method === 'POST').length, 0);
  }
});

test('rejects a user-editable ownership marker and disabled imported identity', async () => {
  const f = fixture();
  f.profile({ attributes: [{ name: 'treeseedSourceAccount', permissions: { view: ['admin'], edit: ['user', 'admin'] } }] });
  await assert.rejects(f.importer.importAccount(input), /administrator-only/);
  const ready = fixture(); await ready.importer.importAccount(input); ready.records[0]!.enabled = false;
  await assert.rejects(ready.importer.importAccount(input), /ownership read-back/);
});

test('keeps distinct source resources separate despite matching local IDs', async () => {
  const f = fixture(); await f.importer.importAccount(input);
  await assert.rejects(f.importer.importAccount({ ...input, sourceResource: 'https://another-api.example' }), /explicit account linking/);
});

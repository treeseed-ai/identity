import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ensureManagedScopes } from '../dist/keycloak-scopes.js';

function fixture() {
  const scopes: Record<string, any>[] = [];
  const writes: unknown[] = [];
  let grants: unknown = {};
  let persist = true;
  const request = async (path: string, method = 'GET', body?: unknown) => {
    if (path.endsWith('/scope-mappings')) return grants;
    assert.equal(path, 'client-scopes');
    if (method === 'POST') {
      writes.push(body);
      if (persist) scopes.push({ ...(body as object), id: `scope-${scopes.length}` });
      return;
    }
    return structuredClone(scopes);
  };
  return { scopes, writes, request, setGrants(value: unknown) { grants = value; }, dropWrites() { persist = false; } };
}

test('creates permission labels without role or claim grants and repeats without writes', async () => {
  const f = fixture();
  f.scopes.push({ id: 'builtin', name: 'profile', protocol: 'openid-connect' });
  await ensureManagedScopes(f.request, ['treeseed:read', 'treeseed:execution']);
  await ensureManagedScopes(f.request, ['treeseed:read', 'treeseed:execution']);
  assert.equal(f.writes.length, 2);
  assert.deepEqual(f.scopes[0], { id: 'builtin', name: 'profile', protocol: 'openid-connect' });
  assert.deepEqual(f.scopes[1].protocolMappers, []);
});

test('rejects reserved or malformed labels before transport', async () => {
  for (const label of ['openid', 'profile', 'roles', 'offline_access', 'scope space', '*', 'x'.repeat(129)]) {
    let requests = 0;
    await assert.rejects(ensureManagedScopes(async () => { requests++; }, [label]));
    assert.equal(requests, 0);
  }
});

test('preflights all existing scope definitions before creating any missing ones', async () => {
  const f = fixture();
  f.scopes.push({ id: 'unmanaged', name: 'existing', protocol: 'openid-connect' });
  await assert.rejects(ensureManagedScopes(f.request, ['missing', 'existing']), /custody or policy drift/);
  assert.equal(f.writes.length, 0);
});

test('rejects injected claims, realm roles and client roles', async () => {
  for (const grants of [{ realmMappings: [{ id: 'role' }] }, { clientMappings: { api: {} } }, { unknown: true }, []]) {
    const f = fixture(); await ensureManagedScopes(f.request, ['read']);
    f.setGrants(grants);
    await assert.rejects(ensureManagedScopes(f.request, ['missing', 'read']));
    assert.equal(f.writes.length, 1);
  }
  const f = fixture(); await ensureManagedScopes(f.request, ['read']);
  f.scopes[0].protocolMappers.push({ protocolMapper: 'oidc-usermodel-attribute-mapper' });
  await assert.rejects(ensureManagedScopes(f.request, ['read']), /policy drift/);
});

test('requires authoritative creation read-back and unique names', async () => {
  const f = fixture(); f.dropWrites();
  await assert.rejects(ensureManagedScopes(f.request, ['read']), /policy drift/);
  const duplicate = fixture(); await ensureManagedScopes(duplicate.request, ['read']);
  duplicate.scopes.push({ ...duplicate.scopes[0], id: 'second' });
  await assert.rejects(ensureManagedScopes(duplicate.request, ['read']), /Ambiguous/);
});

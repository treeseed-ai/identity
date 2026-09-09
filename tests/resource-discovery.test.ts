import { test } from 'node:test';
import assert from 'node:assert/strict';
import { discoverResourceAuthorization } from '../dist/resource-discovery.js';

const resource = 'https://api.example.test/mcp', issuer = 'https://identity.example.test/realms/local';
function transport(metadata: Record<string, unknown>, status = 200): typeof fetch {
  return async (url, init) => {
    assert.equal(String(url), 'https://api.example.test/.well-known/oauth-protected-resource/mcp');
    assert.equal(init?.redirect, 'error'); assert.equal(init?.credentials, 'omit');
    assert.equal(new Headers(init?.headers).has('authorization'), false);
    return Response.json(metadata, { status });
  };
}
const metadata = { resource, authorization_servers: [issuer], bearer_methods_supported: ['header'], scopes_supported: ['custom:read'] };
test('discovers exact path-qualified resource using credential-free metadata', async () => {
  assert.deepEqual(await discoverResourceAuthorization({ resource, transport: transport(metadata) }), { resource, issuer, scopesSupported: ['custom:read'] });
});
test('multiple issuers require an explicit advertised selection; no transitive traversal', async () => {
  const metadata = { resource, authorization_servers: [issuer, 'https://sovereign.test/realms/local'] };
  await assert.rejects(discoverResourceAuthorization({ resource, transport: transport(metadata) }), { reason: 'issuer_selection_required' });
  assert.equal((await discoverResourceAuthorization({ resource, issuer, transport: transport(metadata) })).issuer, issuer);
  await assert.rejects(discoverResourceAuthorization({ resource, issuer: 'https://untrusted.test', transport: transport(metadata) }), { reason: 'issuer_not_advertised' });
});
test('wrong resource, token query transport, errors and oversized metadata fail closed', async () => {
  for (const changed of [{ resource: 'https://other.test' }, { bearer_methods_supported: ['query'] }, { padding: 'x'.repeat(65536) }])
    await assert.rejects(discoverResourceAuthorization({ resource, transport: transport({ ...metadata, ...changed }) }));
  await assert.rejects(discoverResourceAuthorization({ resource, transport: transport({ error: 'private diagnostic' }, 500) }), { code: 'identity_authentication_failed' });
});

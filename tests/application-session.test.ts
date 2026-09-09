import assert from 'node:assert/strict';
import test from 'node:test';
import { createApplicationSession } from '../dist/application-session.js';

const resource = 'https://api.example.test', issuer = 'https://identity.example.test';
const session = 's'.repeat(43), binding = 'b'.repeat(43);
function fixture(extra: { foreignResource?: boolean; failure?: boolean; redirect?: boolean } = {}) {
  const calls: Array<{ url: string; body: Record<string, string> }> = [];
  const adapter = createApplicationSession({ resource, issuer, callbackUrl: 'https://admin.example.test/auth/callback', afterLogin: '/app/', cookieName: '__Host-admin-session',
    credentials: { async token(request) { assert.deepEqual(request, { resource, scopes: ['treeseed:identity:sessions'] }); return 'private-workload'; } },
    transport: async (input, init) => {
      assert.equal(init?.credentials, 'omit'); assert.equal(init?.redirect, 'error');
      assert.equal(new Headers(init?.headers).get('authorization'), 'Bearer private-workload');
      const url = String(input), body = JSON.parse(String(init?.body)) as Record<string, string>; calls.push({ url, body });
      if (extra.redirect) return new Response(null, { status: 302, headers: { location: 'https://attacker.test' } });
      if (extra.failure) return Response.json({ error: 'private-error-detail' }, { status: 503 });
      let data: object;
      if (url.endsWith('/begin')) { assert.match(body.browserBinding!, /^[A-Za-z0-9_-]{43}$/u); data = { authorizationUrl: `${issuer}/auth?state=private-state` }; }
      else if (url.endsWith('/finish')) data = { handle: session, expiresAt: new Date(Date.now() + 3600000).toISOString() };
      else if (url.endsWith('/logout')) data = { loggedOut: true, upstreamRevoked: true };
      else data = { accessToken: 'private-access', resource: extra.foreignResource ? 'https://other-api.test' : resource, expiresAt: Date.now() + 60000,
        principal: { principalId: 'user', kind: 'human', identity: { issuer, subject: 'subject' }, audience: resource, scopes: ['read'] } };
      return Response.json({ data });
    } });
  return { adapter, calls };
}
test('login and callback expose opaque host-only cookies, never access/refresh/workload tokens', async () => {
  const f = fixture(), login = await f.adapter.login(new Request('https://admin.example.test/auth/sign-in'));
  assert.equal(login.status, 303); assert.equal(login.headers.get('cache-control'), 'no-store');
  const cookie = login.headers.getSetCookie()[0]!;
  assert.match(cookie, /^__Host-admin-session-login=[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Lax; Max-Age=300$/u);
  assert.equal(cookie.includes('Domain='), false);
  const response = await f.adapter.callback(new Request('https://admin.example.test/auth/callback?code=one-time&state=state', { headers: { cookie: `__Host-admin-session-login=${binding}` } }));
  assert.equal(response.headers.get('location'), 'https://admin.example.test/app/');
  assert.ok(response.headers.getSetCookie().some(value => value.startsWith(`__Host-admin-session=${session};`)));
  assert.equal((await response.text()).length, 0);
  const headers: string[] = []; response.headers.forEach(value => headers.push(value));
  for (const token of ['private-workload', 'private-access', 'refresh']) assert.equal(JSON.stringify(headers).includes(token), false);
});
test('session credentials remain server-side and cannot cross API resources', async () => {
  const request = new Request('https://admin.example.test/app/', { headers: { cookie: `__Host-admin-session=${session}` } });
  assert.equal((await fixture().adapter.session(request))?.accessToken, 'private-access');
  await assert.rejects(fixture({ foreignResource: true }).adapter.session(request));
  const f = fixture(); assert.equal(await f.adapter.session(new Request('https://admin.example.test/app/')), null); assert.equal(f.calls.length, 0);
});
test('same-origin navigation survives sign-in and is bound to this login attempt', async () => {
  const f = fixture();
  const login = await f.adapter.login(new Request('https://admin.example.test/auth/sign-in'), '/team-invites/example/accept');
  const cookies = login.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
  const result = await f.adapter.callback(new Request('https://admin.example.test/auth/callback?code=code&state=state', { headers: { cookie: cookies } }));
  assert.equal(result.headers.get('location'), 'https://admin.example.test/team-invites/example/accept');
  await assert.rejects(f.adapter.callback(new Request('https://admin.example.test/auth/callback?code=code&state=state', {
    headers: { cookie: cookies.replace(/-login=[^;]+/u, `-login=${binding}`) },
  })));
  for (const destination of ['https://attacker.test/', '//attacker.test/', '\\\\attacker.test/'])
    await assert.rejects(f.adapter.login(new Request('https://admin.example.test/auth/sign-in'), destination));
  const switchAccount = await f.adapter.login(new Request('https://admin.example.test/auth/sign-in'), '/app/', { promptForLogin: true });
  assert.equal(new URL(switchAccount.headers.get('location')!).searchParams.get('prompt'), 'login');
});
test('logout requires same-origin POST and removes only application cookies', async () => {
  const f = fixture(), headers = { cookie: `__Host-admin-session=${session}` };
  for (const request of [new Request('https://admin.example.test/auth/logout', { headers }), new Request('https://admin.example.test/auth/logout', { method: 'POST', headers: { ...headers, origin: 'https://attacker.test' } })])
    await assert.rejects(f.adapter.logout(request));
  assert.equal(f.calls.length, 0);
  const result = await f.adapter.logout(new Request('https://admin.example.test/auth/logout', { method: 'POST', headers: { ...headers, origin: 'https://admin.example.test' } }));
  assert.ok(result.headers.getSetCookie().every(value => value.includes('Max-Age=0')));
});
test('duplicate cookies, wrong callback hosts and bridge redirects/errors fail closed', async () => {
  await assert.rejects(fixture().adapter.session(new Request('https://admin.example.test/app/', { headers: { cookie: `__Host-admin-session=${session}; __Host-admin-session=${binding}` } })));
  await assert.rejects(fixture().adapter.callback(new Request('https://attacker.test/auth/callback')));
  for (const extra of [{ failure: true }, { redirect: true }]) {
    await assert.rejects(fixture(extra).adapter.login(new Request('https://admin.example.test/auth/sign-in')), error => error instanceof Error && !error.message.includes('private-error-detail'));
  }
});

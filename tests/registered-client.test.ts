import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeyPair, SignJWT } from 'jose';
import { createAccessTokenVerifier } from '../dist/index.js';

for (const profile of ['keycloak', 'rfc9068'] as const) {
  test(`${profile}: workload registration binds the originating client, not claims or email`, async () => {
    const keys = await generateKeyPair('RS256');
    const issuer = 'https://identity.example.test', audience = 'https://api.example.test';
    const verify = createAccessTokenVerifier({ issuer, audience, profile, verificationKey: keys.publicKey,
      resolvePrincipal: async identity => identity.subject === 'registered-subject'
        ? { principalId: 'preserved-service', kind: 'service', clientId: 'registered-client' } : null });
    const token = (client?: string, subject = 'registered-subject') => new SignJWT({ typ: 'Bearer',
      scope: 'read', ...(client ? { [profile === 'keycloak' ? 'azp' : 'client_id']: client } : {}),
      email: 'owner@example.test', roles: ['administrator'] })
      .setProtectedHeader({ alg: 'RS256', typ: profile === 'rfc9068' ? 'at+jwt' : 'JWT' })
      .setIssuer(issuer).setAudience(audience).setSubject(subject).setIssuedAt().setExpirationTime('1m').sign(keys.privateKey);
    const principal = await verify(await token('registered-client'));
    assert.equal(principal.principalId, 'preserved-service');
    assert.equal(principal.kind, 'service');
    assert.deepEqual(principal.scopes, ['read']);
    for (const value of [await token(), await token('other-client'), await token('registered-client', 'unregistered')]) {
      await assert.rejects(verify(value), { code: 'identity_authentication_failed' });
    }
  });
}

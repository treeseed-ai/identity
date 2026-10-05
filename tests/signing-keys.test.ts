import assert from 'node:assert/strict';
import { test } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT, jwtVerify } from 'jose';
import { discoverSigningKeys } from '../dist/signing-keys.js';

const issuer = 'https://identity.example.test/realms/local', endpoint = `${issuer}/certs`;
const pair = await generateKeyPair('RS256');
const publicKey = {...await exportJWK(pair.publicKey), kid:'first'};
const signed = () => new SignJWT({}).setProtectedHeader({alg:'RS256', kid:'first'}).sign(pair.privateKey);

test('issuer-local keys are credential-free, cached, and isolated between resolvers', async () => {
  let reads = 0;
  const transport: typeof fetch = async (url, init) => {
    assert.equal(init?.redirect, 'error'); assert.equal(init?.credentials, 'omit');
    assert.equal(new Headers(init?.headers).has('authorization'), false);
    if (String(url) === endpoint) { reads++; return Response.json({keys:[publicKey]}); }
    return Response.json({issuer, jwks_uri:endpoint});
  };
  const keys = await discoverSigningKeys({issuer, transport});
  await jwtVerify(await signed(), keys); await jwtVerify(await signed(), keys);
  assert.equal(reads,1);
  const independent = await discoverSigningKeys({issuer, transport});
  await jwtVerify(await signed(), independent); assert.equal(reads,2);
});

test('signing-key rotation refreshes expired cache', async context => {
  context.mock.timers.enable({apis:['Date'], now: Date.now()});
  let reads = 0;
  const rotated = await generateKeyPair('RS256');
  const keys = await discoverSigningKeys({issuer, transport:async url => {
    if (String(url) !== endpoint) return Response.json({issuer, jwks_uri:endpoint});
    reads++;
    return Response.json({keys:reads === 1 ? [publicKey] : [{...await exportJWK(rotated.publicKey), kid:'next'}]});
  }});
  await jwtVerify(await signed(), keys);
  context.mock.timers.tick(60001);
  await jwtVerify(await new SignJWT({}).setProtectedHeader({alg:'RS256', kid:'next'}).sign(rotated.privateKey), keys);
  assert.equal(reads,2);
  await assert.rejects(jwtVerify(await signed(), keys));
});

test('untrusted discovery, redirect, oversized and private key sets fail closed', async () => {
  for (const metadata of [{issuer:'https://wrong.test', jwks_uri:endpoint}, {issuer, jwks_uri:'https://untrusted.test/keys'}])
    await assert.rejects(discoverSigningKeys({issuer, transport:async()=>Response.json(metadata)}));
  for (const payload of [{keys:[{...publicKey,d:'private'}]}, {keys:Array(33).fill(publicKey)}, {padding:'x'.repeat(131073)}]) {
    const keys = await discoverSigningKeys({issuer, transport:async url => Response.json(String(url) === endpoint ? payload : {issuer, jwks_uri:endpoint})});
    await assert.rejects(jwtVerify(await signed(), keys), {code:'identity_authentication_failed'});
  }
  await assert.rejects(discoverSigningKeys({issuer, transport:async()=>new Response(null,{status:302,headers:{location:'https://other.test'}})}));
});

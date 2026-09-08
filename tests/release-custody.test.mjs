import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { releaseRoute, verifyEvidence } from '../scripts/release-custody.mjs';

test('only numbered RC and stable versions select their matching protected branch', () => {
  assert.deepEqual(releaseRoute('0.1.0-rc.2'), { branch: 'staging', channel: 'rc' });
  assert.deepEqual(releaseRoute('1.0.0'), { branch: 'main', channel: 'latest' });
  for (const value of ['1.0.0-beta.1', 'v1.0.0', '1.0.0-rc', '1.0.0+meta', '', 'staging']) assert.throws(() => releaseRoute(value));
});

test('custody rejects moved commits, versions, missing SBOM, path escapes and tampering', () => {
  const bytes = Buffer.from('sealed artifact');
  const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  const commit = 'a'.repeat(40);
  const version = '0.1.0-rc.2';
  const time = '2026-01-01T00:00:00.000Z';
  const evidence = {
    schemaVersion: 'treeseed.release-evidence/v1',
    candidate: { id: 'candidate-test', receiptDigest: digest, sourceCommit: commit, stagingRef: 'refs/heads/staging', workflowRunId: '1', createdAt: time },
    packages: [{ projectId: 'identity', name: '@treeseed/identity', version, minimumBump: 'patch' }],
    artifacts: ['npm-package', 'sbom'].map(kind => ({ id: kind, kind, identity: `${kind}.bin`, mediaType: 'application/octet-stream', digest, size: bytes.length })),
    contractBundles: [], compatibilityAttestations: [], verification: { status: 'passed', operations: ['npm run verify'], completedAt: time },
  };
  const options = { commit, version, read: () => bytes };
  assert.doesNotThrow(() => verifyEvidence(evidence, options));
  assert.throws(() => verifyEvidence(evidence, { ...options, commit: 'b'.repeat(40) }));
  assert.throws(() => verifyEvidence(evidence, { ...options, version: '1.0.0' }));
  assert.throws(() => verifyEvidence(evidence, { ...options, read: () => Buffer.from('tampered') }));
  assert.throws(() => verifyEvidence({ ...evidence, artifacts: evidence.artifacts.slice(0, 1) }, options));
  const escaped = structuredClone(evidence);
  escaped.artifacts[0].identity = '../secret';
  assert.throws(() => verifyEvidence(escaped, options));
  const names = [];
  verifyEvidence(evidence, { ...options, readback: true, read: name => { names.push(name); return bytes; } });
  assert.deepEqual(names, ['npm-package.bin']);
});

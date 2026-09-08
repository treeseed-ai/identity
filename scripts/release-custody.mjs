import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, statSync } from 'node:fs';
import { basename, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { releaseEvidenceSchema } from '@treeseed/sdk/development';

export function releaseRoute(version) {
  if (/^\d+\.\d+\.\d+-rc\.\d+$/.test(version)) return { branch: 'staging', channel: 'rc' };
  if (/^\d+\.\d+\.\d+$/.test(version)) return { branch: 'main', channel: 'latest' };
  throw new Error('Only exact stable or numbered RC versions may publish.');
}

export function verifyEvidence(evidence, { commit, version, read, readback = false }) {
  evidence = releaseEvidenceSchema.parse(evidence);
  if (evidence.candidate.sourceCommit !== commit) throw new Error('Candidate commit mismatch.');
  if (evidence.packages.length !== 1 || evidence.packages[0].name !== '@treeseed/identity' || evidence.packages[0].version !== version) throw new Error('Candidate package mismatch.');
  if (evidence.artifacts.length !== 2 || !evidence.artifacts.some(a => a.kind === 'npm-package') || !evidence.artifacts.some(a => a.kind === 'sbom')) throw new Error('Missing package/SBOM custody.');
  for (const artifact of evidence.artifacts) {
    if (basename(artifact.identity) !== artifact.identity) throw new Error('Unsafe artifact path.');
    if (readback && artifact.kind !== 'npm-package') continue;
    const bytes = read(artifact.identity);
    if (digest(bytes) !== artifact.digest || bytes.length !== artifact.size) throw new Error('Artifact digest/size mismatch.');
  }
}
const digest = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const command = process.argv[2];
  const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
  const route = releaseRoute(pkg.version);
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
  const directory = resolve(root, 'candidate');
  const evidencePath = resolve(directory, 'release-evidence-v1.json');
  if (process.env.GITHUB_REF?.startsWith('refs/tags/')) {
    if (process.env.GITHUB_REF_NAME !== pkg.version) throw new Error('Tag/version mismatch.');
    const head = execFileSync('git', ['rev-parse', `origin/${route.branch}`], { cwd: root, encoding: 'utf8' }).trim();
    if (head !== commit) throw new Error('Protected head moved.');
  }
  if (command === 'seal') {
    const artifacts = [
      ['npm-package', `treeseed-identity-${pkg.version}.tgz`, 'application/gzip'],
      ['sbom', 'sbom.cdx.json', 'application/vnd.cyclonedx+json'],
    ].map(([kind, identity, mediaType]) => ({ id: `identity-${kind}`, kind, identity, mediaType, digest: digest(readFileSync(resolve(directory, identity))), size: statSync(resolve(directory, identity)).size }));
    const now = new Date().toISOString();
    const evidence = releaseEvidenceSchema.parse({ schemaVersion: 'treeseed.release-evidence/v1', candidate: { id: `candidate-${commit.slice(0, 12)}`, receiptDigest: digest(`${commit}\n${artifacts.map(a => a.digest).join('\n')}`), sourceCommit: commit, stagingRef: process.env.GITHUB_REF ?? 'refs/heads/staging', workflowRunId: process.env.GITHUB_RUN_ID ?? '1', createdAt: now }, packages: [{ projectId: 'identity', name: pkg.name, version: pkg.version, minimumBump: 'patch' }], artifacts, contractBundles: [], compatibilityAttestations: [], verification: { status: 'passed', operations: ['npm run verify'], completedAt: now } });
    writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
  } else if (command === 'verify' || command === 'readback') {
    verifyEvidence(JSON.parse(readFileSync(evidencePath, 'utf8')), { commit, version: pkg.version, readback: command === 'readback', read: name => readFileSync(resolve(root, command === 'readback' ? 'readback' : 'candidate', name)) });
  } else throw new Error('Expected seal, verify or readback.');
}

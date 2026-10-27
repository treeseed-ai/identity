import { test, expect } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { IdentityProtocol } from '../../src/identity.js';
export class SelectedEndpointTests {
    protected readonly configuration = { installationId: 'endpoint-fixture', origin: 'https://localhost:58443', issuer: 'https://localhost:58443/identity/realms/cordis', identityInternalOrigin: 'http://issuer-17:9090', clientId: 'cordis-admin', clientSecret: 'IDENTITY_SECRET_CANARY', databaseUrl: 'postgresql://fixture', bootstrapSubject: 'fixture-subject', workerSocket: '/fixture/host.sock', assetDigest: 'a'.repeat(64) };
}

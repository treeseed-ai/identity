import { test, expect } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { IdentityProtocol } from '../../src/identity.js';
import {SelectedEndpointTests} from '../support/selected-endpoint-test-support.js';
class SelectedEndpointTestsUnit extends SelectedEndpointTests {

    denied(): void { for (const endpoint of ['https://issuer-17:9090', 'http://issuer.example:9090', 'http://127.0.0.1:9090', 'http://user:pass@issuer-17:9090', 'http://issuer-17:9090/path', 'http://issuer-17:9090/?q=CANARY', 'http://issuer-17:9090/#CANARY']) expect(IdentityProtocol.validateConfiguration.bind(IdentityProtocol, { ...this.configuration, identityInternalOrigin: endpoint })).toThrow(); for (const issuer of ['https://elsewhere.invalid/identity/realms/cordis', this.configuration.issuer + '?q=CANARY', this.configuration.issuer + '#CANARY', 'https://user:pass@localhost:58443/identity/realms/cordis']) expect(IdentityProtocol.validateConfiguration.bind(IdentityProtocol, { ...this.configuration, issuer })).toThrow(); }
}
const selectedEndpoints=new SelectedEndpointTestsUnit();
test('unit: selected OIDC endpoint still refuses unbound public authority and URL credentials or state', selectedEndpoints.denied.bind(selectedEndpoints));

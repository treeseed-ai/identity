import { test, expect } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { IdentityProtocol } from '../../src/identity.js';
import {SelectedEndpointTests} from '../support/selected-endpoint-test-support.js';
class SelectedEndpointTestsAcceptance extends SelectedEndpointTests {

    program(): void { const code = "import {IdentityProtocol} from '@treeseed-cordis/identity';class Program{static run(){const settings=JSON.parse(process.argv[1]);for(const endpoint of ['http://issuer-17:9090','http://issuer-17:80','http://identity:8080'])new IdentityProtocol({...settings,identityInternalOrigin:endpoint});process.stdout.write('selected-identity-endpoint-ok\\n');}}Program.run();", result = spawnSync('node', ['--input-type=module', '-e', code, JSON.stringify(this.configuration)], { encoding: 'utf8' }); expect(result.status).toBe(0); expect(result.stderr).toBe(''); expect(result.stdout).toBe('selected-identity-endpoint-ok\n'); }
}
const selectedEndpoints=new SelectedEndpointTestsAcceptance();
test("acceptance: public Identity protocol constructs with selected service aliases ports and retained legacy endpoint", selectedEndpoints.program.bind(selectedEndpoints));

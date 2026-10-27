import {test,expect} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {IdentityBuild,IdentityProtocol,KeycloakContainerPlugin} from '../../src/identity.js';
import {InstalledSchemas,ProviderSchemas} from '@treeseed-cordis/sdk';
class IdentityTestsAcceptance {

  program():void {const result=spawnSync('node',['dist/src/identity.js','--describe'],{encoding:'utf8'});expect(result.status).toBe(0);expect(result.stderr).toBe('');const metadata=JSON.parse(result.stdout);expect(metadata.capability).toBe('container.identity');expect(metadata.inject).toEqual(['deployment.engine','container.database']);expect(metadata).toEqual(KeycloakContainerPlugin.declaration);}
}
const suite=new IdentityTestsAcceptance();
test("acceptance: built identity program exposes native container declaration",suite.program.bind(suite));

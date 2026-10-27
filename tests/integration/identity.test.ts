import {test,expect} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {IdentityBuild,IdentityProtocol,KeycloakContainerPlugin} from '../../src/identity.js';
import {InstalledSchemas,ProviderSchemas} from '@treeseed-cordis/sdk';
class IdentityTestsIntegration {

  metadata():void {const metadata=JSON.parse(readFileSync('package.json','utf8'));expect(metadata.cordis).toEqual(IdentityBuild.metadata());expect(metadata.cordisService).toEqual(KeycloakContainerPlugin.definition);expect(metadata.cordisProviders).toEqual(IdentityBuild.providers());}
}
const suite=new IdentityTestsIntegration();
test('integration: generated package metadata comes from native class',suite.metadata.bind(suite));

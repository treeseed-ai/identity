import {test,expect} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {IdentityBuild,IdentityProtocol,KeycloakContainerPlugin} from '../src/identity.js';
import {InstalledSchemas,ProviderSchemas} from '@treeseed-cordis/sdk';
class IdentityTests {
  program():void {const result=spawnSync('node',['dist/src/identity.js','--describe'],{encoding:'utf8'});expect(result.status).toBe(0);expect(result.stderr).toBe('');const metadata=JSON.parse(result.stdout);expect(metadata.capability).toBe('container.identity');expect(metadata.inject).toEqual(['deployment.engine','container.database']);expect(metadata).toEqual(KeycloakContainerPlugin.declaration);}
  boundaries():void {expect(ProviderSchemas.declaration.parse(KeycloakContainerPlugin.declaration).target).toBe('deployment');expect(KeycloakContainerPlugin.provide).toEqual(['container.identity']);expect(KeycloakContainerPlugin.definition.service.environment).toEqual({JAVA_OPTS_KC_HEAP:'-Xms128m -Xmx512m'});expect(IdentityProtocol.validateConfiguration.bind(IdentityProtocol,{})).toThrow();expect(InstalledSchemas.serverConfiguration.safeParse({principal:'forged'}).success).toBe(false);}
  metadata():void {const metadata=JSON.parse(readFileSync('package.json','utf8'));expect(metadata.cordis).toEqual(IdentityBuild.metadata());expect(metadata.cordisService).toEqual(KeycloakContainerPlugin.definition);expect(metadata.cordisProviders).toEqual(IdentityBuild.providers());}
}
const suite=new IdentityTests();test('smoke: built identity program exposes native container declaration',suite.program.bind(suite));test('unit: identity rejects unconfigured authority',suite.boundaries.bind(suite));test('integration: generated package metadata comes from native class',suite.metadata.bind(suite));

import {test,expect} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {IdentityBuild,IdentityProtocol,KeycloakContainerPlugin} from '../../src/identity.js';
import {InstalledSchemas,ProviderSchemas} from '@treeseed-cordis/sdk';
class IdentityTestsUnit {

  boundaries():void {expect(ProviderSchemas.declaration.parse(KeycloakContainerPlugin.declaration).target).toBe('deployment');expect(KeycloakContainerPlugin.provide).toEqual(['container.identity']);expect(KeycloakContainerPlugin.definition.service.environment).toEqual({JAVA_OPTS_KC_HEAP:'-Xms128m -Xmx512m'});expect(IdentityProtocol.validateConfiguration.bind(IdentityProtocol,{})).toThrow();expect(InstalledSchemas.serverConfiguration.safeParse({principal:'forged'}).success).toBe(false);}
}
const suite=new IdentityTestsUnit();
test('unit: identity rejects unconfigured authority',suite.boundaries.bind(suite));

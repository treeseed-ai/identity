import {test,expect} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {readFileSync,writeFileSync,mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {CordisComposition,type CompositionHandle} from '@treeseed-cordis/sdk/composition';
import {ServiceTokens,PluginManagementSchemas,ProviderV4Schemas,type ProbeContext} from '@treeseed-cordis/sdk';
import type {Context} from '@treeseed-cordis/sdk/composition';
import {DiscoveryFixture,ProbeReceiver,ProbeConsumer} from '../support/services-test-support.js';
class ServicesTestsUnit {

 async metadata():Promise<void>{const {IdentityBuild}=await import('../../src/identity.js'),{KeycloakServicePlugin}=await import('../../src/services.js'),value=JSON.parse(readFileSync('package.json','utf8'));const descriptor=PluginManagementSchemas.packageDescriptor.parse(value.cordisPackage);expect(descriptor).toEqual(IdentityBuild.package());expect(descriptor.providers).toHaveLength(5);expect(KeycloakServicePlugin.container.dependencies).toEqual([{port:'database',contractId:'storage.postgres',contractVersion:'1.0.0'}]);expect(JSON.stringify(KeycloakServicePlugin.container).includes('database:5432')).toBe(false);expect(descriptor.images[0]!.source.kind).toBe('prepared');for(const provider of descriptor.providers)expect(provider.declaration.contractVersion).toBe(ProviderV4Schemas.version);}
}
const suite=new ServicesTestsUnit();
test('unit: named provider metadata retains same-owner authority and instance-neutral dependency contracts',suite.metadata.bind(suite));

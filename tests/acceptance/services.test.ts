import {test,expect} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {readFileSync,writeFileSync,mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {CordisComposition,type CompositionHandle} from '@treeseed-cordis/sdk/composition';
import {ServiceTokens,PluginManagementSchemas,ProviderV4Schemas,type ProbeContext} from '@treeseed-cordis/sdk';
import type {Context} from '@treeseed-cordis/sdk/composition';
import {DiscoveryFixture,ProbeReceiver,ProbeConsumer} from '../support/services-test-support.js';
class ServicesTestsAcceptance {

 program():void{const result=spawnSync('node',['dist/src/identity.js','--describe-services'],{encoding:'utf8'});expect(result.status).toBe(0);expect(result.stderr).toBe('');const descriptor=PluginManagementSchemas.packageDescriptor.parse(JSON.parse(result.stdout));expect(descriptor.providers).toHaveLength(5);expect(descriptor.package).toEqual({name:'@treeseed-cordis/identity',version:JSON.parse(readFileSync('package.json','utf8')).version});expect(result.stdout).not.toContain('private-canary');const root=mkdtempSync(join(tmpdir(),'cordis-identity-metadata-'));try{const file=join(root,'package.json'),bytes=JSON.stringify({name:'@treeseed-cordis/identity',version:'999.0.0',privateCanary:'PRIVATE_METADATA_CANARY'});writeFileSync(file,bytes);const denied=spawnSync('node',[resolve('dist/src/identity.js'),'--metadata'],{cwd:root,encoding:'utf8'});expect(denied.status).not.toBe(0);expect(denied.stderr).toContain('IDENTITY_PACKAGE_IDENTITY_DRIFT');expect(denied.stderr).not.toContain('PRIVATE_METADATA_CANARY');expect(readFileSync(file,'utf8')).toBe(bytes);}finally{rmSync(root,{recursive:true});}}
}
const suite=new ServicesTestsAcceptance();
test("acceptance: built identity program exposes five named native providers without private values",suite.program.bind(suite));

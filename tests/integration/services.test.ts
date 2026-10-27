import {test,expect} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {readFileSync,writeFileSync,mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {CordisComposition,type CompositionHandle} from '@treeseed-cordis/sdk/composition';
import {ServiceTokens,PluginManagementSchemas,ProviderV4Schemas,type ProbeContext} from '@treeseed-cordis/sdk';
import type {Context} from '@treeseed-cordis/sdk/composition';
import {DiscoveryFixture,ProbeReceiver,ProbeConsumer} from '../support/services-test-support.js';
class ServicesTestsIntegration {

 async probe():Promise<void>{const {KeycloakReadinessPlugin}=await import('../../src/services.js'),fixture=new DiscoveryFixture();let handle:CompositionHandle|undefined;try{const token=ServiceTokens.probe();handle=await CordisComposition.start({registrations:[{token,plugin:KeycloakReadinessPlugin,declaration:KeycloakReadinessPlugin.declaration,configuration:{issuer:fixture.issuer},artifact:{kind:'bundled',identity:'identity-probe-fixture'}}],selections:[{scopeId:'probe',capability:token.id,providerId:KeycloakReadinessPlugin.declaration.id}]},{scopeId:'probe',target:'deployment',principalId:'fixture',resourceScope:'fixture'});const receiver=new ProbeReceiver();await handle.mount(ProbeConsumer,receiver);const lease=await handle.locator(receiver.context!).acquire(token);try{expect((await lease.value.observe(fixture)).ready).toBe(true);expect(fixture.requests).toBe(1);expect(fixture.privateReads).toBe(0);fixture.invalid=true;const denied=await lease.value.observe(fixture);expect(denied.ready).toBe(false);expect(JSON.stringify(denied)).not.toContain('canary');fixture.invalid=false;fixture.redirect=true;expect((await lease.value.observe(fixture)).ready).toBe(false);fixture.redirect=false;fixture.oversized=true;expect((await lease.value.observe(fixture)).ready).toBe(false);const abort=new AbortController();abort.abort();expect((await lease.value.observe({...fixture,signal:abort.signal,credential:fixture.credential.bind(fixture),authority:fixture.authority.bind(fixture)})).ready).toBe(false);}finally{await lease.release();}}finally{await handle?.dispose();fixture.close();}}
}
const suite=new ServicesTestsIntegration();
test('integration: native default Keycloak discovery probe uses bounded real HTTP and rejects foreign redirected oversized or cancelled evidence',suite.probe.bind(suite));

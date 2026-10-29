import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import * as sdk from '@treeseed-cordis/sdk';
import { IdentityBuild } from '../../src/identity.js';

class CapacityContractProgram {
  run(): void {
    this.selection();
    const channel = Reflect.get(sdk, 'CapacityChannelSchemas');
    assert.equal(typeof channel, 'function', 'manager channel contracts required');
    assert.equal(Reflect.get(channel, 'version'), '1.1.0-cordis.1');
    assert.equal(typeof Reflect.get(sdk, 'CapacitySchemas'), 'function');
    assert.equal(typeof Reflect.get(sdk, 'SeedSchemas'), 'function');
    assert.equal(sdk.PlatformOperations.all.length, 7);
    assert.equal(IdentityBuild.metadata().capability, 'container.identity');
    process.stdout.write('identity-capacity-contracts-ok\n');
  }
  private selection(): void {
    const metadata = JSON.parse(readFileSync('package.json', 'utf8'));
    const digest = createHash('sha256').update(readFileSync('vendor/sdk.tgz')).digest('hex');
    assert.equal(metadata.peerDependencies['@treeseed-cordis/sdk'], '0.0.0-cordis.42');
    assert.equal(metadata.cordisCandidate.sdk.commit, 'afdfac7bdd3c9c1f783362cd1d50324181e1d725');
    assert.equal(digest, '0ecfe599916fe8ef364fc4b73203c810981f163109fbe71a0dd4c01a9dfb7bbc');
    assert.equal(metadata.cordisCandidate.sdk.sha256, digest);
  }
}
if (import.meta.main) new CapacityContractProgram().run();

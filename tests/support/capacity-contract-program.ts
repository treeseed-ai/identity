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
    assert.equal(metadata.peerDependencies['@treeseed-cordis/sdk'], '0.0.0-cordis.44');
    assert.equal(metadata.cordisCandidate.sdk.commit, '00be028b92998f8d7039a3906e784c6b8598e730');
    assert.equal(digest, 'd95c54cf6081c7634498dfb4f3235d42d65b8664a5d62cc87c4dd4e85381f0f3');
    assert.equal(metadata.cordisCandidate.sdk.sha256, digest);
  }
}
if (import.meta.main) new CapacityContractProgram().run();

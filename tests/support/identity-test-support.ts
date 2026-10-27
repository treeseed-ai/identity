import {test,expect} from 'bun:test';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {IdentityBuild,IdentityProtocol,KeycloakContainerPlugin} from '../../src/identity.js';
import {InstalledSchemas,ProviderSchemas} from '@treeseed-cordis/sdk';

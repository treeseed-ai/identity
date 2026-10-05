import { test } from 'node:test';
import assert from 'node:assert/strict';
import { browserEnrollmentProfile } from '../dist/browser-enrollment.js';

test('enrollment profile does not carry permissions, roles, account links or unsafe profile text', () => {
  assert.deepEqual(browserEnrollmentProfile('https://identity.example/realms/team', {
    sub: 'one', email: 'person@example.test', email_verified: 'true', given_name: 'First', family_name: 'Last',
    name: 'unsafe\nname', roles: ['admin'], teamId: 'owner', preferred_username: 'existing-admin',
  }), { identity: { issuer: 'https://identity.example/realms/team', subject: 'one' }, email: 'person@example.test',
    emailVerified: false, firstName: 'First', lastName: 'Last', displayName: undefined });
  assert.throws(() => browserEnrollmentProfile('https://identity.example', { sub: '' }));
});

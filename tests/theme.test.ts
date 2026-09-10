import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

test('theme preserves native Keycloak forms and uses the canonical UI assets', () => {
  const template = readFileSync('themes/treeseed/login/template.ftl', 'utf8');
  assert.match(template, /treeseed-logo\.svg/);
  assert.match(template, /startSessionPolling/);
  assert.match(template, /checkAuthSession/);
  assert.match(template, /<#nested "form">/);
  // The inherited try-another-way form is retained; never add password fields.
  assert.doesNotMatch(template, /<input[^>]*type="password"/);
  for (const [specifier, path] of [
    ['@treeseed/ui/styles/tokens.css', 'css/tokens.css'],
    ['@treeseed/ui/styles/auth.css', 'css/auth.css'],
    ['@treeseed/ui/assets/treeseed-logo.svg', 'img/treeseed-logo.svg'],
  ]) assert.deepEqual(readFileSync(new URL(import.meta.resolve(specifier!))), readFileSync(`themes/treeseed/login/resources/${path}`));
});

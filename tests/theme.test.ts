import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

test('theme preserves native Keycloak forms and uses the canonical UI assets', () => {
  const template = readFileSync('themes/treeseed/login/template.ftl', 'utf8');
  assert.match(template, /treeseed-logo\.svg/);
  // Keycloak 26.7 supplies inherited favicon metadata even in child themes.
  // It must not override TreeSeed's canonical identity.
  assert.doesNotMatch(template, /renderFavicons|themeResources\.favicons/);
  assert.match(template, /startSessionPolling/);
  assert.match(template, /checkAuthSession/);
  const adapter = readFileSync('themes/treeseed/login/resources/css/treeseed.css', 'utf8');
  assert.match(adapter, /grid-template-areas: "header main"/);
  assert.match(adapter, /grid-template-areas: "header" "main"/);
  assert.match(adapter, /text-transform: none; letter-spacing: normal/);
  assert.match(adapter, /color: var\(--ts-color-text\) !important/);
  assert.match(template, /<#nested "form">/);
  // The inherited try-another-way form is retained; never add password fields.
  assert.doesNotMatch(template, /<input[^>]*type="password"/);
  for (const [specifier, path] of [
    ['@treeseed/ui/styles/tokens.css', 'css/tokens.css'],
    ['@treeseed/ui/styles/auth.css', 'css/auth.css'],
    ['@treeseed/ui/assets/treeseed-logo.svg', 'img/treeseed-logo.svg'],
  ]) assert.deepEqual(readFileSync(new URL(import.meta.resolve(specifier!))), readFileSync(`themes/treeseed/login/resources/${path}`));
});

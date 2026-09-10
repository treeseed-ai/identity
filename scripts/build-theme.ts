import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Compile-time reuse only: do not ship Astro/React or the UI dependency tree
// into Keycloak. Native Keycloak forms keep their own authentication semantics.
for (const [source, target] of [
  ['@treeseed/ui/styles/tokens.css', 'css/tokens.css'],
  ['@treeseed/ui/styles/auth.css', 'css/auth.css'],
  ['@treeseed/ui/assets/treeseed-logo.svg', 'img/treeseed-logo.svg'],
] as const) {
  const destination = resolve('themes/treeseed/login/resources', target);
  mkdirSync(dirname(destination), { recursive: true });
  copyFileSync(fileURLToPath(import.meta.resolve(source)), destination);
}

# Cordis Identity


## Task 3B: Identity plugins and configured OIDC

Legacy src/application-session.ts remains this repository's capability. The public package provides native Keycloak container, OIDC protocol, principal/session and request-authority class plugins. The container plugin consumes the Deployment engine contract, exports a typed identity service and awaits real realm discovery. Server plugins use authorization code with PKCE/state/nonce and exact issuer/audience, retain tokens server-side and persist issuer/subject principals in PostgreSQL. Only the explicit bootstrap subject receives platform administration. No password issuer, credential fallback or trusted principal in caller configuration. Public exports separate container/server entry points; generated metadata comes from native declarations.

Task 3B is authorized after the maintainer reviewed the isolated setup. Tracking: #44. Detailed integration plan: https://github.com/treeseed-ai/platform/blob/feature/713-task3b-initialization/docs/superpowers/plans/2026-10-24-task3b-installed-composition.md. Implementation evidence is recorded separately; these requirements are not a passing-test claim.

Development: Bun 1.4.4, Node 24.19.0, TypeScript 5.9.3, native Cordis 4.0.0-rc.12. Run bun run verify (semantic class/source check, strict compiler, build and nonempty unit/integration/program smoke). Installed acceptance uses genuine exact package/OCI bytes, real identity/database/API/HTTPS and explicit isolated certificate trust. No global trust mutation or legacy service changes. All handwritten source, tools and tests are strict TypeScript classes.

All capabilities that can be plugins, including container services, are native Cordis class plugins with typed swappable contracts. No parallel DI graph. Keep independent repository/public package boundaries, exact archive pins and original licenses. Migration PRs target cordis with Part of issue references. All issues remain open until authorized release; installer/Agent/generalized recovery are later tasks.

# Cordis Identity


## Task 3B: Identity plugins and configured OIDC

Legacy src/application-session.ts remains this repository's capability. The public package provides native Keycloak container, OIDC protocol, principal/session and request-authority class plugins. The container plugin consumes the Deployment engine contract, exports a typed identity service and awaits real realm discovery. Server plugins use authorization code with PKCE/state/nonce and exact issuer/audience, retain tokens server-side and persist issuer/subject principals in PostgreSQL. Only the explicit bootstrap subject receives platform administration. No password issuer, credential fallback or trusted principal in caller configuration. Public exports separate container/server entry points; generated metadata comes from native declarations.

Task 3B is authorized after the maintainer reviewed the isolated setup. Tracking: #44. Detailed integration plan: https://github.com/treeseed-ai/platform/blob/cordis/docs/superpowers/plans/2026-10-24-task3b-installed-composition.md. Implementation evidence is recorded separately; these requirements are not a passing-test claim.

Development: Bun 1.4.4, Node 24.19.0, TypeScript 5.9.3, native Cordis 4.0.0-rc.12. Run bun run verify (semantic class/source check, strict compiler, build and nonempty unit/integration/program smoke). Installed acceptance uses genuine exact package/OCI bytes, real identity/database/API/HTTPS and explicit isolated certificate trust. No global trust mutation or legacy service changes. All handwritten source, tools and tests are strict TypeScript classes.

All capabilities that can be plugins, including container services, are native Cordis class plugins with typed swappable contracts. No parallel DI graph. Keep independent repository/public package boundaries, exact archive pins and original licenses. Migration PRs target cordis with Part of issue references. All issues remain open until authorized release; installer/Agent/generalized recovery are later tasks.

The qualified PostgreSQL client is postgres@3.4.9 (no runtime dependency or optional-peer closure). Its parameterized query API remains inside the Identity store class. OIDC uses openid-client@6.8.8 with its exact locked jose/oauth4webapi closure. See the upstream [database client API](https://github.com/porsager/postgres#queries) and [OIDC client](https://github.com/panva/openid-client). Container and server projections are generated separately from the same native declarations.

Build generates both cordisService (the container/private-slot/readiness declaration) and cordisProviders (the server plugins) from the actual owning class fields. The declaration uses generic accepted private projections; Deployment has no Keycloak realm/configuration catalog. Browser cookies and database sessions are scoped to the explicit installation/origin; application logout revokes the local session, while the configured identity provider retains its own SSO session policy.

IdentityPersistence and IdentityProtocolAdapter are public structural contracts with exported capability tokens; consumers do not depend on private fields of concrete store/protocol classes. Native constructor injection supplies the default implementation.

The fixed private backchannel overwrites forwarded protocol/host/port from the accepted HTTPS origin, matching the edge-termination profile. Public issuer/audience/state/nonce validation stays enabled; no TLS validation flag is disabled. The identity service is reachable only on the owned Docker network. See [Keycloak proxy guidance](https://www.keycloak.org/server/reverseproxy).

The first installed Keycloak provider bounds its JVM heap to 128–512 MiB through its owner-declared `JAVA_OPTS_KC_HEAP`. This local acceptance profile does not infer a heap from all host memory. Broader capacity profiles remain a later sizing decision. See [Keycloak container memory guidance](https://www.keycloak.org/server/containers#_specifying_different_memory_settings).

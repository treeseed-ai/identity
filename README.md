# Cordis Identity

## Task 3D contract compatibility

Issue #57 qualifies Identity `.9` against accepted SDK `0.0.0-cordis.42`, source
`afdfac7bdd3c9c1f783362cd1d50324181e1d725`, SHA-256
`0ecfe599916fe8ef364fc4b73203c810981f163109fbe71a0dd4c01a9dfb7bbc`.
Installed bytes, peer and source/archive identity must agree. Built public compatibility requires
capacity-channel version `1.1.0-cordis.1`, seed/capacity contracts and the unchanged seven global
platform operations. Existing OIDC/session/discovery and native Keycloak provider suites remain
required. This selects the manager/worker-compatible closure; it adds no authority or enrollment
implementation. Approval, credentials, issuer and subject custody stay behind existing protocols.
Historical SDK .19 and Identity .8 artifacts remain immutable. All issues remain open.

Task 3C's current Identity candidate consumes SDK .12 from
`4a0b12ca45478f58d92a02de4a7c144ed94c7417`, archive SHA-256
`9652a1e1f830eb85c41b2d9ea207782ffdf291db2ef97331e338775dadf62fd4`.
Requalify the existing native Keycloak discovery/service and OIDC/session contracts against that
exact archive. The optional accepted-observation metadata does not move issuer, credential or
session authority out of Identity. Genuine Keycloak installed assembly remains a separate gate.


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

## Task 3C contract

Owner issue: https://github.com/treeseed-ai/identity/issues/46. Follow the approved Platform Task 3C service/provider/UI plan through exact public archives. Preserve independent repository ownership, strict TypeScript classes, native Cordis lifecycle, historical formats and all seven SDK operations. Expected-generation/idempotency, resource/credential/TLS retention and explicit unsafe restart/migration gates are mandatory. All issues remain open until release.

Every visual component must be mobile-first from 320 CSS pixels to widescreen monitors; test 320/375/768/1024/1440/1920/2560 widths, long content, keyboard/touch and 200% text resizing. Keep authored controls at least 44×44 CSS pixels, required actions visible, logical/fluid dimensions and no page overflow (labeled local semantic-table overflow is permitted). UI owns components/styles/renderers; consumers retain domain behavior and Identity retains Keycloak authority.

## Named Keycloak service and provider contracts

`@treeseed-cordis/identity/services` exports `KeycloakServicePlugin` and
`KeycloakReadinessPlugin`. The service uses an accepted instance context and Deployment's
bounded engine, with typed `identity.oidc@1.0.0` provision and `storage.postgres@1.0.0`
dependency. Endpoints and explicit database credential grants reference dependency ports;
there are no fixed database/identity DNS names in the new projection. Realm `cordis`, client
`cordis-admin`, issuer/public `/identity` prefix, PKCE S256 and owner bootstrap semantics stay.

The readiness class performs bounded direct OIDC discovery at its accepted endpoint, validates
issuer and protocol endpoint identities, honors cancellation/deadline and returns safe evidence
without following metadata URLs or exposing response/credential errors. It receives no Docker
or filesystem interface. Actual Keycloak login/session persistence remains an assembled gate.

Identity's persistence/OIDC/session providers are public named Cordis classes with format-4
metadata derived from their declarations, Config and conservative restart policy. Existing
method contracts and Keycloak authority stay here. The legacy format-2 container export is
retained for historical exact releases; new packages/compositions use the versioned metadata.
The package declares the previously qualified native Keycloak manifest
`88943b6ad06d6293a239f0dfca5acec64218c9b3ab327bf9c936acf408a6ae3b` as prepared OCI bytes,
with selected-index SHA-256 `2c57cdc49e3d4b2a5aedea1fab23b57171c29eff4ef1e17f4d59247f683effe8`.
Planning verifies those bytes. Absence does not authorize a pull or invented download URL.

### Selected internal OIDC endpoint

The protocol adapter accepts the HTTP root of the selected typed identity service, rather than
requiring a container named `identity` on port 8080. The internal hostname must be a valid SDK
service ID, with a valid TCP port (including HTTP's default port). Userinfo, query, fragment,
foreign/public DNS names, non-root paths and non-HTTP internal routes are refused. Deployment's
verified projection is responsible for binding that alias/port to the selected service.
The public issuer remains the configured loopback HTTPS origin plus `/identity/realms/cordis`;
userinfo/query/fragment are refused there too. This does not change Keycloak ownership,
forwarded-origin binding, PKCE, callback, principal, session or credential handling.

### Exact shared contract alignment

Adopt SDK `.14` source `597a9abd79b76fb292a80cd86e4ea83042fbec62`, archive SHA-256
`c92fb068064a6db4823b29c31602b47e01c21200af759a770480a1a0cc4240a2`, through the same
public package interface. Preserve Keycloak as the sole issuer/session authority, selected
internal endpoints, PKCE and principal/session custody. This dependency alignment adds no
registration, restart or deployment authority to Identity. Rebuild the private `.5` package
metadata with its own version and rerun default public-construction contracts.

### Coherent Task 3C SDK alignment

The next Identity candidate uses exact SDK `.16`, source
`4c0ecd2a0fc28545dbf677cc988ce69f0cf2f15d`, archive SHA-256
`4084aa8dbe9767984fac9fef7f5cea30a0bec93ed416138d32c804e6389fdba5`.
This aligns its native service/probe and OIDC contracts with UI and the remaining owner assembly.
Keycloak stays the identity authority; issuer, realm, client/session policy, service projection,
secret grants and pinned Keycloak image retain their behavior. Consumers still use the public
Identity package and exact archive references; no identity implementation moves to another owner.

Identity `.7` supersedes the rejected `.6` alignment artifact: the consumer assembly detected
that `.6` still advertised `.5` in its native package declaration. The immutable `.6` archive is
retained as negative evidence and must not be selected. Identity's built public declaration now
must match its own package manifest, and metadata generation refuses a different name/version
before writing any file. This guards developer packaging identity; Keycloak behavior is unchanged.

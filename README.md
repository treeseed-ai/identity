# TreeSeed Identity

## Publication and runtime ownership

The browser OIDC adapter is a server-side confidential-client building block,
not an application session store. Applications must supply atomic, browser-bound
transaction storage, keep returned tokens server-side, and issue their own secure
HttpOnly host-only session cookies. Deployment supplies the authorized HTTPS
transport and private-route/DNS protections. The adapter uses maintained OAuth
protocol validation, S256 PKCE, state, nonce, and signed ID-token verification;
it never assigns team roles or links accounts by email. Browser clients configure
one exact API resource, requested scopes, verification keys and local principal
resolver. Both initial and refreshed access tokens must match that resource,
client and user, even when refresh returns no ID token. Transactions bind those
settings; changes require a new sign-in. Live applications are not
yet migrated to it.

`createApplicationSession` is the shared server-side application integration.
Configure the API resource, trusted issuer, callback, a distinct `__Host-` cookie
name and Deployment-backed workload credentials. `login` and `callback` return
redirect responses containing opaque cookies only; `session` returns an API
credential **for server-side requests only**. Never serialize that value into
HTML, browser JSON or storage. `logout` requires same-origin POST. The API owns
encrypted transaction/token storage and application authorization. Applications
do not collect passwords or implement their own refresh-token rotation.

This repository publishes `@treeseed/identity` to npm and unchanged custody assets
to GitHub Releases. RC tags use staging; stable tags use main/production. Required
checks seal the tarball and CycloneDX SBOM with SDK release evidence; publication
verifies the exact protected head and reads the registry bytes back without rebuilding.

Deployment owns Keycloak/SPIRE provisioning, exact upstream image digests, and any
TreeSeed custom image builds (including baked-in login themes). Identity requires
no Docker Hub publishing credential. Human review remains at main PRs only.

Independent authentication integration for sovereign TreeSeed installations.
Applications share sign-in, not browser cookies or authorization.

## Implemented foundation

`createAccessTokenVerifier` checks a configured issuer and API audience using explicitly
supplied asymmetric verification keys. A local mapping callback preserves application
principal IDs and supplies the principal kind. Email and token roles never create accounts
or grant membership. Unknown identities fail closed.

Keycloak and RFC 9068 access-token profiles are explicit. ID tokens, wrong issuers/audiences,
expired/oversized tokens, unsupported algorithms and unimplemented actor delegation are
rejected. Public errors contain no token details. The verifier does not fetch URLs or
discover trust: remote key resolution requires Deployment's approved network transport.

## Remaining work

Adapters for discovery, native/device CLI sign-in, refresh, browser SSO and asymmetric
workloads are published. Actual application integration, managed policy reconciliation,
workload attestation and live migration remain tracked in #1 and Platform #467.
This is not an accepted live SSO deployment.

Run `npm ci` then `npm run verify`. SDK owns contracts, Deployment owns provisioning,
and APIs own resource permissions. Knowledge lives in `treeseed-ai/identity-library`.

The generated engineering website scaffold was removed; it remains recoverable from the
initialization commit and immutable template release. No user-authored work was removed.

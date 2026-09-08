# TreeSeed Identity

## Publication and runtime ownership

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

Hosted login, sessions, discovery/refresh, CLI flows, federation and workload integration
are tracked in #1 and Platform #467. This is not an accepted live SSO deployment.

Run `npm ci` then `npm run verify`. SDK owns contracts, Deployment owns provisioning,
and APIs own resource permissions. Knowledge lives in `treeseed-ai/identity-library`.

The generated engineering website scaffold was removed; it remains recoverable from the
initialization commit and immutable template release. No user-authored work was removed.

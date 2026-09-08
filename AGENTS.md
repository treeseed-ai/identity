# Identity workspace guidance

Identity owns authentication adapters; SDK owns public contracts. Deployment owns
Keycloak/SPIRE packaging, TLS, bootstrap, hosting and recovery. APIs retain authorization.
Never infer account links or memberships from email. No passwords or secrets in logs.

Issues are status authority; Actions are verification authority. No routine comments.
Fetch exact protected heads before branches, merges or releases. Staging uses PRs and
automated gates; main/production PRs require human review. No preview environments.
Independent published dependencies only. Keep files under 500 lines and tests in tests/.

Use `trsd library show identity` and `trsd library status identity` before library reads.
Author through governed TreeDX workspaces; never recreate source content trees or edit
TreeDX storage. Never commit host identities, personal paths or runtime receipts.

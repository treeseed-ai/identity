# TreeSeed authentication theme

The `treeseed` login theme extends **Keycloak 26.7.3 `keycloak.v2`**.
`template.ftl` is adapted from that release's Apache-2.0 template. It preserves
native session polling, one-time links, locale selection, forms, required
actions, MFA and sanitization. Review upstream template changes when upgrading
Keycloak; do not silently reuse this adapter across untested versions.

The build copies exact published `@treeseed/ui` authentication CSS, design tokens
and logo. Only these small static assets ship, not the Astro/React application or
the UI dependency graph. Keycloak renders its native forms; Astro components
cannot execute inside its FreeMarker runtime. The adapter recreates the existing
UI AuthCard layout without replacing authentication handlers.

Deployment owns installation and realm policy. Selecting the theme does not
enable registration, reset mail, identity linking or team membership. Public
registration additionally requires API enrollment and a verified mail transport.
Color mode follows the operating system; cross-application saved preferences
are not synchronized by this theme and no application cookies are shared.

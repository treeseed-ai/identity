import * as oauth from 'oauth4webapi';
import { decodeJwt } from 'jose';
import { identityEndpointSchema, resourceTokenRequestSchema } from '@treeseed/sdk/identity';
import { createAccessTokenVerifier, IdentityAuthenticationError, type AccessTokenVerifierOptions } from './access-token.js';

export interface WorkloadCredentialOptions {
  issuer: string;
  clientId: string;
  privateKey: CryptoKey;
  /** Immutable configured resource allowlist, not a caller-selected issuer. */
  resources: readonly string[];
  verificationKey: AccessTokenVerifierOptions['verificationKey'];
  resolvePrincipal: AccessTokenVerifierOptions['resolvePrincipal'];
  profile: AccessTokenVerifierOptions['profile'];
  /** Deployment owns routing, trust anchors and DNS-rebinding protection. */
  transport: typeof fetch;
  maxLifetimeSeconds?: number;
}

/** Supported OAuth private_key_jwt authentication; possession of this workload
 * key is not host attestation. SPIRE exchange must verify attestation separately.
 * Tokens are returned only to an authorized server-side consumer, never logged.
 */
export async function createWorkloadCredentials(options: WorkloadCredentialOptions) {
  const issuer = identityEndpointSchema.parse(options.issuer);
  if (!options.clientId || options.clientId.length > 256 || !options.resources.length || options.resources.length > 64) throw new IdentityAuthenticationError();
  const resources = new Set(options.resources.map(value => identityEndpointSchema.parse(value)));
  if (resources.size !== options.resources.length) throw new IdentityAuthenticationError();
  const origin = new URL(issuer).origin;
  const request: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    if (url.origin !== origin || url.username || url.password || url.hash) throw new IdentityAuthenticationError();
    const response = await options.transport(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(10_000) });
    if (response.redirected || response.status >= 300 && response.status < 400) throw new IdentityAuthenticationError();
    return response;
  };
  const http = { [oauth.customFetch]: request };
  let server: oauth.AuthorizationServer;
  try {
    server = await oauth.processDiscoveryResponse(new URL(issuer), await oauth.discoveryRequest(new URL(issuer), http));
    if (!server.token_endpoint || new URL(identityEndpointSchema.parse(server.token_endpoint)).origin !== origin) throw new IdentityAuthenticationError();
  } catch { throw new IdentityAuthenticationError(); }
  const client: oauth.Client = { client_id: options.clientId, token_endpoint_auth_method: 'private_key_jwt' };
  const auth = oauth.PrivateKeyJwt(options.privateKey);
  return {
    /** No ambient token cache: each operation rechecks current principal authority. */
    async credentials(input: { resource: string; scopes: string[] }) {
      try {
        const selected = resourceTokenRequestSchema.parse(input);
        if (!resources.has(selected.resource)) throw new IdentityAuthenticationError();
        const response = await oauth.clientCredentialsGrantRequest(server, client, auth,
          { resource: selected.resource, ...(selected.scopes.length ? { scope: selected.scopes.join(' ') } : {}) }, http);
        const tokens = await oauth.processClientCredentialsResponse(server, client, response);
        if (tokens.token_type.toLowerCase() !== 'bearer' || tokens.refresh_token !== undefined) throw new IdentityAuthenticationError();
        const verify = createAccessTokenVerifier({ issuer, audience: selected.resource, verificationKey: options.verificationKey,
          resolvePrincipal: options.resolvePrincipal, profile: options.profile, maxLifetimeSeconds: options.maxLifetimeSeconds });
        const principal = await verify(tokens.access_token);
        const verifiedClaims = decodeJwt(tokens.access_token);
        if ((options.profile === 'keycloak' ? verifiedClaims.azp : verifiedClaims.client_id) !== options.clientId) throw new IdentityAuthenticationError();
        if (principal.kind !== 'service' || selected.scopes.some(scope => !principal.scopes.includes(scope))) throw new IdentityAuthenticationError();
        // Audience verification is mandatory even when a provider ignores the
        // resource parameter. Never forward a token intended for another API.
        return { accessToken: tokens.access_token, tokenType: 'Bearer' as const, resource: selected.resource, principal };
      } catch { throw new IdentityAuthenticationError(); }
    },
  };
}

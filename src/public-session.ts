import * as oauth from 'oauth4webapi';
import { decodeJwt } from 'jose';
import { identityEndpointSchema, resourceTokenRequestSchema } from '@treeseed/sdk/identity';
import { createAccessTokenVerifier, IdentityAuthenticationError, type AccessTokenVerifierOptions } from './access-token.js';

export interface PublicSessionOptions {
  issuer: string; clientId: string; resource: string; scopes: string[];
  verificationKey: AccessTokenVerifierOptions['verificationKey'];
  resolvePrincipal: AccessTokenVerifierOptions['resolvePrincipal'];
  profile: AccessTokenVerifierOptions['profile']; transport: typeof fetch;
}

/** Session lifecycle shared by native-PKCE and device-login CLI sessions.
 * Caller must serialize refresh under its secure-store lock, atomically replace
 * the result, and invalidate the local record on ambiguous refresh failure.
 */
export async function createPublicSessionClient(options: PublicSessionOptions) {
  const issuer = identityEndpointSchema.parse(options.issuer), origin = new URL(issuer).origin;
  const selected = resourceTokenRequestSchema.parse({ resource: options.resource, scopes: options.scopes });
  if (!options.clientId || options.clientId.length > 256) throw new IdentityAuthenticationError();
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
    for (const endpoint of [server.token_endpoint, server.jwks_uri]) {
      if (!endpoint || new URL(identityEndpointSchema.parse(endpoint)).origin !== origin) throw new IdentityAuthenticationError();
    }
    if (server.revocation_endpoint && new URL(identityEndpointSchema.parse(server.revocation_endpoint)).origin !== origin) throw new IdentityAuthenticationError();
  } catch { throw new IdentityAuthenticationError(); }
  const client: oauth.Client = { client_id: options.clientId, token_endpoint_auth_method: 'none' };
  return {
    async refresh(refreshToken: string, expectedIdentity: { issuer: string; subject: string }) {
      try {
        if (!refreshToken || refreshToken.length > 32768 || expectedIdentity.issuer !== issuer || !expectedIdentity.subject) throw new IdentityAuthenticationError();
        const response = await oauth.refreshTokenGrantRequest(server, client, oauth.None(), refreshToken,
          { ...http, additionalParameters: { resource: selected.resource } });
        const tokens = await oauth.processRefreshTokenResponse(server, client, response);
        const verify = createAccessTokenVerifier({ issuer, audience: selected.resource, profile: options.profile,
          verificationKey: options.verificationKey, resolvePrincipal: options.resolvePrincipal });
        const principal = await verify(tokens.access_token), claims = decodeJwt(tokens.access_token);
        if (principal.kind !== 'human' || principal.identity.subject !== expectedIdentity.subject || tokens.token_type.toLowerCase() !== 'bearer'
          || (options.profile === 'keycloak' ? claims.azp : claims.client_id) !== options.clientId
          || selected.scopes.some(scope => !principal.scopes.includes(scope))) throw new IdentityAuthenticationError();
        const idClaims = oauth.getValidatedIdTokenClaims(tokens);
        if (idClaims) {
          await oauth.validateApplicationLevelSignature(server, response, http);
          if (idClaims.sub !== expectedIdentity.subject) throw new IdentityAuthenticationError();
        }
        return { principal, resource: selected.resource, tokens };
      } catch { throw new IdentityAuthenticationError(); }
    },
    /** Local deletion remains mandatory even if upstream revocation fails. */
    async revoke(token: string) {
      try {
        if (!token || token.length > 32768 || !server.revocation_endpoint) throw new IdentityAuthenticationError();
        await oauth.processRevocationResponse(await oauth.revocationRequest(server, client, oauth.None(), token, http));
        return { revoked: true as const };
      } catch { throw new IdentityAuthenticationError(); }
    },
  };
}

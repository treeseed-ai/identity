import * as oauth from 'oauth4webapi';
import { decodeJwt } from 'jose';
import { identityEndpointSchema, resourceTokenRequestSchema } from '@treeseed/sdk/identity';
import { createAccessTokenVerifier, IdentityAuthenticationError, type AccessTokenVerifierOptions } from './access-token.js';

export interface NativeOidcOptions {
  issuer: string; clientId: string; redirectUri: string; resource: string; scopes: string[];
  verificationKey: AccessTokenVerifierOptions['verificationKey'];
  resolvePrincipal: AccessTokenVerifierOptions['resolvePrincipal'];
  profile: AccessTokenVerifierOptions['profile'];
  transport: typeof fetch;
  now?: () => number;
}

/** Browser authorization for a native CLI with an already-bound loopback
 * listener. No client secret or application cookie. Caller stores tokens only
 * after this adapter verifies both identity and resource-specific access.
 */
export async function createNativeOidcClient(options: NativeOidcOptions) {
  const issuer = identityEndpointSchema.parse(options.issuer), origin = new URL(issuer).origin;
  const selected = resourceTokenRequestSchema.parse({ resource: options.resource, scopes: options.scopes });
  const redirect = new URL(options.redirectUri), now = options.now ?? Date.now;
  if (redirect.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(redirect.hostname) || !redirect.port
    || redirect.username || redirect.password || redirect.search || redirect.hash || !options.clientId || options.clientId.length > 256) throw new IdentityAuthenticationError();
  const request: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    if (url.origin !== origin || url.username || url.password || url.hash) throw new IdentityAuthenticationError();
    const response = await options.transport(url, { ...init, redirect: 'error',
      signal: AbortSignal.any([AbortSignal.timeout(10_000), ...(init?.signal ? [init.signal] : [])]) });
    if (response.redirected || response.status >= 300 && response.status < 400) throw new IdentityAuthenticationError();
    return response;
  };
  const http = { [oauth.customFetch]: request };
  let server: oauth.AuthorizationServer;
  try {
    server = await oauth.processDiscoveryResponse(new URL(issuer), await oauth.discoveryRequest(new URL(issuer), http));
    for (const endpoint of [server.authorization_endpoint, server.token_endpoint, server.jwks_uri]) {
      if (!endpoint || new URL(identityEndpointSchema.parse(endpoint)).origin !== origin) throw new IdentityAuthenticationError();
    }
    if (!server.code_challenge_methods_supported?.includes('S256')) throw new IdentityAuthenticationError();
  } catch { throw new IdentityAuthenticationError(); }
  const client: oauth.Client = { client_id: options.clientId, token_endpoint_auth_method: 'none' };
  return {
    async begin() {
      let verifier = oauth.generateRandomCodeVerifier();
      const state = oauth.generateRandomState(), nonce = oauth.generateRandomNonce(), expiresAt = now() + 300_000;
      const cancellation = new AbortController(); let consumed = false;
      const url = new URL(server.authorization_endpoint!);
      url.search = new URLSearchParams({ client_id: options.clientId, redirect_uri: redirect.href, response_type: 'code',
        scope: [...new Set(['openid', ...selected.scopes])].join(' '), resource: selected.resource, state, nonce,
        code_challenge: await oauth.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256' }).toString();
      return {
        authorizationUrl: url.href, expiresAt,
        cancel() { consumed = true; verifier = ''; cancellation.abort(); },
        async finish(callback: URL) {
          try {
            if (consumed || now() >= expiresAt) { consumed = true; throw new IdentityAuthenticationError(); }
            if (callback.origin !== redirect.origin || callback.pathname !== redirect.pathname || callback.hash
              || callback.searchParams.getAll('state').length !== 1 || callback.searchParams.get('state') !== state) throw new IdentityAuthenticationError();
            consumed = true;
            const parameters = oauth.validateAuthResponse(server, client, callback, state);
            const response = await oauth.authorizationCodeGrantRequest(server, client, oauth.None(), parameters, redirect.href, verifier,
              { ...http, signal: cancellation.signal, additionalParameters: { resource: selected.resource } });
            const tokens = await oauth.processAuthorizationCodeResponse(server, client, response, { expectedNonce: nonce, requireIdToken: true });
            await oauth.validateApplicationLevelSignature(server, response, http);
            const identity = oauth.getValidatedIdTokenClaims(tokens);
            const verify = createAccessTokenVerifier({ issuer, audience: selected.resource, profile: options.profile,
              verificationKey: options.verificationKey, resolvePrincipal: options.resolvePrincipal });
            const principal = await verify(tokens.access_token), claims = decodeJwt(tokens.access_token);
            if (!identity || principal.kind !== 'human' || identity.sub !== principal.identity.subject || tokens.token_type.toLowerCase() !== 'bearer'
              || (options.profile === 'keycloak' ? claims.azp : claims.client_id) !== options.clientId
              || selected.scopes.some(scope => !principal.scopes.includes(scope)) || cancellation.signal.aborted || now() >= expiresAt) throw new IdentityAuthenticationError();
            return { principal, resource: selected.resource, tokens };
          } catch { throw new IdentityAuthenticationError(); }
          finally { if (consumed) verifier = ''; }
        },
      };
    },
  };
}

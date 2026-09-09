import * as oauth from 'oauth4webapi';
import { identityEndpointSchema, resourceTokenRequestSchema } from '@treeseed/sdk/identity';
import { createAccessTokenVerifier, IdentityAuthenticationError, type AccessTokenVerifierOptions } from './access-token.js';

export interface LoginTransaction {
  state: string; nonce: string; verifier: string; expiresAt: number;
  issuer: string; clientId: string; redirectUri: string;
  resource: string; scopes: string[];
}
/** Server-side only. consume must atomically remove a transaction bound to this browser session. */
export interface LoginTransactionStore {
  put(browserBinding: string, transaction: LoginTransaction): Promise<void>;
  consume(browserBinding: string, state: string): Promise<LoginTransaction | null>;
}
export interface BrowserOidcOptions {
  issuer: string; clientId: string; redirectUri: string;
  privateKey: CryptoKey;
  resource: string; scopes: string[];
  profile: AccessTokenVerifierOptions['profile'];
  verificationKey: AccessTokenVerifierOptions['verificationKey'];
  resolvePrincipal: AccessTokenVerifierOptions['resolvePrincipal'];
  store: LoginTransactionStore;
  /** Deployment-authorized transport owns private routing and DNS-rebinding protection. */
  transport: typeof fetch;
  now?: () => number;
}

/** Confidential BFF client. Tokens returned by finish must never be sent to browser storage. */
export async function createBrowserOidcClient(options: BrowserOidcOptions) {
  const issuer = identityEndpointSchema.parse(options.issuer);
  const redirectUri = identityEndpointSchema.parse(options.redirectUri);
  const selected = resourceTokenRequestSchema.parse({ resource: options.resource, scopes: options.scopes });
  if (!options.clientId || options.clientId.length > 256) throw new Error('Invalid client ID.');
  const origin = new URL(issuer).origin;
  const now = options.now ?? Date.now;
  const request: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    if (url.origin !== origin || url.username || url.password || url.hash) throw new IdentityAuthenticationError();
    const response = await options.transport(url, { ...init, credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(10_000) });
    if (response.redirected || response.status >= 300 && response.status < 400) throw new IdentityAuthenticationError();
    return response;
  };
  const http = { [oauth.customFetch]: request };
  const server = await oauth.processDiscoveryResponse(new URL(issuer), await oauth.discoveryRequest(new URL(issuer), http));
  for (const endpoint of [server.authorization_endpoint, server.token_endpoint, server.jwks_uri]) {
    if (typeof endpoint !== 'string' || new URL(identityEndpointSchema.parse(endpoint)).origin !== origin) throw new IdentityAuthenticationError();
  }
  if (server.revocation_endpoint && new URL(identityEndpointSchema.parse(server.revocation_endpoint)).origin !== origin) throw new IdentityAuthenticationError();
  if (!server.code_challenge_methods_supported?.includes('S256')) throw new IdentityAuthenticationError();
  const client: oauth.Client = { client_id: options.clientId, token_endpoint_auth_method: 'private_key_jwt' };
  const auth = oauth.PrivateKeyJwt(options.privateKey);
  const verify = createAccessTokenVerifier({ issuer, audience: selected.resource, profile: options.profile,
    verificationKey: options.verificationKey, resolvePrincipal: async identity => {
      const principal = await options.resolvePrincipal(identity);
      if (!principal || principal.kind !== 'human' || principal.clientId !== undefined && principal.clientId !== options.clientId) return null;
      return { ...principal, clientId: options.clientId };
    } });
  const validate = async (token: string, expected: { issuer: string; subject: string }) => {
    const principal = await verify(token);
    if (principal.identity.issuer !== expected.issuer || principal.identity.subject !== expected.subject
      || selected.scopes.some(scope => !principal.scopes.includes(scope))) throw new IdentityAuthenticationError();
    return principal;
  };
  return {
    /** Revalidate a saved server-side access token and current local mapping
     * before use; this never expands the configured resource or scopes. */
    verifyAccessToken: validate,
    /** Caller serializes refreshes and atomically replaces its server-side token record. */
    async refresh(refreshToken: string, expectedIdentity: { issuer: string; subject: string }) {
      try {
        if (!refreshToken || expectedIdentity.issuer !== issuer || !expectedIdentity.subject) throw new IdentityAuthenticationError();
        const response = await oauth.refreshTokenGrantRequest(server, client, auth, refreshToken, http);
        const tokens = await oauth.processRefreshTokenResponse(server, client, response);
        const claims = oauth.getValidatedIdTokenClaims(tokens);
        if (claims) {
          await oauth.validateApplicationLevelSignature(server, response, http);
          if (claims.sub !== expectedIdentity.subject) throw new IdentityAuthenticationError();
        }
        const principal = await validate(tokens.access_token, expectedIdentity);
        return { identity: principal.identity, principal, tokens };
      } catch { throw new IdentityAuthenticationError(); }
    },
    /** Revoke this client's token only; application logout must also delete its local session. */
    async revoke(token: string) {
      try {
        if (!token || !server.revocation_endpoint) throw new IdentityAuthenticationError();
        await oauth.processRevocationResponse(await oauth.revocationRequest(server, client, auth, token, http));
      } catch { throw new IdentityAuthenticationError(); }
    },
    async begin(browserBinding: string): Promise<string> {
      if (!browserBinding) throw new IdentityAuthenticationError();
      const transaction: LoginTransaction = { state: oauth.generateRandomState(), nonce: oauth.generateRandomNonce(),
        verifier: oauth.generateRandomCodeVerifier(), expiresAt: now() + 300_000, issuer, clientId: options.clientId, redirectUri,
        resource: selected.resource, scopes: [...selected.scopes] };
      await options.store.put(browserBinding, transaction);
      const url = new URL(server.authorization_endpoint!);
      url.search = new URLSearchParams({ client_id: options.clientId, redirect_uri: redirectUri, response_type: 'code',
        resource: selected.resource, scope: [...new Set(['openid', ...selected.scopes])].join(' '), state: transaction.state, nonce: transaction.nonce,
        code_challenge: await oauth.calculatePKCECodeChallenge(transaction.verifier), code_challenge_method: 'S256' }).toString();
      return url.href;
    },
    async finish(browserBinding: string, callback: URL) {
      try {
        if (!browserBinding || callback.origin + callback.pathname !== new URL(redirectUri).origin + new URL(redirectUri).pathname || callback.hash) throw new IdentityAuthenticationError();
        const states = callback.searchParams.getAll('state');
        if (states.length !== 1 || !states[0]) throw new IdentityAuthenticationError();
        const transaction = await options.store.consume(browserBinding, states[0]);
        if (!transaction || transaction.state !== states[0] || transaction.expiresAt <= now() || transaction.expiresAt > now() + 300_000
          || transaction.issuer !== issuer || transaction.clientId !== options.clientId || transaction.redirectUri !== redirectUri
          || transaction.resource !== selected.resource || JSON.stringify(transaction.scopes) !== JSON.stringify(selected.scopes)) throw new IdentityAuthenticationError();
        const parameters = oauth.validateAuthResponse(server, client, callback, transaction.state);
        const response = await oauth.authorizationCodeGrantRequest(server, client, auth, parameters, redirectUri, transaction.verifier, http);
        const tokens = await oauth.processAuthorizationCodeResponse(server, client, response, { expectedNonce: transaction.nonce, requireIdToken: true });
        await oauth.validateApplicationLevelSignature(server, response, http);
        const claims = oauth.getValidatedIdTokenClaims(tokens);
        if (!claims) throw new IdentityAuthenticationError();
        const principal = await validate(tokens.access_token, { issuer, subject: claims.sub });
        return { identity: principal.identity, principal, tokens };
      } catch { throw new IdentityAuthenticationError(); }
    },
  };
}

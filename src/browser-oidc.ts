import * as oauth from 'oauth4webapi';
import { identityEndpointSchema } from '@treeseed/sdk/identity';
import { IdentityAuthenticationError } from './access-token.js';

export interface LoginTransaction {
  state: string; nonce: string; verifier: string; expiresAt: number;
  issuer: string; clientId: string; redirectUri: string;
}
/** Server-side only. consume must atomically remove a transaction bound to this browser session. */
export interface LoginTransactionStore {
  put(browserBinding: string, transaction: LoginTransaction): Promise<void>;
  consume(browserBinding: string, state: string): Promise<LoginTransaction | null>;
}
export interface BrowserOidcOptions {
  issuer: string; clientId: string; redirectUri: string;
  privateKey: CryptoKey;
  store: LoginTransactionStore;
  /** Deployment-authorized transport owns private routing and DNS-rebinding protection. */
  transport: typeof fetch;
  now?: () => number;
}

/** Confidential BFF client. Tokens returned by finish must never be sent to browser storage. */
export async function createBrowserOidcClient(options: BrowserOidcOptions) {
  const issuer = identityEndpointSchema.parse(options.issuer);
  const redirectUri = identityEndpointSchema.parse(options.redirectUri);
  if (!options.clientId || options.clientId.length > 256) throw new Error('Invalid client ID.');
  const origin = new URL(issuer).origin;
  const now = options.now ?? Date.now;
  const request: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    if (url.origin !== origin || url.username || url.password || url.hash) throw new IdentityAuthenticationError();
    const response = await options.transport(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(10_000) });
    if (response.redirected || response.status >= 300 && response.status < 400) throw new IdentityAuthenticationError();
    return response;
  };
  const http = { [oauth.customFetch]: request };
  const server = await oauth.processDiscoveryResponse(new URL(issuer), await oauth.discoveryRequest(new URL(issuer), http));
  for (const endpoint of [server.authorization_endpoint, server.token_endpoint, server.jwks_uri]) {
    if (typeof endpoint !== 'string' || new URL(identityEndpointSchema.parse(endpoint)).origin !== origin) throw new IdentityAuthenticationError();
  }
  if (!server.code_challenge_methods_supported?.includes('S256')) throw new IdentityAuthenticationError();
  const client: oauth.Client = { client_id: options.clientId, token_endpoint_auth_method: 'private_key_jwt' };
  const auth = oauth.PrivateKeyJwt(options.privateKey);
  return {
    async begin(browserBinding: string): Promise<string> {
      if (!browserBinding) throw new IdentityAuthenticationError();
      const transaction: LoginTransaction = { state: oauth.generateRandomState(), nonce: oauth.generateRandomNonce(),
        verifier: oauth.generateRandomCodeVerifier(), expiresAt: now() + 300_000, issuer, clientId: options.clientId, redirectUri };
      await options.store.put(browserBinding, transaction);
      const url = new URL(server.authorization_endpoint!);
      url.search = new URLSearchParams({ client_id: options.clientId, redirect_uri: redirectUri, response_type: 'code',
        scope: 'openid', state: transaction.state, nonce: transaction.nonce,
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
          || transaction.issuer !== issuer || transaction.clientId !== options.clientId || transaction.redirectUri !== redirectUri) throw new IdentityAuthenticationError();
        const parameters = oauth.validateAuthResponse(server, client, callback, transaction.state);
        const response = await oauth.authorizationCodeGrantRequest(server, client, auth, parameters, redirectUri, transaction.verifier, http);
        const tokens = await oauth.processAuthorizationCodeResponse(server, client, response, { expectedNonce: transaction.nonce, requireIdToken: true });
        await oauth.validateApplicationLevelSignature(server, response, http);
        const claims = oauth.getValidatedIdTokenClaims(tokens);
        if (!claims) throw new IdentityAuthenticationError();
        return { identity: { issuer, subject: claims.sub }, tokens };
      } catch { throw new IdentityAuthenticationError(); }
    },
  };
}

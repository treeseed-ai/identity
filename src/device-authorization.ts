import * as oauth from 'oauth4webapi';
import { decodeJwt } from 'jose';
import { identityEndpointSchema, resourceTokenRequestSchema } from '@treeseed/sdk/identity';
import { createAccessTokenVerifier, IdentityAuthenticationError, type AccessTokenVerifierOptions } from './access-token.js';

export interface DeviceAuthorizationOptions {
  issuer: string; clientId: string; resources: readonly string[];
  verificationKey: AccessTokenVerifierOptions['verificationKey'];
  resolvePrincipal: AccessTokenVerifierOptions['resolvePrincipal'];
  profile: AccessTokenVerifierOptions['profile'];
  /** Deployment owns TLS trust and authorized network routing. */
  transport: typeof fetch;
  now?: () => number;
}

/** Public CLI client. Device codes are closure-local and never returned for
 * persistence. Successful tokens belong only in the caller's protected store.
 */
export async function createDeviceAuthorizationClient(options: DeviceAuthorizationOptions) {
  const issuer = identityEndpointSchema.parse(options.issuer), origin = new URL(issuer).origin;
  const now = options.now ?? Date.now;
  if (!options.clientId || options.clientId.length > 256 || !options.resources.length || options.resources.length > 64) throw new IdentityAuthenticationError();
  const resources = new Set(options.resources.map(value => identityEndpointSchema.parse(value)));
  if (resources.size !== options.resources.length) throw new IdentityAuthenticationError();
  const transport: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    if (url.origin !== origin || url.username || url.password || url.hash) throw new IdentityAuthenticationError();
    const response = await options.transport(url, { ...init, redirect: 'error',
      signal: AbortSignal.any([AbortSignal.timeout(10_000), ...(init?.signal ? [init.signal] : [])]) });
    if (response.redirected || response.status >= 300 && response.status < 400) throw new IdentityAuthenticationError();
    return response;
  };
  const http = { [oauth.customFetch]: transport };
  let server: oauth.AuthorizationServer;
  try {
    server = await oauth.processDiscoveryResponse(new URL(issuer), await oauth.discoveryRequest(new URL(issuer), http));
    for (const endpoint of [server.device_authorization_endpoint, server.token_endpoint]) {
      if (!endpoint || new URL(identityEndpointSchema.parse(endpoint)).origin !== origin) throw new IdentityAuthenticationError();
    }
  } catch { throw new IdentityAuthenticationError(); }
  const client: oauth.Client = { client_id: options.clientId, token_endpoint_auth_method: 'none' };
  return {
    async begin(input: { resource: string; scopes: string[] }) {
      try {
        const selected = resourceTokenRequestSchema.parse(input);
        if (!resources.has(selected.resource)) throw new IdentityAuthenticationError();
        // Keycloak applies its S256 client policy to device authorization too.
        // Keep the proof private to this pending authorization, never in the
        // user-facing verification URI or persisted CLI configuration.
        let verifier = options.profile === 'keycloak' ? oauth.generateRandomCodeVerifier() : '';
        const response = await oauth.processDeviceAuthorizationResponse(server, client,
          await oauth.deviceAuthorizationRequest(server, client, oauth.None(), {
            resource: selected.resource, ...(selected.scopes.length ? { scope: selected.scopes.join(' ') } : {}),
            ...(verifier ? { code_challenge_method: 'S256', code_challenge: await oauth.calculatePKCECodeChallenge(verifier) } : {}),
          }, http));
        const link = (value: string) => {
          const url = new URL(value);
          if (url.origin !== origin || url.username || url.password || url.hash) throw new IdentityAuthenticationError();
          return url.href;
        };
        const verificationUri = link(response.verification_uri);
        const verificationUriComplete = response.verification_uri_complete ? link(response.verification_uri_complete) : undefined;
        if (!Number.isFinite(response.expires_in) || response.expires_in <= 0 || response.expires_in > 3600
          || !Number.isFinite(response.interval ?? 5) || (response.interval ?? 5) < 1 || (response.interval ?? 5) > 60
          || response.device_code.length > 4096 || response.user_code.length > 128) throw new IdentityAuthenticationError();
        let code = response.device_code, interval = (response.interval ?? 5) * 1000;
        const expiresAt = now() + response.expires_in * 1000, cancellation = new AbortController();
        let nextPollAt = now() + interval, busy = false, terminal = false;
        const end = () => { terminal = true; code = ''; verifier = ''; cancellation.abort(); };
        return {
          userCode: response.user_code, verificationUri, verificationUriComplete, expiresAt,
          cancel: end,
          async poll() {
            if (terminal) throw new IdentityAuthenticationError();
            if (now() >= expiresAt) { end(); return { status: 'expired' as const }; }
            if (busy || now() < nextPollAt) return { status: 'pending' as const, nextPollAt };
            busy = true; nextPollAt = now() + interval;
            try {
              const raw = await oauth.deviceCodeGrantRequest(server, client, oauth.None(), code,
                { ...http, signal: cancellation.signal, additionalParameters: { resource: selected.resource,
                  ...(verifier ? { code_verifier: verifier } : {}) } });
              const tokens = await oauth.processDeviceCodeResponse(server, client, raw);
              if (terminal || now() >= expiresAt || tokens.token_type.toLowerCase() !== 'bearer') throw new IdentityAuthenticationError();
              const verify = createAccessTokenVerifier({ issuer, audience: selected.resource, verificationKey: options.verificationKey,
                resolvePrincipal: options.resolvePrincipal, profile: options.profile });
              const principal = await verify(tokens.access_token);
              const claims = decodeJwt(tokens.access_token);
              if (principal.kind !== 'human' || selected.scopes.some(scope => !principal.scopes.includes(scope))
                || (options.profile === 'keycloak' ? claims.azp : claims.client_id) !== options.clientId) throw new IdentityAuthenticationError();
              const idClaims = oauth.getValidatedIdTokenClaims(tokens);
              if (idClaims) {
                await oauth.validateApplicationLevelSignature(server, raw, http);
                if (idClaims.sub !== principal.identity.subject) throw new IdentityAuthenticationError();
              }
              if (terminal || now() >= expiresAt) throw new IdentityAuthenticationError();
              end();
              return { status: 'authorized' as const, principal, resource: selected.resource, tokens };
            } catch (error) {
              if (!terminal && error instanceof oauth.ResponseBodyError && ['authorization_pending', 'slow_down'].includes(error.error)) {
                if (error.error === 'slow_down') interval += 5000;
                nextPollAt = now() + interval;
                return { status: 'pending' as const, nextPollAt };
              }
              end();
              if (error instanceof oauth.ResponseBodyError && error.error === 'access_denied') return { status: 'denied' as const };
              if (error instanceof oauth.ResponseBodyError && error.error === 'expired_token') return { status: 'expired' as const };
              throw new IdentityAuthenticationError();
            } finally { busy = false; }
          },
        };
      } catch { throw new IdentityAuthenticationError(); }
    },
  };
}

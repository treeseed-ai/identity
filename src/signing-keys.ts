import * as oauth from 'oauth4webapi';
import { createRemoteJWKSet, customFetch, type JWTVerifyGetKey } from 'jose';
import { identityEndpointSchema } from '@treeseed/sdk/identity';
import { IdentityAuthenticationError } from './access-token.js';

/** Issuer-local signing keys for API, browser and native clients. Cache belongs
 * to this resolver, never to another resource/issuer or a caller-writable file.
 * Deployment supplies trusted TLS and routing; redirects cannot change either.
 */
export async function discoverSigningKeys(options: { issuer: string; transport: typeof fetch }): Promise<JWTVerifyGetKey> {
  const issuer = identityEndpointSchema.parse(options.issuer), origin = new URL(issuer).origin;
  const request: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    if (url.origin !== origin || url.username || url.password || url.search || url.hash) throw new IdentityAuthenticationError();
    const response = await options.transport(url, { ...init, method: 'GET', headers: { Accept: 'application/json' },
      credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(5000) });
    if (response.status !== 200 || response.redirected) { await response.body?.cancel(); throw new IdentityAuthenticationError(); }
    const reader = response.body?.getReader(); if (!reader) throw new IdentityAuthenticationError();
    const chunks: Uint8Array[] = []; let size = 0;
    try {
      for (;;) {
        const chunk = await reader.read(); if (chunk.done) break;
        size += chunk.value.byteLength;
        if (size > 131072) throw new IdentityAuthenticationError();
        chunks.push(chunk.value);
      }
    } finally { await reader.cancel(); reader.releaseLock(); }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return new Response(bytes, {status:200, headers:response.headers});
  };
  try {
    const server = await oauth.processDiscoveryResponse(new URL(issuer), await oauth.discoveryRequest(new URL(issuer), { [oauth.customFetch]: request }));
    const endpoint = identityEndpointSchema.parse(server.jwks_uri);
    if (new URL(endpoint).origin !== origin) throw new IdentityAuthenticationError();
    const keys = createRemoteJWKSet(new URL(endpoint), {
      timeoutDuration: 5000, cooldownDuration: 5000, cacheMaxAge: 60000,
      [customFetch]: async (url, init) => {
        if (url !== endpoint) throw new IdentityAuthenticationError();
        const response = await request(url, init);
        const value: unknown = await response.clone().json();
        if (!value || typeof value !== 'object' || !('keys' in value) || !Array.isArray(value.keys) || value.keys.length > 32
          || value.keys.some(key => !key || typeof key !== 'object' || ['d','p','q','dp','dq','qi','oth','k'].some(field => field in key))) throw new IdentityAuthenticationError();
        return response;
      },
    });
    return async (header, token) => {
      try {
        if (header.jku || header.x5u || header.jwk) throw new IdentityAuthenticationError();
        return await keys(header, token);
      } catch { throw new IdentityAuthenticationError(); }
    };
  } catch { throw new IdentityAuthenticationError(); }
}

import * as oauth from 'oauth4webapi';
import { identityEndpointSchema, protectedResourceMetadataSchema } from '@treeseed/sdk/identity';
import { IdentityAuthenticationError } from './access-token.js';

export class IdentityDiscoveryError extends IdentityAuthenticationError {
  constructor(readonly reason: 'invalid_resource_metadata' | 'issuer_selection_required' | 'issuer_not_advertised') {
    super(); this.name = 'IdentityDiscoveryError';
    this.message = reason === 'issuer_selection_required' ? 'Choose an authorization server advertised by this API.'
      : reason === 'issuer_not_advertised' ? 'The selected authorization server is not advertised by this API.' : 'The API returned invalid identity discovery metadata.';
  }
}

/** Resolve only the selected resource's advertised authority, without sending
 * credentials or recursively expanding federation. Multiple issuers require an
 * explicit selection. Deployment still owns endpoint routing and TLS trust.
 */
export async function discoverResourceAuthorization(options: { resource: string; issuer?: string; transport: typeof fetch }) {
  try {
    const resource = identityEndpointSchema.parse(options.resource), origin = new URL(resource).origin;
    const request: typeof fetch = async (input, init) => {
      const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
      if (url.origin !== origin || url.username || url.password || url.hash) throw new IdentityAuthenticationError();
      const response = await options.transport(url, { ...init, headers: { Accept: 'application/json' }, credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(10_000) });
      if (response.status !== 200 || response.redirected) { await response.body?.cancel(); throw new IdentityAuthenticationError(); }
      const reader = response.body?.getReader(); if (!reader) throw new IdentityAuthenticationError();
      const chunks: Uint8Array[] = []; let size = 0;
      try {
        for (;;) {
          const chunk = await reader.read(); if (chunk.done) break;
          size += chunk.value.byteLength;
          if (size > 65536) throw new IdentityAuthenticationError();
          chunks.push(chunk.value);
        }
      } finally { await reader.cancel(); reader.releaseLock(); }
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      return new Response(bytes, { status: 200, headers: response.headers });
    };
    const raw = await oauth.resourceDiscoveryRequest(new URL(resource), { [oauth.customFetch]: request });
    const metadata = protectedResourceMetadataSchema.parse(await oauth.processResourceDiscoveryResponse(new URL(resource), raw));
    const issuer = options.issuer ? identityEndpointSchema.parse(options.issuer)
      : metadata.authorization_servers.length === 1 ? metadata.authorization_servers[0] : undefined;
    if (!issuer) throw new IdentityDiscoveryError('issuer_selection_required');
    if (!metadata.authorization_servers.includes(issuer)) throw new IdentityDiscoveryError('issuer_not_advertised');
    return { resource: metadata.resource, issuer, scopesSupported: metadata.scopes_supported ?? [] };
  } catch (error) { throw error instanceof IdentityDiscoveryError ? error : new IdentityDiscoveryError('invalid_resource_metadata'); }
}

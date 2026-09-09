import { identityEndpointSchema, resourceTokenRequestSchema, type IdentityCredentials } from '@treeseed/sdk/identity';

interface ApplicationBase {
  clientId: string;
  resource: string;
  scopes: string[];
  redirectUris: string[];
}
export type KeycloakApplication = ApplicationBase & ({
  kind: 'browser' | 'workload';
  /** Base64 DER X.509 public certificate; Deployment retains the private key. */
  certificate: string;
} | { kind: 'native'; deviceAuthorization: boolean; certificate?: never });

const owner = 'treeseed-deployment';
const canonical = (value: unknown): string => JSON.stringify(value, (_key, item) =>
  item && typeof item === 'object' && !Array.isArray(item)
    ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);
const sorted = (value: unknown) => Array.isArray(value) ? [...value].sort() : [];
const mappers = (value: unknown) => Array.isArray(value) ? value.map(({ id: _id, ...mapper }) => mapper).sort((a,b) => String(a.name).localeCompare(String(b.name))) : [];

function desiredClient(input: KeycloakApplication) {
  resourceTokenRequestSchema.parse({ resource: input.resource, scopes: input.scopes });
  const native = input.kind === 'native';
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(input.clientId) || input.clientId === 'treeseed-identity-reconciler'
    || !['browser', 'workload', 'native'].includes(input.kind)
    || (native ? 'certificate' in input || typeof input.deviceAuthorization !== 'boolean'
      : !/^[A-Za-z0-9+/]{100,32766}={0,2}$/u.test(input.certificate))
    || input.scopes.some(scope => ['openid', 'roles', 'offline_access'].includes(scope))
    || input.redirectUris.length > 16 || new Set(input.redirectUris).size !== input.redirectUris.length
    || (input.kind === 'browser' ? !input.redirectUris.length : native ? !input.redirectUris.length && !input.deviceAuthorization : input.redirectUris.length !== 0)) throw new Error('Invalid managed Identity application');
  const redirects = input.redirectUris.map(uri => {
    if (native) {
      // Keycloak's RFC8252 loopback rule varies only the port at request time.
      // Register a literal IP and exact path, never localhost or a wildcard.
      if (!/^http:\/\/(?:127\.0\.0\.1|\[::1\])\/[A-Za-z0-9/_-]*$/u.test(uri)) throw new Error('Exact native loopback callback required');
      return uri;
    }
    const parsed = identityEndpointSchema.parse(uri);
    if (parsed.includes('*')) throw new Error('Exact browser redirect required');
    return parsed;
  });
  return { clientId: input.clientId, enabled: true, protocol: 'openid-connect', publicClient: native,
    clientAuthenticatorType: native ? 'client-secret' : 'client-jwt', serviceAccountsEnabled: input.kind === 'workload',
    standardFlowEnabled: input.kind === 'browser' || native && redirects.length > 0, implicitFlowEnabled: false, directAccessGrantsEnabled: false,
    fullScopeAllowed: false, consentRequired: native, redirectUris: sorted(redirects), webOrigins: [],
    // Keycloak attaches its service-account identity scope when enabling this
    // flow. Declare it only for workload clients; it is not a role grant.
    defaultClientScopes: input.kind === 'workload' ? ['basic', 'service_account'] : ['basic'], optionalClientScopes: sorted(input.scopes),
    attributes: { 'treeseed.managed-by': owner,
      ...(native ? { 'oauth2.device.authorization.grant.enabled': String(input.deviceAuthorization) }
        : { 'jwt.credential.certificate': input.certificate, 'token.endpoint.auth.signing.alg': 'RS256' }),
      'pkce.code.challenge.method': 'S256', 'access.token.lifespan': '300' },
    protocolMappers: [{ name: 'treeseed-resource', protocol: 'openid-connect', protocolMapper: 'oidc-audience-mapper', consentRequired: false,
      config: { 'included.custom.audience': input.resource, 'access.token.claim': 'true', 'id.token.claim': 'false', 'userinfo.token.claim': 'false' } }],
  };
}

/** Initial registration and repeatable read-back, not silent drift overwrite.
 * All scopes must already be provisioned by Deployment. An existing unmanaged
 * client or changed configuration requires an explicit reconciliation plan.
 * Never grants realm roles, API memberships, or application authorization.
 */
export function createKeycloakApplicationRegistry(options: {
  issuer: string; credentials: IdentityCredentials; transport: typeof fetch;
}) {
  const issuer = new URL(identityEndpointSchema.parse(options.issuer));
  const match = issuer.pathname.match(/^(.*)\/realms\/([A-Za-z0-9_-]+)$/u);
  if (!match) throw new Error('Explicit Keycloak realm issuer required');
  const resource = `${issuer.origin}${match[1]}/admin/realms/${match[2]}`;
  async function request(path: string, method = 'GET', body?: unknown) {
    try {
      const token = await options.credentials.token({ resource, scopes: [] });
      const response = await options.transport(`${resource}/${path}`, { method, redirect: 'error', credentials: 'omit',
        signal: AbortSignal.timeout(15_000), headers: { accept: 'application/json', authorization: `Bearer ${token}`,
          ...(body === undefined ? {} : { 'content-type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      if (response.redirected || !response.ok) { await response.body?.cancel(); throw new Error(); }
      if (method !== 'GET') { await response.body?.cancel(); return null; }
      const reader = response.body?.getReader(); if (!reader) throw new Error();
      const chunks: Uint8Array[] = []; let size = 0;
      try { for (;;) { const chunk = await reader.read(); if (chunk.done) break;
        size += chunk.value.byteLength; if (size > 262144) throw new Error(); chunks.push(chunk.value);
      } } finally { await reader.cancel(); reader.releaseLock(); }
      const buffer = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { buffer.set(chunk, offset); offset += chunk.byteLength; }
      return JSON.parse(new TextDecoder().decode(buffer));
    } catch { throw new Error('Identity application registry unavailable'); }
  }
  async function read(clientId: string): Promise<Record<string, any> | null> {
    const values = await request(`clients?${new URLSearchParams({ clientId, search: 'false', max: '2' })}`);
    if (!Array.isArray(values) || values.length > 1 || values.some(value => value?.clientId !== clientId || typeof value.id !== 'string'))
      throw new Error('Ambiguous Identity application registration');
    return values[0] ?? null;
  }
  function verify(actual: Record<string, any>, expected: ReturnType<typeof desiredClient>) {
    if (actual.attributes?.['treeseed.managed-by'] !== owner) throw new Error('Existing Identity application is not managed by Deployment');
    for (const [key, value] of Object.entries(expected)) {
      const observed = key === 'attributes' ? Object.fromEntries(Object.keys(value).map(name => [name, actual.attributes?.[name]]))
        : key === 'protocolMappers' ? mappers(actual[key]) : Array.isArray(value) ? sorted(actual[key]) : actual[key];
      // The field name comes from our own fixed representation, never provider
      // content. Report the boundary without certificates, tokens or values.
      if (canonical(observed) !== canonical(value)) throw new Error(`Identity application drift in ${key} requires a reconciliation plan`);
    }
  }
  return { async ensure(input: KeycloakApplication) {
    const expected = desiredClient(input), existing = await read(input.clientId);
    if (existing) { verify(existing, expected); return { action: 'noop' as const, clientId: input.clientId, id: existing.id as string }; }
    await request('clients', 'POST', expected);
    const actual = await read(input.clientId);
    if (!actual) throw new Error('Identity application read-back is missing');
    verify(actual, expected);
    return { action: 'create' as const, clientId: input.clientId, id: actual.id as string };
  } };
}

import { identityEndpointSchema, type IdentityCredentials } from '@treeseed/sdk/identity';

export interface KeycloakAccountImport {
  sourceResource: string;
  sourceUserId: string;
  username: string;
  email: string;
  emailVerified: boolean;
  credential: { type: 'password'; temporary: false; credentialData: string; secretData: string };
}

const markerName = 'treeseedSourceAccount';
const markerDefinition = { name: markerName, displayName: 'TreeSeed source account', multivalued: false,
  permissions: { view: ['admin'], edit: ['admin'] } };
const object = (input: unknown): Record<string, unknown> => input && typeof input === 'object' && !Array.isArray(input)
  ? input as Record<string, unknown> : {};

/** Maintenance-only hash import. The API owns source inventory and mapping;
 * this adapter never authenticates passwords, infers email-based account links,
 * or supplies team/application permissions. The fixed admin-only marker makes
 * interrupted creates replayable without adopting an unrelated existing user.
 */
export function createKeycloakAccountImporter(options: {
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
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      try { return JSON.parse(new TextDecoder().decode(bytes)) as unknown; }
      finally { bytes.fill(0); for (const chunk of chunks) chunk.fill(0); }
    } catch { throw new Error('Identity account import request failed'); }
  }
  let policyReady = false;
  async function policy() {
    if (policyReady) return;
    const profile = object(await request('users/profile'));
    if (!Array.isArray(profile.attributes)) throw new Error('Identity user-profile policy unavailable');
    const definitions = profile.attributes.map(object).filter(value => value.name === markerName);
    if (definitions.length === 0) {
      await request('users/profile', 'PUT', { ...profile, attributes: [...profile.attributes, markerDefinition] });
      const actual = object(await request('users/profile'));
      if (!Array.isArray(actual.attributes)) throw new Error('Identity user-profile policy read-back failed');
      definitions.push(...actual.attributes.map(object).filter(value => value.name === markerName));
    }
    const definition = definitions[0], permissions = object(definition?.permissions);
    if (definitions.length !== 1 || definition?.multivalued === true
      || JSON.stringify(permissions.view) !== '["admin"]' || JSON.stringify(permissions.edit) !== '["admin"]')
      throw new Error('Identity migration marker must be administrator-only');
    policyReady = true;
  }
  async function users(query: Record<string, string>) {
    const result = await request(`users?${new URLSearchParams({ ...query, exact: 'true', max: '2', briefRepresentation: 'false' })}`);
    if (!Array.isArray(result) || result.length > 1) throw new Error('Ambiguous Identity account import');
    return result.map(object);
  }
  return { async importAccount(input: KeycloakAccountImport) {
    identityEndpointSchema.parse(input.sourceResource);
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(input.sourceUserId)
      || typeof input.username !== 'string' || !input.username.trim() || input.username.length > 256 || /[\x00-\x1f]/u.test(input.username)
      || typeof input.email !== 'string' || !/^[^\s@]+@[^\s@]+$/u.test(input.email) || input.email.length > 320
      || typeof input.emailVerified !== 'boolean' || input.credential?.type !== 'password' || input.credential.temporary !== false
      || typeof input.credential.credentialData !== 'string' || input.credential.credentialData.length > 4096
      || typeof input.credential.secretData !== 'string' || input.credential.secretData.length > 4096) throw new Error('Invalid account import descriptor');
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify([input.sourceResource, input.sourceUserId])));
    const marker = [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, '0')).join('');
    await policy();
    const bySource = await users({ q: `${markerName}:${marker}` });
    const verify = (user: Record<string, unknown>) => {
      if (typeof user.id !== 'string' || !/^[A-Za-z0-9-]{1,128}$/u.test(user.id) || user.enabled !== true
        || JSON.stringify(object(user.attributes)[markerName]) !== JSON.stringify([marker])) throw new Error('Identity account ownership read-back failed');
      return { issuer: options.issuer, subject: user.id, sourceUserId: input.sourceUserId };
    };
    if (bySource[0]) return { ...verify(bySource[0]), action: 'noop' as const };
    // A matching email/username is a collision, never proof of account ownership.
    if ((await users({ username: input.username })).length || (await users({ email: input.email })).length)
      throw new Error('Existing Identity account requires explicit account linking');
    await request('users', 'POST', { username: input.username, email: input.email, emailVerified: input.emailVerified, enabled: true,
      attributes: { [markerName]: [marker] }, credentials: [input.credential] });
    const actual = (await users({ q: `${markerName}:${marker}` }))[0];
    if (!actual) throw new Error('Identity account import read-back missing');
    return { ...verify(actual), action: 'create' as const };
  } };
}

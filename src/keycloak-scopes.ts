type Request = (path: string, method?: string, body?: unknown) => Promise<any>;
const owner = 'treeseed-deployment';
const reserved = new Set(['openid', 'roles', 'offline_access', 'profile', 'email', 'address', 'phone', 'basic', 'service_account', 'web-origins', 'acr', 'microprofile-jwt']);

export function validateManagedScopes(scopes: string[]) {
  if (scopes.some(scope => reserved.has(scope) || !/^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$/u.test(scope)))
    throw new Error('Managed application scopes must be custom, bounded permission labels');
}

/** Scope labels carry no roles, claims or resource audience. API authorization
 * remains separate. Never adopt or overwrite preexisting scope definitions.
 */
export async function ensureManagedScopes(request: Request, scopes: string[]) {
  validateManagedScopes(scopes);
  if (!scopes.length) return;
  const read = async () => {
    const values = await request('client-scopes');
    if (!Array.isArray(values) || values.length > 4096) throw new Error('Invalid Identity scope inventory');
    return values;
  };
  const select = (values: any[], name: string) => {
    const matches = values.filter(value => value?.name === name);
    if (matches.length > 1) throw new Error('Ambiguous Identity scope inventory');
    return matches[0];
  };
  const expected = (name: string) => ({ name, protocol: 'openid-connect',
    attributes: { 'treeseed.managed-by': owner, 'include.in.token.scope': 'true', 'display.on.consent.screen': 'true' },
    protocolMappers: [] });
  const verify = async (actual: any, name: string) => {
    if (!actual || !/^[A-Za-z0-9-]{1,128}$/u.test(actual.id) || actual.name !== name || actual.protocol !== 'openid-connect'
      || Object.entries(expected(name).attributes).some(([key, value]) => actual.attributes?.[key] !== value)
      || actual.protocolMappers != null && (!Array.isArray(actual.protocolMappers) || actual.protocolMappers.length))
      throw new Error('Identity scope custody or policy drift requires a plan');
    const grants = await request(`client-scopes/${encodeURIComponent(actual.id)}/scope-mappings`);
    if (!grants || typeof grants !== 'object' || Array.isArray(grants)
      || Object.keys(grants).some(key => !['realmMappings', 'clientMappings'].includes(key))
      || grants.realmMappings != null && (!Array.isArray(grants.realmMappings) || grants.realmMappings.length)
      || grants.clientMappings != null && (typeof grants.clientMappings !== 'object' || Array.isArray(grants.clientMappings) || Object.keys(grants.clientMappings).length))
      throw new Error('Managed Identity scopes cannot grant realm or client roles');
  };
  const observed = await read();
  // Resolve every known conflict before creating any missing scope.
  for (const name of scopes) { const actual = select(observed, name); if (actual) await verify(actual, name); }
  for (const name of scopes) {
    if (select(observed, name)) continue;
    await request('client-scopes', 'POST', expected(name));
    await verify(select(await read(), name), name);
  }
}

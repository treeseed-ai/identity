import { BROWSER_SESSION_BRIDGE_PATH, BROWSER_SESSION_SCOPE, browserSessionResponses,
  identityEndpointSchema, type IdentityCredentials, type BrowserSessionCredentials } from '@treeseed/sdk/identity';
import { IdentityAuthenticationError } from './access-token.js';

export interface ApplicationSessionOptions {
  resource: string; issuer: string; callbackUrl: string; afterLogin: string;
  /** Distinct __Host- cookie name for each configured resource/client. */
  cookieName: string;
  credentials: IdentityCredentials;
  /** Deployment-approved server transport; never a browser fetch client. */
  transport: typeof fetch;
}

const opaque = /^[A-Za-z0-9_-]{43}$/u;
async function safe<T>(run: () => Promise<T>): Promise<T> {
  try { return await run(); } catch { throw new IdentityAuthenticationError(); }
}
async function json(response: Response): Promise<Record<string, unknown>> {
  if (!response.body || Number(response.headers.get('content-length') ?? 0) > 65536) throw new IdentityAuthenticationError();
  const reader = response.body.getReader(), chunks: Uint8Array[] = []; let size = 0;
  try {
    for (;;) { const next = await reader.read(); if (next.done) break; size += next.value.length;
      if (size > 65536) throw new IdentityAuthenticationError(); chunks.push(next.value); }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    const value: unknown = JSON.parse(new TextDecoder().decode(bytes));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new IdentityAuthenticationError();
    return value as Record<string, unknown>;
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
}

/** Shared server adapter for independent Admin/Market/custom applications.
 * The browser receives opaque cookies only. session() is a server-only value
 * for authenticated API calls, never data to serialize to HTML or browser JSON.
 */
export function createApplicationSession(options: ApplicationSessionOptions) {
  const resource = identityEndpointSchema.parse(options.resource), issuer = identityEndpointSchema.parse(options.issuer);
  const callback = new URL(identityEndpointSchema.parse(options.callbackUrl));
  if (!/^__Host-[A-Za-z0-9_-]{1,80}$/u.test(options.cookieName)) throw new IdentityAuthenticationError();
  const landing = new URL(options.afterLogin, callback.origin);
  if (landing.origin !== callback.origin || landing.username || landing.password) throw new IdentityAuthenticationError();
  const loginCookie = `${options.cookieName}-login`;
  const returnCookie = `${options.cookieName}-return`;
  const navigation = (value: string) => {
    if (value.length > 2048) throw new IdentityAuthenticationError();
    const target = new URL(value, callback.origin);
    if (target.origin !== callback.origin || target.username || target.password) throw new IdentityAuthenticationError();
    return target.href;
  };
  const cookie = (name: string, value: string, seconds: number) => `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${seconds}`;
  const read = (request: Request, name: string) => {
    const entries = (request.headers.get('cookie') ?? '').split(';').map(value => value.trim()).filter(value => value.startsWith(`${name}=`));
    if (!entries.length) return null;
    const value = entries[0]!.slice(name.length + 1);
    if (entries.length !== 1 || !opaque.test(value)) throw new IdentityAuthenticationError();
    return value;
  };
  const trustedRequest = (request: Request) => {
    if (new URL(request.url).origin !== callback.origin) throw new IdentityAuthenticationError();
  };
  const invoke = async (operation: keyof typeof browserSessionResponses, body: object) => {
    try {
      const token = await options.credentials.token({ resource, scopes: [BROWSER_SESSION_SCOPE] });
      if (!token || token.length > 16384 || /\s/u.test(token)) throw new IdentityAuthenticationError();
      const response = await options.transport(`${resource.replace(/\/$/u, '')}${BROWSER_SESSION_BRIDGE_PATH}/${operation}`, {
        method: 'POST', credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(15000),
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify(body),
      });
      if (response.redirected || response.status >= 300 && response.status < 400) throw new IdentityAuthenticationError();
      const result = await json(response);
      if (response.status === 401 && result.error === 'browser_session_unavailable') return null;
      if (!response.ok) throw new IdentityAuthenticationError();
      return result.data;
    } catch { throw new IdentityAuthenticationError(); }
  };
  const redirect = (url: string, cookies: string[]) => {
    const headers = new Headers({ location: url, 'cache-control': 'no-store' });
    for (const value of cookies) headers.append('set-cookie', value);
    return new Response(null, { status: 303, headers });
  };
  return {
    async login(request: Request, returnTo = options.afterLogin) {
      return safe(async () => {
      trustedRequest(request);
      if (request.method !== 'GET') throw new IdentityAuthenticationError();
      const destination = navigation(returnTo);
      const bytes = crypto.getRandomValues(new Uint8Array(32));
      const binding = btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
      const result = browserSessionResponses.begin.parse(await invoke('begin', { browserBinding: binding }));
      if (new URL(result.authorizationUrl).origin !== new URL(issuer).origin) throw new IdentityAuthenticationError();
      return redirect(result.authorizationUrl, [cookie(loginCookie, binding, 300),
        cookie(returnCookie, encodeURIComponent(JSON.stringify({ binding, destination })), 300)]);
      });
    },
    async callback(request: Request) {
      return safe(async () => {
      trustedRequest(request); const url = new URL(request.url), binding = read(request, loginCookie);
      if (request.method !== 'GET' || url.pathname !== callback.pathname || !binding) throw new IdentityAuthenticationError();
      const returns = (request.headers.get('cookie') ?? '').split(';').map(value => value.trim()).filter(value => value.startsWith(`${returnCookie}=`));
      if (returns.length > 1) throw new IdentityAuthenticationError();
      let destination = landing.href;
      if (returns.length) {
        const stored = JSON.parse(decodeURIComponent(returns[0]!.slice(returnCookie.length + 1))) as { binding?: unknown; destination?: unknown };
        if (stored.binding !== binding || typeof stored.destination !== 'string') throw new IdentityAuthenticationError();
        destination = navigation(stored.destination);
      }
      const result = browserSessionResponses.finish.parse(await invoke('finish', { browserBinding: binding, callback: url.href }));
      const seconds = Math.floor((Date.parse(result.expiresAt) - Date.now()) / 1000);
      if (seconds < 1 || seconds > 86400) throw new IdentityAuthenticationError();
      return redirect(destination, [cookie(loginCookie, '', 0), cookie(returnCookie, '', 0), cookie(options.cookieName, result.handle, seconds)]);
      });
    },
    async session(request: Request): Promise<BrowserSessionCredentials | null> {
      return safe(async () => {
      trustedRequest(request); const handle = read(request, options.cookieName); if (!handle) return null;
      const value = await invoke('credentials', { handle }); if (value === null) return null;
      const result = browserSessionResponses.credentials.parse(value);
      if (result.resource !== resource || result.principal.identity.issuer !== issuer || result.expiresAt <= Date.now()) throw new IdentityAuthenticationError();
      return result;
      });
    },
    async logout(request: Request) {
      return safe(async () => {
      trustedRequest(request);
      // Strict Origin verification is the CSRF boundary for cookie-authenticated logout.
      if (request.method !== 'POST' || request.headers.get('origin') !== callback.origin) throw new IdentityAuthenticationError();
      const handle = read(request, options.cookieName);
      if (handle) { const value = await invoke('logout', { handle }); if (value !== null) browserSessionResponses.logout.parse(value); }
      return redirect(callback.origin, [cookie(options.cookieName, '', 0), cookie(loginCookie, '', 0), cookie(returnCookie, '', 0)]);
      });
    },
  };
}

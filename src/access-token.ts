import { decodeProtectedHeader, jwtVerify, type JWTVerifyGetKey } from 'jose';
import { externalIdentitySchema, identityEndpointSchema, identityPrincipalSchema, resourceTokenRequestSchema, type ExternalIdentity, type IdentityPrincipal } from '@treeseed/sdk/identity';

export class IdentityAuthenticationError extends Error {
  readonly code = 'identity_authentication_failed';
  constructor() { super('Identity authentication failed.'); this.name = 'IdentityAuthenticationError'; }
}

export interface AccessTokenVerifierOptions {
  issuer: string;
  audience: string;
  profile: 'keycloak' | 'rfc9068';
  verificationKey: CryptoKey | JWTVerifyGetKey;
  resolvePrincipal(identity: ExternalIdentity): Promise<Pick<IdentityPrincipal, 'principalId' | 'kind'> | null>;
  maxLifetimeSeconds?: number;
  now?: () => Date;
}

/** Authentication only: consumers must separately authorize every resource operation. */
export function createAccessTokenVerifier(options: AccessTokenVerifierOptions) {
  const issuer = identityEndpointSchema.parse(options.issuer);
  const audience = identityEndpointSchema.parse(options.audience);
  if (!['keycloak', 'rfc9068'].includes(options.profile)) throw new Error('Unsupported access-token profile.');
  const maxLifetime = options.maxLifetimeSeconds ?? 300;
  if (!Number.isSafeInteger(maxLifetime) || maxLifetime < 1 || maxLifetime > 3600) throw new Error('Invalid maximum token lifetime.');
  return async (token: string): Promise<IdentityPrincipal> => {
    try {
      if (typeof token !== 'string' || token.length > 16384) throw new IdentityAuthenticationError();
      const header = decodeProtectedHeader(token);
      if (header.jku || header.x5u || header.jwk) throw new IdentityAuthenticationError();
      const now = options.now?.() ?? new Date();
      const verifyOptions = { issuer, audience, algorithms: ['RS256', 'PS256', 'ES256'],
        requiredClaims: ['iss', 'sub', 'aud', 'iat', 'exp'], currentDate: now, clockTolerance: 0 };
      const verified = typeof options.verificationKey === 'function'
        ? await jwtVerify(token, options.verificationKey, verifyOptions)
        : await jwtVerify(token, options.verificationKey, verifyOptions);
      const { payload, protectedHeader } = verified;
      const seconds = Math.floor(now.getTime() / 1000);
      if (!Number.isFinite(seconds) || typeof payload.iat !== 'number' || typeof payload.exp !== 'number'
        || payload.iat > seconds || payload.exp <= payload.iat || payload.exp - payload.iat > maxLifetime) throw new IdentityAuthenticationError();
      if (options.profile === 'keycloak' ? payload.typ !== 'Bearer' : !['at+jwt', 'application/at+jwt'].includes(protectedHeader.typ ?? '')) throw new IdentityAuthenticationError();
      if (payload.act !== undefined) throw new IdentityAuthenticationError();
      if (payload.scope !== undefined && typeof payload.scope !== 'string') throw new IdentityAuthenticationError();
      const { scopes } = resourceTokenRequestSchema.parse({ resource: audience,
        scopes: typeof payload.scope === 'string' && payload.scope ? payload.scope.split(' ') : [] });
      const identity = externalIdentitySchema.parse({ issuer, subject: payload.sub });
      const principal = await options.resolvePrincipal(identity);
      if (!principal) throw new IdentityAuthenticationError();
      return identityPrincipalSchema.parse({ principalId: principal.principalId, kind: principal.kind, identity, audience, scopes });
    } catch { throw new IdentityAuthenticationError(); }
  };
}

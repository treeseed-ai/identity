import type { ExternalIdentity } from '@treeseed/sdk/identity';

/** Profile claims are presentation only: never authorization or email linking. */
export interface BrowserEnrollmentProfile {
  identity: ExternalIdentity;
  email?: string;
  emailVerified: boolean;
  firstName?: string;
  lastName?: string;
  displayName?: string;
}
export function browserEnrollmentProfile(issuer: string, claims: Record<string, unknown>): BrowserEnrollmentProfile {
  const text = (value: unknown, maximum: number) => typeof value === 'string' && value.length <= maximum
    && !/[\u0000-\u001f\u007f]/u.test(value) && value.trim() ? value.trim() : undefined;
  const subject = text(claims.sub, 255);
  if (!subject) throw new Error('Invalid browser identity profile');
  return { identity: { issuer, subject }, email: text(claims.email, 320), emailVerified: claims.email_verified === true,
    firstName: text(claims.given_name, 128), lastName: text(claims.family_name, 128), displayName: text(claims.name, 256) };
}

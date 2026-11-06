/**
 * Domain constants and types shared by the API, worker, database schema and web app.
 * Keep this package free of runtime dependencies so it can be imported anywhere.
 */

export const PLANS = ['free', 'pro'] as const;
export type Plan = (typeof PLANS)[number];

export const SUBSCRIPTION_STATUSES = ['active', 'trialing', 'past_due', 'canceled'] as const;
export type SubscriptionStatus = (typeof SUBSCRIPTION_STATUSES)[number];

export const VERIFY_METHODS = ['dns_txt', 'file'] as const;
export type VerifyMethod = (typeof VERIFY_METHODS)[number];

export const SCAN_KINDS = ['external', 'inside'] as const;
export type ScanKind = (typeof SCAN_KINDS)[number];

export const SCAN_TRIGGERS = ['manual', 'scheduled', 'plugin'] as const;
export type ScanTrigger = (typeof SCAN_TRIGGERS)[number];

export const SCAN_STATUSES = ['queued', 'running', 'completed', 'failed'] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

/** Ordered most to least severe. */
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SOFTWARE_TYPES = ['core', 'plugin', 'theme', 'php'] as const;
export type SoftwareType = (typeof SOFTWARE_TYPES)[number];

export const VULN_SOURCES = ['wordfence', 'osv', 'nvd'] as const;
export type VulnSource = (typeof VULN_SOURCES)[number];

export const USER_TOKEN_PURPOSES = ['email_verify', 'password_reset'] as const;
export type UserTokenPurpose = (typeof USER_TOKEN_PURPOSES)[number];

export const SERVICE_REQUEST_STATUSES = ['open', 'in_progress', 'closed'] as const;
export type ServiceRequestStatus = (typeof SERVICE_REQUEST_STATUSES)[number];

/** Password rules shared by the API (enforced) and the web app (hinted). */
export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

/** Ownership checks older than this must be repeated before a scan may run. */
export const VERIFICATION_TTL_HOURS = 24;

/** Maximum sites per account. */
export const SITE_LIMITS: Record<Plan, number> = { free: 3, pro: 25 };

export type SiteStatus = 'verified' | 'stale' | 'unverified';

/** verified = checked within the TTL; stale = verified before but needs re-checking. */
export function siteStatus(verifiedAt: Date | string | null, now: number = Date.now()): SiteStatus {
  if (!verifiedAt) return 'unverified';
  const at = typeof verifiedAt === 'string' ? Date.parse(verifiedAt) : verifiedAt.getTime();
  return now - at < VERIFICATION_TTL_HOURS * 60 * 60 * 1000 ? 'verified' : 'stale';
}

/** A paid plan only counts while its subscription is in good standing. */
export function effectivePlan(plan: Plan | null | undefined, status: SubscriptionStatus | null | undefined): Plan {
  return plan === 'pro' && (status === 'active' || status === 'trialing') ? 'pro' : 'free';
}

export * from './domain';

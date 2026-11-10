import { sql } from 'drizzle-orm';
import {
  bigserial,
  boolean,
  char,
  check,
  index,
  inet,
  integer,
  jsonb,
  numeric,
  pgEnum,
  pgTable,
  primaryKey,
  smallint,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  CONFIDENCES,
  PLANS,
  SCAN_KINDS,
  SCAN_STATUSES,
  SCAN_TRIGGERS,
  SERVICE_REQUEST_STATUSES,
  SEVERITIES,
  SOFTWARE_TYPES,
  SUBSCRIPTION_STATUSES,
  USER_TOKEN_PURPOSES,
  VERIFY_METHODS,
  VULN_SOURCES,
} from '@shc/shared';

const tz = { withTimezone: true } as const;
const createdAt = () => timestamp('created_at', tz).notNull().defaultNow();
const updatedAt = () => timestamp('updated_at', tz).notNull().defaultNow();

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------
export const planEnum = pgEnum('plan', PLANS);
export const subStatusEnum = pgEnum('sub_status', SUBSCRIPTION_STATUSES);
export const verifyMethodEnum = pgEnum('verify_method', VERIFY_METHODS);
export const scanKindEnum = pgEnum('scan_kind', SCAN_KINDS);
export const scanTriggerEnum = pgEnum('scan_trigger', SCAN_TRIGGERS);
export const scanStatusEnum = pgEnum('scan_status', SCAN_STATUSES);
export const severityEnum = pgEnum('severity', SEVERITIES);
export const softwareTypeEnum = pgEnum('software_type', SOFTWARE_TYPES);
export const vulnSourceEnum = pgEnum('vuln_source', VULN_SOURCES);
export const userTokenPurposeEnum = pgEnum('user_token_purpose', USER_TOKEN_PURPOSES);
export const serviceRequestStatusEnum = pgEnum('service_request_status', SERVICE_REQUEST_STATUSES);
export const confidenceEnum = pgEnum('confidence', CONFIDENCES);

// ---------------------------------------------------------------------------
// Accounts and auth
// ---------------------------------------------------------------------------
export const users = pgTable(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    /** Always stored trimmed and lower-cased. */
    email: text('email').notNull(),
    /** argon2id encoded hash. */
    passwordHash: text('password_hash').notNull(),
    emailVerifiedAt: timestamp('email_verified_at', tz),
    failedLogins: integer('failed_logins').notNull().default(0),
    lockedUntil: timestamp('locked_until', tz),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    unique('users_email_key').on(t.email),
    check('users_email_lowercase', sql`${t.email} = lower(${t.email})`),
  ],
);

export const sessions = pgTable(
  'sessions',
  {
    /** SHA-256 of the cookie token. The raw token is never stored. */
    idHash: text('id_hash').primaryKey(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    expiresAt: timestamp('expires_at', tz).notNull(),
    createdAt: createdAt(),
    lastSeenAt: timestamp('last_seen_at', tz).notNull().defaultNow(),
    ip: inet('ip'),
    userAgent: text('user_agent'),
  },
  (t) => [index('sessions_user_id_idx').on(t.userId), index('sessions_expires_at_idx').on(t.expiresAt)],
);

export const userTokens = pgTable(
  'user_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    purpose: userTokenPurposeEnum('purpose').notNull(),
    /** SHA-256 of the emailed token. */
    tokenHash: text('token_hash').notNull(),
    expiresAt: timestamp('expires_at', tz).notNull(),
    usedAt: timestamp('used_at', tz),
    createdAt: createdAt(),
  },
  (t) => [unique('user_tokens_token_hash_key').on(t.tokenHash), index('user_tokens_user_id_idx').on(t.userId)],
);

export const subscriptions = pgTable('subscriptions', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id')
    .notNull()
    .unique('subscriptions_user_id_key')
    .references(() => users.id, { onDelete: 'cascade' }),
  plan: planEnum('plan').notNull().default('free'),
  status: subStatusEnum('status').notNull().default('active'),
  provider: text('provider').notNull().default('stub'),
  providerRef: text('provider_ref'),
  currentPeriodEnd: timestamp('current_period_end', tz),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

// ---------------------------------------------------------------------------
// Sites and ownership
// ---------------------------------------------------------------------------
export const sites = pgTable(
  'sites',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    ownerId: uuid('owner_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    /** Normalised hostname: lower-case, punycode, no scheme, port or path. */
    domain: text('domain').notNull(),
    verificationMethod: verifyMethodEnum('verification_method'),
    /** Random value the owner publishes in DNS or in a file. Not a secret. */
    verificationToken: text('verification_token').notNull(),
    /** Last successful ownership check. Scans re-verify when this is older than 24 hours. */
    verifiedAt: timestamp('verified_at', tz),
    lastVerifyAttemptAt: timestamp('last_verify_attempt_at', tz),
    lastVerifyError: text('last_verify_error'),
    weeklyScan: boolean('weekly_scan').notNull().default(false),
    nextScanAt: timestamp('next_scan_at', tz),
    createdAt: createdAt(),
  },
  (t) => [
    unique('sites_owner_domain_key').on(t.ownerId, t.domain),
    index('sites_next_scan_at_idx').on(t.nextScanAt).where(sql`${t.weeklyScan}`),
    check('sites_domain_lowercase', sql`${t.domain} = lower(${t.domain})`),
  ],
);

// ---------------------------------------------------------------------------
// Scans and findings
// ---------------------------------------------------------------------------
export interface ModuleResult {
  module: string;
  status: 'ok' | 'skipped' | 'failed' | 'budget_exhausted';
  durationMs: number;
  requests: number;
  findings: number;
  note?: string;
}

export const scans = pgTable(
  'scans',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    siteId: uuid('site_id')
      .notNull()
      .references(() => sites.id, { onDelete: 'cascade' }),
    requestedBy: uuid('requested_by').references(() => users.id, { onDelete: 'set null' }),
    kind: scanKindEnum('kind').notNull(),
    trigger: scanTriggerEnum('trigger').notNull(),
    status: scanStatusEnum('status').notNull().default('queued'),
    createdAt: createdAt(),
    startedAt: timestamp('started_at', tz),
    finishedAt: timestamp('finished_at', tz),
    score: smallint('score'),
    grade: char('grade', { length: 1 }),
    requestCount: integer('request_count').notNull().default(0),
    /** Origin the scan actually reached after redirects, e.g. https://www.example.com */
    baseUrl: text('base_url'),
    /** Per-module outcome, for transparency and debugging. */
    moduleResults: jsonb('module_results').$type<ModuleResult[]>(),
    /** Ontology version the findings' concept ids belong to. */
    ontologyVersion: text('ontology_version'),
    error: text('error'),
  },
  (t) => [
    index('scans_site_created_idx').on(t.siteId, t.createdAt.desc()),
    // At most one queued or running external scan per site.
    uniqueIndex('scans_one_active_external_per_site')
      .on(t.siteId)
      .where(sql`${t.status} in ('queued', 'running') and ${t.kind} = 'external'`),
    check('scans_score_range', sql`${t.score} is null or (${t.score} between 0 and 100)`),
    check('scans_grade_valid', sql`${t.grade} is null or ${t.grade} in ('A', 'B', 'C', 'D', 'E', 'F')`),
  ],
);

/**
 * Software found on a site during one scan: the instance layer of the ontology
 * ("this site runs plugin X at version Y"). Findings point at these rows.
 */
export const siteComponents = pgTable(
  'site_components',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    scanId: uuid('scan_id')
      .notNull()
      .references(() => scans.id, { onDelete: 'cascade' }),
    siteId: uuid('site_id')
      .notNull()
      .references(() => sites.id, { onDelete: 'cascade' }),
    softwareType: softwareTypeEnum('software_type').notNull(),
    /** 'wordpress' for core, plugin/theme directory slug, 'php', or server name. */
    slug: text('slug').notNull(),
    name: text('name'),
    version: text('version'),
    versionConfidence: confidenceEnum('version_confidence'),
    /** How it was detected, e.g. ['meta-generator', 'rss-feed']. */
    sources: text('sources').array().notNull().default(sql`'{}'::text[]`),
    /** Known only from the inside view (companion plugin). */
    active: boolean('active'),
    createdAt: createdAt(),
  },
  (t) => [
    unique('site_components_scan_item_key').on(t.scanId, t.softwareType, t.slug),
    index('site_components_site_lookup_idx').on(t.siteId, t.softwareType, t.slug),
  ],
);

export interface FindingEvidence {
  url?: string;
  status?: number;
  /** Short, truncated excerpt. Never a full file body. */
  snippet?: string;
  detail?: Record<string, unknown>;
}

export interface FindingReference {
  type: 'cve' | 'advisory' | 'docs';
  id?: string;
  url?: string;
}

export const findings = pgTable(
  'findings',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    scanId: uuid('scan_id')
      .notNull()
      .references(() => scans.id, { onDelete: 'cascade' }),
    checkId: text('check_id').notNull(),
    /** Ontology exposure id, e.g. 'exposure/xmlrpc-enabled'. */
    conceptId: text('concept_id').notNull(),
    componentId: uuid('component_id').references(() => siteComponents.id, { onDelete: 'set null' }),
    confidence: confidenceEnum('confidence').notNull().default('confirmed'),
    severity: severityEnum('severity').notNull(),
    title: text('title').notNull(),
    evidence: jsonb('evidence').$type<FindingEvidence>().notNull().default({}),
    explanation: text('explanation').notNull(),
    /** Markdown. */
    fixSteps: text('fix_steps').notNull(),
    references: jsonb('references').$type<FindingReference[]>().notNull().default([]),
    /** Free users always see the title and a warning for these. */
    indicatesCompromise: boolean('indicates_compromise').notNull().default(false),
    /** Chosen when the scan finishes; the API applies it at read time based on plan. */
    visibleInFree: boolean('visible_in_free').notNull().default(false),
    /** Source and licence notices for third-party vulnerability data (Wordfence, NVD). */
    attribution: jsonb('attribution').$type<{ source: string; recordUrl: string | null; copyrights: VulnCopyrights | null } | null>(),
    sortOrder: integer('sort_order').notNull().default(0),
    createdAt: createdAt(),
  },
  (t) => [index('findings_scan_id_idx').on(t.scanId), index('findings_concept_idx').on(t.conceptId)],
);

// ---------------------------------------------------------------------------
// Companion plugin
// ---------------------------------------------------------------------------
export const pluginPairingCodes = pgTable(
  'plugin_pairing_codes',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    siteId: uuid('site_id')
      .notNull()
      .references(() => sites.id, { onDelete: 'cascade' }),
    createdBy: uuid('created_by')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    codeHash: text('code_hash').notNull(),
    expiresAt: timestamp('expires_at', tz).notNull(),
    usedAt: timestamp('used_at', tz),
    attempts: integer('attempts').notNull().default(0),
    createdAt: createdAt(),
  },
  (t) => [unique('plugin_pairing_codes_code_hash_key').on(t.codeHash), index('plugin_pairing_codes_site_idx').on(t.siteId)],
);

export const pluginKeys = pgTable(
  'plugin_keys',
  {
    /** Sent by the plugin as the key id; used to look up the key. */
    id: uuid('id').primaryKey().defaultRandom(),
    siteId: uuid('site_id')
      .notNull()
      .references(() => sites.id, { onDelete: 'cascade' }),
    /** SHA-256 of the derived site key. The key itself is never stored. */
    keyHash: text('key_hash').notNull(),
    expiresAt: timestamp('expires_at', tz).notNull(),
    revokedAt: timestamp('revoked_at', tz),
    lastUsedAt: timestamp('last_used_at', tz),
    createdAt: createdAt(),
  },
  (t) => [index('plugin_keys_site_idx').on(t.siteId)],
);

export const pluginReports = pgTable(
  'plugin_reports',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    siteId: uuid('site_id')
      .notNull()
      .references(() => sites.id, { onDelete: 'cascade' }),
    pluginKeyId: uuid('plugin_key_id')
      .notNull()
      .references(() => pluginKeys.id, { onDelete: 'cascade' }),
    /** The 'inside' scan built from this report. */
    scanId: uuid('scan_id').references(() => scans.id, { onDelete: 'set null' }),
    signedAt: timestamp('signed_at', tz).notNull(),
    nonce: text('nonce').notNull(),
    receivedAt: timestamp('received_at', tz).notNull().defaultNow(),
    pluginVersion: text('plugin_version').notNull(),
    payload: jsonb('payload').notNull(),
    payloadSha256: text('payload_sha256').notNull(),
  },
  (t) => [
    unique('plugin_reports_key_nonce_key').on(t.pluginKeyId, t.nonce),
    index('plugin_reports_site_received_idx').on(t.siteId, t.receivedAt.desc()),
  ],
);

// ---------------------------------------------------------------------------
// Vulnerability intelligence
// ---------------------------------------------------------------------------
export interface CopyrightNotice {
  notice: string;
  license: string;
  licenseUrl: string;
}

export interface VulnCopyrights {
  message?: string;
  /** e.g. { defiant: {...}, mitre: {...} } */
  holders: Record<string, CopyrightNotice>;
}

export interface AffectedRange {
  from?: string;
  fromInclusive?: boolean;
  to?: string;
  toInclusive?: boolean;
}

export const vulnCache = pgTable(
  'vuln_cache',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    source: vulnSourceEnum('source').notNull(),
    sourceId: text('source_id').notNull(),
    softwareType: softwareTypeEnum('software_type').notNull(),
    /** 'wordpress' for core, plugin/theme slug, or 'php'. */
    slug: text('slug').notNull(),
    title: text('title').notNull(),
    cveIds: text('cve_ids').array().notNull().default(sql`'{}'::text[]`),
    cvssScore: numeric('cvss_score', { precision: 3, scale: 1 }),
    severity: severityEnum('severity'),
    affected: jsonb('affected').$type<AffectedRange[]>().notNull(),
    fixedIn: text('fixed_in'),
    references: jsonb('references').$type<FindingReference[]>().notNull().default([]),
    /** Wordfence marks some records as having little or no real-world impact. */
    informational: boolean('informational').notNull().default(false),
    description: text('description'),
    remediation: text('remediation'),
    cwe: jsonb('cwe').$type<{ id: number; name: string } | null>(),
    /** Link to the source's page for this record (required by Wordfence's licence). */
    recordUrl: text('record_url'),
    /** Copyright notices and licences that must be shown with this record. */
    copyrights: jsonb('copyrights').$type<VulnCopyrights | null>(),
    publishedAt: timestamp('published_at', tz),
    updatedAt: timestamp('updated_at', tz),
    syncedAt: timestamp('synced_at', tz).notNull().defaultNow(),
  },
  (t) => [
    unique('vuln_cache_source_item_key').on(t.source, t.sourceId, t.softwareType, t.slug),
    index('vuln_cache_lookup_idx').on(t.softwareType, t.slug),
  ],
);

/**
 * Latest-release information per piece of software, refreshed from WordPress.org.
 * For core, `details` holds the version -> latest/outdated/insecure map.
 */
export const softwareReleases = pgTable(
  'software_releases',
  {
    softwareType: softwareTypeEnum('software_type').notNull(),
    slug: text('slug').notNull(),
    latestVersion: text('latest_version'),
    /** False when the source has no record (e.g. premium plugins not on WordPress.org). */
    found: boolean('found').notNull().default(true),
    details: jsonb('details').$type<Record<string, unknown>>(),
    fetchedAt: timestamp('fetched_at', tz).notNull().defaultNow(),
  },
  (t) => [primaryKey({ name: 'software_releases_pkey', columns: [t.softwareType, t.slug] })],
);

export const vulnSyncRuns = pgTable(
  'vuln_sync_runs',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    source: vulnSourceEnum('source').notNull(),
    startedAt: timestamp('started_at', tz).notNull().defaultNow(),
    finishedAt: timestamp('finished_at', tz),
    status: text('status').notNull().default('running'),
    recordsUpserted: integer('records_upserted').notNull().default(0),
    etag: text('etag'),
    lastModified: text('last_modified'),
    error: text('error'),
  },
  (t) => [index('vuln_sync_runs_source_started_idx').on(t.source, t.startedAt.desc())],
);

// ---------------------------------------------------------------------------
// Paid extras and audit trail
// ---------------------------------------------------------------------------
export const serviceRequests = pgTable(
  'service_requests',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    siteId: uuid('site_id')
      .notNull()
      .references(() => sites.id, { onDelete: 'cascade' }),
    findingId: uuid('finding_id').references(() => findings.id, { onDelete: 'set null' }),
    message: text('message').notNull(),
    status: serviceRequestStatusEnum('status').notNull().default('open'),
    createdAt: createdAt(),
  },
  (t) => [index('service_requests_user_idx').on(t.userId)],
);

export const auditEvents = pgTable(
  'audit_events',
  {
    id: bigserial('id', { mode: 'number' }).primaryKey(),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
    siteId: uuid('site_id').references(() => sites.id, { onDelete: 'set null' }),
    event: text('event').notNull(),
    ip: inet('ip'),
    meta: jsonb('meta').$type<Record<string, unknown>>().notNull().default({}),
    createdAt: createdAt(),
  },
  (t) => [index('audit_events_user_created_idx').on(t.userId, t.createdAt.desc())],
);

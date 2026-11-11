import { auditEvents, type Database } from '@shc/db';

export type AuditEventName =
  | 'register'
  | 'register_existing_email'
  | 'email_verified'
  | 'login'
  | 'login_failed'
  | 'login_locked'
  | 'logout'
  | 'password_reset_requested'
  | 'password_reset'
  | 'site_added'
  | 'site_deleted'
  | 'site_verified'
  | 'site_verify_failed'
  | 'site_reverified'
  | 'site_reverify_failed'
  | 'scan_requested'
  | 'scan_completed'
  | 'scan_failed'
  | 'plan_changed'
  | 'weekly_scan_changed'
  | 'scheduled_scan_skipped'
  | 'fix_requested'
  | 'report_exported'
  | 'plugin_code_created'
  | 'plugin_paired'
  | 'plugin_disconnected'
  | 'plugin_report_received';

export interface AuditInput {
  event: AuditEventName;
  userId?: string | null;
  siteId?: string | null;
  ip?: string | null;
  meta?: Record<string, unknown>;
}

/** Append-only security log. Never put secrets, tokens or passwords in meta. */
export async function audit(db: Database, input: AuditInput): Promise<void> {
  await db.insert(auditEvents).values({
    event: input.event,
    userId: input.userId ?? null,
    siteId: input.siteId ?? null,
    ip: input.ip ?? null,
    meta: input.meta ?? {},
  });
}

import type { AffectedRange, FindingReference, VulnCopyrights } from '@shc/db';
import type { Severity, SoftwareType, VulnSource } from '@shc/shared';

/** One vulnerability for one piece of software, in our cache's shape. */
export interface NormalizedVuln {
  source: VulnSource;
  sourceId: string;
  softwareType: SoftwareType;
  slug: string;
  title: string;
  cveIds: string[];
  cvssScore: number | null;
  severity: Severity | null;
  affected: AffectedRange[];
  fixedIn: string | null;
  references: FindingReference[];
  informational: boolean;
  description: string | null;
  remediation: string | null;
  cwe: { id: number; name: string } | null;
  recordUrl: string | null;
  copyrights: VulnCopyrights | null;
  publishedAt: Date | null;
  updatedAt: Date | null;
}

/**
 * Every external vulnerability source sits behind this interface, so sources can be
 * added, swapped or switched off without touching the scanner.
 */
export interface VulnSourceAdapter {
  readonly source: VulnSource;
  /** Full feeds replace everything from the source; incremental ones only upsert. */
  readonly mode: 'full' | 'incremental';
  /** Why the adapter is off, or null when it can run. */
  disabledReason(): string | null;
  fetch(options: { since?: Date; log?: IntelLogger }): Promise<NormalizedVuln[]>;
}

export interface IntelLogger {
  info(obj: object, msg?: string): void;
  warn(obj: object, msg?: string): void;
}

export const quietLogger: IntelLogger = { info() {}, warn() {} };

export function clip(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  const s = value.trim();
  if (!s) return null;
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

export function httpUrl(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  try {
    const u = new URL(value);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : null;
  } catch {
    return null;
  }
}

import type { ExposureId } from '@shc/ontology';
import type { Confidence, Severity, SoftwareType } from '@shc/shared';
import type { ComponentStore } from './components';
import type { PoliteClient } from './polite-client';

export interface ScanTarget {
  /** The verified domain, e.g. example.com */
  domain: string;
  /** Origin the site actually answered on after redirects, e.g. https://www.example.com */
  baseUrl: string;
}

export interface ComponentRef {
  type: SoftwareType;
  slug: string;
}

export interface ComponentFact extends ComponentRef {
  name?: string;
  version?: string;
  versionConfidence?: Confidence;
  sources: string[];
  active?: boolean;
}

export interface Evidence {
  url?: string;
  status?: number;
  /** Short, truncated excerpt. Never a whole response body. */
  snippet?: string;
  detail?: Record<string, unknown>;
}

export interface Reference {
  type: 'cve' | 'advisory' | 'docs';
  id?: string;
  url?: string;
}

/** What a check module reports. Text for the report comes from the ontology. */
export interface Finding {
  /** '<module>.<specific check>', e.g. 'wp-detect.version-disclosed' */
  checkId: string;
  conceptId: ExposureId;
  severity: Severity;
  title: string;
  confidence: Confidence;
  evidence: Evidence;
  component?: ComponentRef;
  references?: Reference[];
}

export interface VulnRecord {
  source: string;
  sourceId: string;
  title: string;
  cveIds: string[];
  cvssScore: number | null;
  severity: Severity | null;
  affected: Array<{ from?: string; fromInclusive?: boolean; to?: string; toInclusive?: boolean }>;
  fixedIn: string | null;
  references: Reference[];
}

/** Read access to the local vulnerability cache. */
export interface VulnLookup {
  forComponent(type: SoftwareType, slug: string): Promise<VulnRecord[]>;
}

export interface ScanLogger {
  debug(obj: object, msg?: string): void;
  info(obj: object, msg?: string): void;
  warn(obj: object, msg?: string): void;
}

export interface ScanContext {
  http: PoliteClient;
  components: ComponentStore;
  vulns: VulnLookup;
  log: ScanLogger;
}

/**
 * Every check is a module with this shape. Stage 1 modules gather facts from the site;
 * stage 2 modules analyse what stage 1 found (for example vuln-match) and run after it.
 */
export interface CheckModule {
  id: string;
  title: string;
  stage: 1 | 2;
  run(target: ScanTarget, context: ScanContext): Promise<Finding[]>;
}

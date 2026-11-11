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

export interface CopyrightHolders {
  message?: string;
  holders: Record<string, { notice: string; license: string; licenseUrl: string }>;
}

/** Where third-party vulnerability data came from, and the notices its licence requires. */
export interface Attribution {
  source: string;
  recordUrl: string | null;
  copyrights: CopyrightHolders | null;
}

/** What a check module reports. Text for the report comes from the ontology. */
export interface Finding {
  attribution?: Attribution;
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
  /** Little or no real-world impact (Wordfence's classification). */
  informational?: boolean;
  /** Link to the source's record; shown with the finding for attribution. */
  recordUrl?: string | null;
  copyrights?: CopyrightHolders | null;
}

/** Read access to the local vulnerability cache. */
export interface VulnLookup {
  forComponent(type: SoftwareType, slug: string): Promise<VulnRecord[]>;
}

export type CoreStatus = 'latest' | 'outdated' | 'insecure';

/** Read access to latest-release data (WordPress.org), cached by the intel layer. */
export interface ReleaseLookup {
  coreStatus(version: string): Promise<{ status: CoreStatus; latest: string } | null>;
  latestVersion(type: 'plugin' | 'theme', slug: string): Promise<string | null>;
}

export interface ScanLogger {
  debug(obj: object, msg?: string): void;
  info(obj: object, msg?: string): void;
  warn(obj: object, msg?: string): void;
}

/** What a stage 2 module needs: the facts gathered so far and local data, no network. */
export interface AnalysisContext {
  components: ComponentStore;
  vulns: VulnLookup;
  releases: ReleaseLookup;
  log: ScanLogger;
  /** How many plugins and themes may be checked for newer releases; unset means the outside-scan default. */
  releaseLookupLimit?: number;
}

export interface ScanContext extends AnalysisContext {
  http: PoliteClient;
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

/** A stage 2 module. It never touches the site, so it also runs over the inside view's components. */
export interface AnalysisModule extends CheckModule {
  stage: 2;
  run(target: ScanTarget, context: AnalysisContext): Promise<Finding[]>;
}

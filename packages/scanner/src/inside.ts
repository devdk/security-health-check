import type { InsideReport } from '@shc/companion';
import { ONTOLOGY_VERSION } from '@shc/ontology';
import { mask } from '@shc/shared';
import { ComponentStore } from './components';
import { phpSupport } from './data/php-branches';
import { TWO_FACTOR_PLUGINS } from './data/two-factor-plugins';
import { noReleases, sanitiseFinding, type ModuleOutcome, type ScanOutcome } from './engine';
import { outdatedSoftware, vulnMatch } from './modules';
import type { AnalysisContext, AnalysisModule, ComponentFact, Finding, ReleaseLookup, ScanLogger, ScanTarget, VulnLookup } from './types';

/** The companion plugin's own directory. It leaves itself out of reports; this makes sure. */
const COMPANION_SLUG = 'shc-companion';
/** Longest list of paths or logins kept as evidence. Totals are kept alongside. */
const MAX_LISTED = 20;
const RULES_MODULE = 'plugin';
const STAGE_2: readonly AnalysisModule[] = [vulnMatch, outdatedSoftware];

type Plugin = InsideReport['plugins'][number];
type Theme = InsideReport['themes'][number];

/** The report as the rules read it, without the companion. */
interface InsideView {
  report: InsideReport;
  plugins: Plugin[];
  themes: Theme[];
}

const nameOf = (item: { name: string; slug: string }) => item.name.trim() || item.slug;
const listed = <T>(items: readonly T[]) => items.slice(0, MAX_LISTED);
const countLabel = (n: number, truncated: boolean) => `${n}${truncated ? '+' : ''}`;

function components(view: InsideView): ComponentFact[] {
  const versioned = (version: string | null) => (version ? { version, versionConfidence: 'confirmed' as const } : {});
  const sources = ['plugin'];
  return [
    { type: 'core', slug: 'wordpress', name: 'WordPress', ...versioned(view.report.wordpress.version), sources },
    { type: 'php', slug: 'php', name: 'PHP', ...versioned(view.report.php.version), sources },
    ...view.plugins.map((p) => ({ type: 'plugin' as const, slug: p.slug, name: nameOf(p), ...versioned(p.version), sources, active: p.active })),
    ...view.themes.map((t) => ({ type: 'theme' as const, slug: t.slug, name: nameOf(t), ...versioned(t.version), sources, active: t.active })),
  ];
}

type Rule = (view: InsideView) => Finding[];

const phpUnsupported: Rule = ({ report }) => {
  const support = phpSupport(report.php.version);
  if (support.status !== 'eol') return [];
  return [
    {
      checkId: 'plugin.php-unsupported',
      conceptId: 'exposure/php-unsupported',
      severity: 'high',
      confidence: 'confirmed',
      title: `PHP ${support.branch} no longer receives security fixes (support ended ${support.securityUntil})`,
      component: { type: 'php', slug: 'php' },
      evidence: { detail: { version: report.php.version, branch: support.branch, securityUntil: support.securityUntil, source: 'php.net supported versions' } },
    },
  ];
};

const inactiveComponents: Rule = ({ plugins, themes }) => {
  // A child theme needs its parent installed, so an inactive parent is not unused.
  const activeParent = themes.find((t) => t.active)?.parent ?? null;
  const finding = (type: 'plugin' | 'theme', item: Plugin | Theme, title: string): Finding => ({
    checkId: 'plugin.inactive-component-installed',
    conceptId: 'exposure/inactive-component-installed',
    severity: 'low',
    confidence: 'confirmed',
    title,
    component: { type, slug: item.slug },
    evidence: { detail: { slug: item.slug, version: item.version } },
  });
  return [
    ...plugins.filter((p) => !p.active).map((p) => finding('plugin', p, `Plugin “${nameOf(p)}” is installed but not active`)),
    ...themes.filter((t) => !t.active && t.slug !== activeParent).map((t) => finding('theme', t, `Theme “${nameOf(t)}” is installed but not in use`)),
  ];
};

const noTwoFactor: Rule = ({ report, plugins }) => {
  if (plugins.some((p) => p.active && TWO_FACTOR_PLUGINS.has(p.slug))) return [];
  return [
    {
      checkId: 'plugin.no-two-factor-auth',
      conceptId: 'exposure/no-two-factor-auth',
      severity: 'medium',
      confidence: 'likely',
      title: 'No two-factor sign-in plugin is active, so administrators sign in with a password alone',
      evidence: { detail: { administrators: report.admins.length } },
    },
  ];
};

const excessiveAdministrators: Rule = ({ report }) => {
  const count = report.admins.length;
  if (count <= 3) return [];
  return [
    {
      checkId: 'plugin.excessive-administrators',
      conceptId: 'exposure/excessive-administrators',
      severity: 'low',
      confidence: 'confirmed',
      title: `${count} accounts have full administrator rights`,
      evidence: { detail: { count, logins: listed(report.admins.map((a) => mask(a.login))) } },
    },
  ];
};

const debugMode: Rule = ({ report }) => {
  const { wpDebug, wpDebugDisplay, wpDebugLog, displayErrors } = report.debug;
  if (!wpDebug) return [];
  const shown = wpDebugDisplay || displayErrors;
  return [
    {
      checkId: 'plugin.debug-mode-enabled',
      conceptId: 'exposure/debug-mode-enabled',
      severity: shown ? 'medium' : 'low',
      confidence: 'confirmed',
      title: shown ? 'WordPress debug mode is on and errors are shown to visitors' : 'WordPress debug mode (WP_DEBUG) is switched on',
      evidence: { detail: { wpDebug, wpDebugDisplay, wpDebugLog, displayErrors } },
    },
  ];
};

const configPermissions: Rule = ({ report }) => {
  const { found, location, mode } = report.configFile;
  if (!found || mode === null) return [];
  const bits = Number.parseInt(mode, 8);
  const writable = (bits & 0o022) !== 0;
  if (!writable && (bits & 0o004) === 0) return [];
  return [
    {
      checkId: 'plugin.config-file-permissions-weak',
      conceptId: 'exposure/config-file-permissions-weak',
      severity: writable ? 'medium' : 'low',
      confidence: 'confirmed',
      title: writable
        ? `wp-config.php can be changed by other accounts on the server (permissions ${mode})`
        : `wp-config.php can be read by every account on the server (permissions ${mode})`,
      evidence: { detail: { mode, location } },
    },
  ];
};

const coreFilesModified: Rule = ({ report }) => {
  const { modified, unexpected, truncated } = report.coreIntegrity;
  const count = modified.length + unexpected.length;
  if (count === 0) return [];
  return [
    {
      checkId: 'plugin.core-files-modified',
      conceptId: 'exposure/core-files-modified',
      severity: 'critical',
      confidence: 'confirmed',
      title:
        count === 1 && !truncated
          ? 'A WordPress core file has been changed or added'
          : `${countLabel(count, truncated)} WordPress core files have been changed or added`,
      component: { type: 'core', slug: 'wordpress' },
      evidence: {
        detail: {
          wordpressVersion: report.wordpress.version,
          modified: listed(modified),
          modifiedCount: modified.length,
          unexpected: listed(unexpected),
          unexpectedCount: unexpected.length,
          truncated,
        },
      },
    },
  ];
};

const phpInUploads: Rule = ({ report }) => {
  const { files, scanned, truncated } = report.uploadsPhp;
  if (files.length === 0) return [];
  return [
    {
      checkId: 'plugin.php-in-uploads',
      conceptId: 'exposure/php-in-uploads',
      severity: 'critical',
      confidence: 'confirmed',
      title:
        files.length === 1 && !truncated
          ? `A PHP file was found in the uploads folder: ${files[0]!.path}`
          : `${countLabel(files.length, truncated)} PHP files were found in the uploads folder`,
      evidence: { detail: { files: listed(files.map((f) => f.path)), count: files.length, truncated, scanned } },
    },
  ];
};

const suspiciousChanges: Rule = ({ report }) => {
  const { days } = report.recentPhp;
  const files = report.recentPhp.files.filter((f) => !f.packageUpdated);
  if (files.length === 0) return [];
  // The plugin lists changes not explained by an update first, so a capped list only hides
  // some of them when every listed file is one.
  const truncated = report.recentPhp.truncated && files.length === report.recentPhp.files.length;
  return [
    {
      checkId: 'plugin.suspicious-file-changes',
      conceptId: 'exposure/suspicious-file-changes',
      severity: 'high',
      confidence: 'possible',
      title:
        files.length === 1 && !truncated
          ? `A PHP file in wp-content changed in the last ${days} days without an update: ${files[0]!.path}`
          : `${countLabel(files.length, truncated)} PHP files in wp-content changed in the last ${days} days without an update`,
      evidence: { detail: { files: listed(files.map((f) => f.path)), count: files.length, days, truncated } },
    },
  ];
};

const RULES: readonly Rule[] = [
  phpUnsupported,
  inactiveComponents,
  noTwoFactor,
  excessiveAdministrators,
  debugMode,
  configPermissions,
  coreFilesModified,
  phpInUploads,
  suspiciousChanges,
];

export interface AnalyseInsideOptions {
  vulns: VulnLookup;
  /** Latest-release data; without it the outdated-software check finds nothing. */
  releases?: ReleaseLookup;
  log?: ScanLogger;
}

const quietLog: ScanLogger = { debug() {}, info() {}, warn() {} };

/**
 * Turns a companion-plugin report into a scan outcome. Nothing is fetched: the inside
 * rules read the report, then the stage 2 modules match the reported software against
 * the local vulnerability and release data, inactive plugins included.
 */
export async function analyseInside(report: InsideReport, options: AnalyseInsideOptions): Promise<ScanOutcome> {
  const log = options.log ?? quietLog;
  const view: InsideView = {
    report,
    plugins: report.plugins.filter((p) => p.slug !== COMPANION_SLUG),
    themes: report.themes,
  };
  const store = new ComponentStore();
  for (const c of components(view)) store.add(c);
  const home = new URL(report.site.homeUrl);
  const target: ScanTarget = { domain: home.hostname, baseUrl: home.origin };
  // Every listed component is checked: the merged report relies on it (see mergeParts).
  const ctx: AnalysisContext = { components: store, vulns: options.vulns, releases: options.releases ?? noReleases, log, releaseLookupLimit: Infinity };

  const findings: Finding[] = [];
  const outcomes: ModuleOutcome[] = [];
  const record = (module: string, started: number, produced: Finding[], failure?: string) => {
    const valid = produced.map((f) => sanitiseFinding(f, module)).filter((f): f is Finding => f !== null);
    findings.push(...valid);
    outcomes.push({ module, status: failure ? 'failed' : 'ok', durationMs: Date.now() - started, requests: 0, findings: valid.length, note: failure });
  };

  record(RULES_MODULE, Date.now(), RULES.flatMap((rule) => rule(view)));
  await Promise.all(
    STAGE_2.map(async (m) => {
      const started = Date.now();
      try {
        record(m.id, started, await m.run(target, ctx));
      } catch (err) {
        log.warn({ module: m.id, err: String(err) }, 'check module failed');
        record(m.id, started, [], 'Check failed unexpectedly');
      }
    }),
  );

  return {
    baseUrl: home.origin,
    ontologyVersion: ONTOLOGY_VERSION,
    components: store.list(),
    findings,
    modules: outcomes.sort((a, b) => a.module.localeCompare(b.module)),
    requestCount: 0,
  };
}

import type { CheckModule, Finding } from '../types';
import { compareVersions } from '../version';

const MAX_LOOKUPS = 40;

/**
 * Compares the versions found in stage 1 with the latest releases on WordPress.org
 * (cached daily by the intel layer). Makes no requests to the scanned site.
 */
export const outdatedSoftware: CheckModule = {
  id: 'outdated-software',
  title: 'Outdated software',
  stage: 2,

  async run(_target, ctx) {
    const findings: Finding[] = [];

    const core = ctx.components.get('core', 'wordpress');
    if (core?.version) {
      const status = await ctx.releases.coreStatus(core.version);
      if (status && status.status !== 'latest' && compareVersions(core.version, status.latest) < 0) {
        const insecure = status.status === 'insecure';
        findings.push({
          checkId: 'outdated-software.core',
          conceptId: 'exposure/wordpress-core-outdated',
          severity: insecure ? 'high' : 'medium',
          title: insecure
            ? `WordPress ${core.version} is missing security fixes (latest is ${status.latest})`
            : `WordPress ${core.version} is out of date (latest is ${status.latest})`,
          confidence: core.versionConfidence ?? 'possible',
          component: { type: 'core', slug: 'wordpress' },
          evidence: { detail: { installed: core.version, latest: status.latest, wordpressOrgStatus: status.status } },
        });
      }
    }

    const candidates = [...ctx.components.list('plugin'), ...ctx.components.list('theme')].filter((c) => c.version).slice(0, MAX_LOOKUPS);
    for (const c of candidates) {
      const type = c.type as 'plugin' | 'theme';
      const latest = await ctx.releases.latestVersion(type, c.slug);
      if (!latest || compareVersions(c.version!, latest) >= 0) continue;
      findings.push({
        checkId: `outdated-software.${type}`,
        conceptId: type === 'plugin' ? 'exposure/plugin-outdated' : 'exposure/theme-outdated',
        severity: type === 'plugin' ? 'medium' : 'low',
        title: `${type === 'plugin' ? 'Plugin' : 'Theme'} “${c.name ?? c.slug}” ${c.version} is out of date (latest is ${latest})`,
        confidence: c.versionConfidence ?? 'possible',
        component: { type, slug: c.slug },
        evidence: { detail: { installed: c.version, latest, source: 'WordPress.org' } },
      });
    }
    return findings;
  },
};

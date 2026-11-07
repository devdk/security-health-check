import { fileHeaders, referencedUrls, wpContentRefs } from '../html';
import type { CheckModule, ComponentFact, Finding } from '../types';
import { isVersion } from '../version';
import { HOMEPAGE_OPTIONS } from './wp-detect';

/** Upper bound on plugins we look up per scan, to keep request counts predictable. */
export const MAX_PLUGINS = 30;
const MAX_THEMES = 4;

const mostCommon = (values: string[]) => {
  const counts = new Map<string, number>();
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
};

/**
 * Fingerprints plugins and themes from asset paths on the home page, then reads the
 * public readme.txt (plugins) and style.css (themes) for their versions.
 * Requests: the home page (shared with wp-detect) + one per plugin + one per theme.
 */
export const pluginsThemes: CheckModule = {
  id: 'plugins-themes',
  title: 'Plugins and themes',
  stage: 1,

  async run(target, ctx) {
    const home = await ctx.http.get(`${target.baseUrl}/`, HOMEPAGE_OPTIONS);
    const refs = wpContentRefs(referencedUrls(home.body.toString('utf8')));

    const plugins = new Map<string, string[]>();
    const themes = new Map<string, string[]>();
    for (const ref of refs) {
      const bucket = ref.kind === 'plugin' ? plugins : themes;
      if (!bucket.has(ref.slug)) bucket.set(ref.slug, []);
      if (isVersion(ref.ver)) bucket.get(ref.slug)!.push(ref.ver);
    }

    const disclosed: string[] = [];

    // Plugins: asset ?ver= is a weak hint; readme.txt "Stable tag" is the shipped version.
    const pluginSlugs = [...plugins.keys()].slice(0, MAX_PLUGINS);
    if (plugins.size > MAX_PLUGINS) ctx.log.info({ found: plugins.size }, 'plugin list truncated');
    await Promise.all(
      pluginSlugs.map(async (slug) => {
        const hinted = mostCommon(plugins.get(slug)!);
        ctx.components.add({
          type: 'plugin',
          slug,
          version: hinted,
          versionConfidence: hinted ? 'possible' : undefined,
          sources: ['asset-path'],
        });
        const url = `${target.baseUrl}/wp-content/plugins/${slug}/readme.txt`;
        const res = await ctx.http.get(url, { maxBytes: 16 * 1024 });
        const text = res.body.toString('utf8');
        if (res.status !== 200 || !/stable tag\s*:/i.test(text)) return;
        const h = fileHeaders(text);
        const name = /^\s*===\s*(.+?)\s*===/m.exec(text)?.[1];
        const stable = h['stable tag'];
        const fact: ComponentFact = { type: 'plugin', slug, name, sources: ['readme.txt'] };
        if (isVersion(stable)) {
          fact.version = stable;
          fact.versionConfidence = 'likely';
        }
        ctx.components.add(fact);
        disclosed.push(url);
      }),
    );

    // Themes: style.css carries the installed version; child themes name their parent.
    const queue = [...themes.keys()];
    const seen = new Set<string>();
    while (queue.length > 0 && seen.size < MAX_THEMES) {
      const slug = queue.shift()!;
      if (seen.has(slug)) continue;
      seen.add(slug);
      const hinted = mostCommon(themes.get(slug) ?? []);
      ctx.components.add({ type: 'theme', slug, version: hinted, versionConfidence: hinted ? 'possible' : undefined, sources: ['asset-path'] });

      const url = `${target.baseUrl}/wp-content/themes/${slug}/style.css`;
      const res = await ctx.http.get(url, { maxBytes: 8 * 1024 });
      const h = fileHeaders(res.body.toString('utf8'));
      if (res.status !== 200 || !h['theme name']) continue;
      const fact: ComponentFact = { type: 'theme', slug, name: h['theme name'], sources: ['style.css'] };
      if (isVersion(h.version)) {
        fact.version = h.version;
        fact.versionConfidence = 'confirmed';
      }
      ctx.components.add(fact);
      disclosed.push(url);
      const parent = h.template?.toLowerCase();
      if (parent && /^[a-z0-9._-]+$/.test(parent) && !seen.has(parent)) {
        queue.push(parent);
        ctx.components.add({ type: 'theme', slug: parent, sources: ['child-theme-template'] });
      }
    }

    const findings: Finding[] = [];
    if (disclosed.length > 0) {
      findings.push({
        checkId: 'plugins-themes.versions-readable',
        conceptId: 'exposure/component-versions-disclosed',
        severity: 'info',
        title: `${disclosed.length} plugin and theme ${disclosed.length === 1 ? 'file reveals' : 'files reveal'} version numbers`,
        confidence: 'confirmed',
        evidence: { url: disclosed[0], detail: { files: disclosed.slice(0, 10), total: disclosed.length } },
      });
    }
    return findings;
  },
};

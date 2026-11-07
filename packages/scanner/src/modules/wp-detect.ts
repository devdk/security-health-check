import type { Confidence } from '@shc/shared';
import { metaGenerators, referencedUrls, snippet } from '../html';
import { HOMEPAGE_OPTIONS } from './common';
import type { CheckModule, Finding } from '../types';
import { isVersion } from '../version';

/** Core assets whose ?ver= is the WordPress version itself. */
const CORE_VERSIONED_ASSETS = [
  /\/wp-includes\/css\/dist\/block-library\/style(?:\.min)?\.css\?(?:[^"']*&)?ver=([0-9][^&"'#]*)/i,
  /\/wp-includes\/js\/wp-emoji-release\.min\.js\?(?:[^"']*&)?ver=([0-9][^&"'#]*)/i,
  /\/wp-includes\/css\/dashicons(?:\.min)?\.css\?(?:[^"']*&)?ver=([0-9][^&"'#]*)/i,
];

/**
 * Confirms the site runs WordPress and works out the core version from the generator
 * tag, the RSS feed and versioned core assets. Two GETs at most (home page, feed).
 */
export const wpDetect: CheckModule = {
  id: 'wp-detect',
  title: 'WordPress detection',
  stage: 1,

  async run(target, ctx) {
    const home = await ctx.http.get(`${target.baseUrl}/`, HOMEPAGE_OPTIONS);
    const html = home.body.toString('utf8');
    const urls = referencedUrls(html);
    const linkHeader = String(home.headers.link ?? '');

    const signals: string[] = [];
    if (urls.some((u) => /\/wp-(?:content|includes)\//i.test(u))) signals.push('wp-paths');
    if (/api\.w\.org/i.test(linkHeader) || /rel=["']https:\/\/api\.w\.org\/["']/i.test(html)) signals.push('rest-api-link');
    if (/xmlrpc\.php/i.test(String(home.headers['x-pingback'] ?? ''))) signals.push('x-pingback');
    const generator = metaGenerators(html).find((g) => /^WordPress\b/i.test(g));
    if (generator) signals.push('meta-generator');

    if (signals.length === 0) {
      return [
        {
          checkId: 'wp-detect.not-wordpress',
          conceptId: 'observation/wordpress-not-detected',
          severity: 'info',
          title: 'WordPress not detected',
          confidence: 'likely',
          evidence: { url: home.url, status: home.status },
        },
      ];
    }

    // version -> sources that reported it
    const versions = new Map<string, Set<string>>();
    const note = (version: string | undefined, source: string) => {
      if (!isVersion(version)) return;
      if (!versions.has(version)) versions.set(version, new Set());
      versions.get(version)!.add(source);
    };

    const genVersion = generator ? /^WordPress\s+([0-9][0-9.a-zA-Z-]*)/i.exec(generator)?.[1] : undefined;
    note(genVersion, 'meta-generator');

    for (const pattern of CORE_VERSIONED_ASSETS) {
      for (const url of urls) {
        const m = pattern.exec(url);
        if (m) note(decodeURIComponent(m[1]!), 'asset-version');
      }
    }

    // The RSS feed states the version in its <generator> element.
    const absolute = (u: string) => {
      try {
        return new URL(u, target.baseUrl);
      } catch {
        return null;
      }
    };
    const feedLink = urls.map(absolute).find((u) => u && /\/feed\/?$/.test(u.pathname) && ctx.http.inScope(u));
    const feedUrl = feedLink ? feedLink.toString() : `${target.baseUrl}/feed/`;
    let feedEvidence: string | undefined;
    try {
      const feed = await ctx.http.get(feedUrl, { followRedirects: true, maxBytes: 64 * 1024 });
      const m = /<generator>\s*https?:\/\/wordpress\.org\/\?v=([^<\s]+)\s*<\/generator>/i.exec(feed.body.toString('utf8'));
      if (feed.status === 200 && m) {
        note(m[1], 'rss-feed');
        feedEvidence = m[0];
      }
    } catch (err) {
      ctx.log.debug({ err: String(err) }, 'feed not available');
    }

    // Pick the version with the most independent sources.
    const ranked = [...versions.entries()].sort((a, b) => b[1].size - a[1].size);
    const [best, bestSources] = ranked[0] ?? [undefined, new Set<string>()];
    const direct = bestSources.has('meta-generator') || bestSources.has('rss-feed');
    const conflicting = ranked.length > 1;
    const confidence: Confidence = direct && !conflicting ? 'confirmed' : 'likely';

    ctx.components.add({
      type: 'core',
      slug: 'wordpress',
      name: 'WordPress',
      version: best,
      versionConfidence: best ? confidence : undefined,
      sources: [...signals, ...bestSources],
    });

    const findings: Finding[] = [];
    if (best) {
      findings.push({
        checkId: 'wp-detect.version-disclosed',
        conceptId: 'exposure/wordpress-version-disclosed',
        severity: 'low',
        title: `WordPress ${best} is publicly visible`,
        confidence,
        component: { type: 'core', slug: 'wordpress' },
        evidence: {
          url: home.url,
          snippet: snippet(generator ? `<meta name="generator" content="${generator}">` : (feedEvidence ?? `ver=${best}`)),
          detail: { version: best, sources: [...bestSources], ...(conflicting ? { otherVersionsSeen: ranked.slice(1).map(([v]) => v) } : {}) },
        },
      });
    }
    return findings;
  },
};

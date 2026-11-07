import type { CheckModule, Finding } from '../types';
import { header, mask, text } from './common';

const SLUG = /^[a-z0-9][a-z0-9._-]{0,59}$/i;

function slugsFromJson(body: string): string[] | null {
  try {
    const data: unknown = JSON.parse(body);
    if (!Array.isArray(data)) return null;
    const slugs = data
      .map((u) => (u && typeof u === 'object' && typeof (u as { slug?: unknown }).slug === 'string' ? (u as { slug: string }).slug : null))
      .filter((s): s is string => s !== null && SLUG.test(s));
    return slugs;
  } catch {
    return null;
  }
}

/**
 * Checks whether login names leak through the REST API users list or through author
 * archive redirects (/?author=1 -> /author/<name>/). Usernames are stored masked.
 */
export const userEnum: CheckModule = {
  id: 'user-enum',
  title: 'Username exposure',
  stage: 1,

  async run(target, ctx) {
    const findings: Finding[] = [];

    // REST API: pretty permalinks first, then the query-string form.
    for (const path of ['/wp-json/wp/v2/users', '/?rest_route=/wp/v2/users']) {
      const res = await ctx.http.get(`${target.baseUrl}${path}`, { followRedirects: true, maxBytes: 64 * 1024 });
      if (res.status !== 200 || !/json/i.test(header(res, 'content-type') ?? '')) continue;
      const slugs = slugsFromJson(text(res));
      if (slugs === null) continue;
      if (slugs.length > 0) {
        findings.push({
          checkId: 'user-enum.rest-api',
          conceptId: 'exposure/usernames-via-rest-api',
          severity: 'medium',
          title: `The REST API lists ${slugs.length} user name${slugs.length === 1 ? '' : 's'}`,
          confidence: 'confirmed',
          evidence: { url: res.url, status: res.status, detail: { count: slugs.length, sample: slugs.slice(0, 3).map(mask) } },
        });
      }
      break;
    }

    // Author archives: WordPress redirects ?author=N to /author/<nicename>/.
    const leaked = new Set<string>();
    let exampleUrl: string | undefined;
    for (const id of [1, 2]) {
      const url = `${target.baseUrl}/?author=${id}`;
      const res = await ctx.http.get(url, { followRedirects: false, maxBytes: 64 * 1024 });
      const location = header(res, 'location') ?? '';
      const fromRedirect = res.status >= 300 && res.status < 400 ? /\/author\/([^/?#]+)/i.exec(location)?.[1] : undefined;
      // Author archives carry body classes "author-<nicename> author-<id>".
      const bodyClasses = res.status === 200 ? (text(res).match(/<body[^>]*\bclass=["']([^"']*)["']/i)?.[1] ?? '').split(/\s+/) : [];
      const fromPage = bodyClasses.map((c) => /^author-(.+)$/.exec(c)?.[1]).find((s) => s !== undefined && !/^\d+$/.test(s));
      const slug = fromRedirect ?? fromPage;
      if (slug && SLUG.test(decodeURIComponent(slug))) {
        leaked.add(decodeURIComponent(slug));
        exampleUrl ??= url;
      }
    }
    if (leaked.size > 0) {
      findings.push({
        checkId: 'user-enum.author-archives',
        conceptId: 'exposure/usernames-via-author-archives',
        severity: 'medium',
        title: `Author pages reveal ${leaked.size} user name${leaked.size === 1 ? '' : 's'}`,
        confidence: 'confirmed',
        evidence: { url: exampleUrl, detail: { count: leaked.size, sample: [...leaked].map(mask) } },
      });
    }
    return findings;
  },
};

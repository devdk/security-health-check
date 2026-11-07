import type { CheckModule } from '../types';
import { text } from './common';

export const LISTING_DIRS = ['/wp-content/uploads/', '/wp-content/plugins/', '/wp-content/themes/', '/wp-includes/'];

const isListing = (body: string) =>
  /<title>\s*Index of \//i.test(body) || /<h1>\s*Index of \//i.test(body) || /<title>\s*Directory listing for \//i.test(body);

/** Checks whether the web server shows automatic file listings for WordPress folders. */
export const directoryListing: CheckModule = {
  id: 'directory-listing',
  title: 'Directory listing',
  stage: 1,

  async run(target, ctx) {
    const open: string[] = [];
    for (const dir of LISTING_DIRS) {
      const res = await ctx.http.get(`${target.baseUrl}${dir}`, { maxBytes: 16 * 1024 });
      if (res.status === 200 && isListing(text(res))) open.push(dir);
    }
    if (open.length === 0) return [];
    return [
      {
        checkId: 'directory-listing.enabled',
        conceptId: 'exposure/directory-listing-enabled',
        severity: 'medium',
        title: `${open.length} folder${open.length === 1 ? ' shows' : 's show'} a public file listing`,
        confidence: 'confirmed',
        evidence: { url: `${target.baseUrl}${open[0]}`, detail: { directories: open } },
      },
    ];
  },
};

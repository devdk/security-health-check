import type { NormalizedVuln, VulnSourceAdapter } from './types';

/**
 * Reserved slot for OSV (https://osv.dev). Switched off: as of 2026-11 OSV has no
 * WordPress or PHP-runtime ecosystem (only Composer packages via Packagist), and its data
 * licences vary by source, some non-commercial. Enable once a relevant ecosystem exists
 * and its licence has been checked.
 */
export class OsvAdapter implements VulnSourceAdapter {
  readonly source = 'osv' as const;
  readonly mode = 'incremental' as const;

  disabledReason(): string | null {
    return 'OSV has no WordPress or PHP-runtime data yet; adapter reserved for later';
  }

  async fetch(): Promise<NormalizedVuln[]> {
    return [];
  }
}

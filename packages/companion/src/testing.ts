import type { InsideReport } from './report';

/** A valid report from a small, healthy site. Each call returns a fresh copy to modify. */
export function sampleInsideReport(): InsideReport {
  return {
    schema: 1,
    generatedAt: '2026-11-11T03:00:00Z',
    plugin: { version: '0.1.0' },
    site: { homeUrl: 'https://example.com', siteUrl: 'https://example.com', multisite: false },
    wordpress: { version: '6.4.2', locale: 'en_US' },
    php: { version: '8.1.27' },
    plugins: [
      { slug: 'contact-form-7', file: 'contact-form-7/wp-contact-form-7.php', name: 'Contact Form 7', version: '5.3.1', active: true, autoUpdate: false },
    ],
    themes: [{ slug: 'twentytwentyone', name: 'Twenty Twenty-One', version: '2.0', active: true, parent: null, autoUpdate: false }],
    admins: [{ login: 's******n', roles: ['administrator'] }],
    debug: { wpDebug: false, wpDebugDisplay: true, wpDebugLog: false, displayErrors: false },
    configFile: { found: true, location: 'root', mode: '0640' },
    coreIntegrity: { status: 'ok', reason: null, modified: [], missing: [], unexpected: [], truncated: false },
    uploadsPhp: { files: [], scanned: 12, truncated: false },
    recentPhp: { days: 7, files: [], truncated: false },
  };
}

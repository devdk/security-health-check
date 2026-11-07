import type { CoreStatus } from '@shc/scanner';
import { fetchJson as defaultFetchJson, IntelError, type FetchJson } from './http';

export const CORE_STABLE_CHECK = 'https://api.wordpress.org/core/stable-check/1.0/';
const SLUG = /^[a-z0-9][a-z0-9._-]{0,199}$/;

/** Every WordPress release mapped to latest / outdated / insecure, as WordPress.org sees it. */
export async function fetchCoreStatus(get: FetchJson = defaultFetchJson): Promise<{ latest: string; versions: Record<string, CoreStatus> }> {
  const res = await get(CORE_STABLE_CHECK, { timeoutMs: 30_000, maxBytes: 2 * 1024 * 1024 });
  if (res.status !== 200 || typeof res.json !== 'object' || res.json === null) throw new IntelError(`Unexpected WordPress.org response (HTTP ${res.status})`, res.status);
  const versions: Record<string, CoreStatus> = {};
  let latest: string | null = null;
  for (const [version, status] of Object.entries(res.json as Record<string, unknown>)) {
    if (!/^\d+\.\d+(\.\d+)?$/.test(version) || (status !== 'latest' && status !== 'outdated' && status !== 'insecure')) continue;
    versions[version] = status;
    if (status === 'latest') latest = version;
  }
  if (!latest) throw new IntelError('WordPress.org stable-check has no "latest" version');
  return { latest, versions };
}

/** Latest version of a plugin or theme in the WordPress.org directory; found=false for premium ones. */
export async function fetchDirectoryVersion(
  type: 'plugin' | 'theme',
  slug: string,
  get: FetchJson = defaultFetchJson,
): Promise<{ found: boolean; version: string | null }> {
  if (!SLUG.test(slug)) return { found: false, version: null };
  const params = new URLSearchParams({ action: type === 'plugin' ? 'plugin_information' : 'theme_information', 'request[slug]': slug });
  if (type === 'plugin') for (const f of ['sections', 'description', 'reviews', 'banners', 'icons', 'screenshots']) params.set(`request[fields][${f}]`, '0');
  const url = `https://api.wordpress.org/${type}s/info/1.2/?${params}`;
  const res = await get(url, { timeoutMs: 15_000, maxBytes: 1024 * 1024 });
  const json = res.json as { version?: unknown; error?: unknown } | null;
  if (res.status === 404 || (json && typeof json.error === 'string') || !json) return { found: false, version: null };
  if (res.status !== 200) throw new IntelError(`Unexpected WordPress.org response (HTTP ${res.status})`, res.status);
  return { found: true, version: typeof json.version === 'string' ? json.version : null };
}

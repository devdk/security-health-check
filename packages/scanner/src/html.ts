/**
 * Small, dependency-free HTML helpers. We only need to find a handful of well-known
 * markers, and regular expressions over a size-capped body are enough for that.
 */

const decode = (s: string) =>
  s
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;|&apos;/g, "'")
    .replace(/&#038;/g, '&');

/** Attribute map for each `<tag ...>` occurrence. */
export function findTags(html: string, tag: string): Array<Record<string, string>> {
  const out: Array<Record<string, string>> = [];
  const tagRe = new RegExp(`<${tag}\\b([^>]*)>`, 'gi');
  for (const m of html.matchAll(tagRe)) {
    const attrs: Record<string, string> = {};
    for (const a of m[1]!.matchAll(/([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'>]+))/g)) {
      attrs[a[1]!.toLowerCase()] = decode(a[3] ?? a[4] ?? a[5] ?? '');
    }
    out.push(attrs);
  }
  return out;
}

export function metaGenerators(html: string): string[] {
  return findTags(html, 'meta')
    .filter((a) => a.name?.toLowerCase() === 'generator' && a.content)
    .map((a) => a.content!);
}

/** All URLs mentioned in the page, including JSON-escaped ones inside inline scripts. */
export function referencedUrls(html: string): string[] {
  const text = html.replace(/\\\//g, '/');
  const urls = new Set<string>();
  for (const m of text.matchAll(/(?:src|href)\s*=\s*["']([^"']+)["']/gi)) urls.add(decode(m[1]!));
  for (const m of text.matchAll(/["'(]((?:https?:)?\/\/[^"'()\s]+|\/wp-(?:content|includes)\/[^"'()\s]+)/gi)) urls.add(decode(m[1]!));
  return [...urls];
}

export interface WpAssetRef {
  kind: 'plugin' | 'theme';
  slug: string;
  path: string;
  ver?: string;
}

const SLUG = /^[a-z0-9][a-z0-9._-]{0,99}$/i;

/** Plugins and themes referenced from /wp-content/plugins/<slug>/ and /wp-content/themes/<slug>/. */
export function wpContentRefs(urls: string[]): WpAssetRef[] {
  const out: WpAssetRef[] = [];
  for (const raw of urls) {
    const m = /\/wp-content\/(plugins|themes)\/([^/?#"']+)(\/[^?#"']*)?(?:\?([^#"']*))?/i.exec(raw);
    if (!m) continue;
    const slug = m[2]!.toLowerCase();
    if (!SLUG.test(slug)) continue;
    const ver = m[4] ? new URLSearchParams(m[4]).get('ver') ?? undefined : undefined;
    out.push({ kind: m[1]!.toLowerCase() === 'plugins' ? 'plugin' : 'theme', slug, path: m[3] ?? '/', ver });
  }
  return out;
}

/** Reads `Key: value` headers from a WordPress readme.txt or theme style.css. */
export function fileHeaders(text: string): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const line of text.slice(0, 8192).split(/\r?\n/)) {
    const m = /^[\s*#@/]*([A-Za-z][A-Za-z ]{1,40}?)\s*:\s*(.+?)\s*$/.exec(line);
    if (m && !(m[1]!.toLowerCase() in headers)) headers[m[1]!.toLowerCase()] = m[2]!;
  }
  return headers;
}

export function snippet(text: string, max = 200): string {
  const clean = text.replace(/\s+/g, ' ').trim();
  return clean.length > max ? `${clean.slice(0, max)}…` : clean;
}

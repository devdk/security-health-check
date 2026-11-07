/**
 * Version comparison with the same semantics as PHP's version_compare(), which is what
 * WordPress, plugin authors and vulnerability feeds use. So "5.3.1" < "5.3.2",
 * "6.4-RC1" < "6.4", "1.0" < "1.0.0" < "1.0.1".
 */

const VERSION = /^[0-9][0-9A-Za-z.+_-]{0,39}$/;

export function isVersion(value: string | undefined | null): value is string {
  return typeof value === 'string' && VERSION.test(value);
}

function canonical(v: string): string[] {
  return v
    .trim()
    .replace(/[-_+]/g, '.')
    .replace(/([0-9])([^0-9.])/g, '$1.$2')
    .replace(/([^0-9.])([0-9])/g, '$1.$2')
    .split('.')
    .filter((p) => p.length > 0);
}

// PHP's special-form order. Numbers sit at '#'. Unknown words rank below everything.
const SPECIAL: Record<string, number> = { dev: 0, alpha: 1, a: 1, beta: 2, b: 2, rc: 3, '#': 4, pl: 5, p: 5 };
const rank = (part: string) => (/^\d+$/.test(part) ? SPECIAL['#']! : (SPECIAL[part.toLowerCase()] ?? -1));

function comparePart(a: string, b: string): number {
  const aNum = /^\d+$/.test(a);
  const bNum = /^\d+$/.test(b);
  if (aNum && bNum) {
    const diff = BigInt(a) - BigInt(b);
    return diff === 0n ? 0 : diff < 0n ? -1 : 1;
  }
  return Math.sign(rank(a) - rank(b));
}

export function compareVersions(a: string, b: string): number {
  const pa = canonical(a);
  const pb = canonical(b);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i];
    const y = pb[i];
    if (x === undefined) return /^\d+$/.test(y!) ? -1 : comparePart('#', y!);
    if (y === undefined) return /^\d+$/.test(x) ? 1 : comparePart(x, '#');
    const c = comparePart(x, y);
    if (c !== 0) return c;
  }
  return 0;
}

export interface VersionRange {
  from?: string;
  fromInclusive?: boolean;
  to?: string;
  toInclusive?: boolean;
}

const unbounded = (v: string | undefined) => v === undefined || v === '' || v === '*';

/** True when `version` falls inside the range. Bounds default to inclusive; '*' means open. */
export function inRange(version: string, range: VersionRange): boolean {
  if (!unbounded(range.from)) {
    const c = compareVersions(version, range.from!);
    if (c < 0 || (c === 0 && range.fromInclusive === false)) return false;
  }
  if (!unbounded(range.to)) {
    const c = compareVersions(version, range.to!);
    if (c > 0 || (c === 0 && range.toInclusive === false)) return false;
  }
  return true;
}

/**
 * PHP release branches and their support dates, from https://www.php.net/supported-versions.php
 * and https://www.php.net/eol.php (checked 2026-11-08). Dates are facts, not licensed content.
 * A test fails once the newest branch here is old enough that a newer one must exist.
 */
export interface PhpBranch {
  branch: string;
  released: string;
  /** Last day of security fixes. */
  securityUntil: string;
}

export const PHP_BRANCHES: readonly PhpBranch[] = [
  { branch: '8.5', released: '2025-11-20', securityUntil: '2029-12-31' },
  { branch: '8.4', released: '2024-11-21', securityUntil: '2028-12-31' },
  { branch: '8.3', released: '2023-11-23', securityUntil: '2027-12-31' },
  { branch: '8.2', released: '2022-12-08', securityUntil: '2026-12-31' },
  { branch: '8.1', released: '2021-11-25', securityUntil: '2025-12-31' },
  { branch: '8.0', released: '2020-11-26', securityUntil: '2023-11-26' },
  { branch: '7.4', released: '2019-11-28', securityUntil: '2022-11-28' },
  { branch: '7.3', released: '2018-12-06', securityUntil: '2021-12-06' },
  { branch: '7.2', released: '2017-11-30', securityUntil: '2020-11-30' },
  { branch: '7.1', released: '2016-12-01', securityUntil: '2019-12-01' },
  { branch: '7.0', released: '2015-12-03', securityUntil: '2019-01-10' },
];

export type PhpSupport =
  | { status: 'supported'; branch: string; securityUntil: string; daysLeft: number }
  | { status: 'eol'; branch: string; securityUntil: string }
  | { status: 'unknown' };

export function phpSupport(version: string, today: Date = new Date()): PhpSupport {
  const m = /^(\d+)\.(\d+)/.exec(version);
  if (!m) return { status: 'unknown' };
  const major = Number(m[1]);
  const branch = `${m[1]}.${m[2]}`;
  const known = PHP_BRANCHES.find((b) => b.branch === branch);
  if (!known) {
    // Anything older than the oldest listed branch is long out of support.
    return major < 7 ? { status: 'eol', branch, securityUntil: 'before 2019' } : { status: 'unknown' };
  }
  const end = Date.parse(`${known.securityUntil}T23:59:59Z`);
  if (today.getTime() > end) return { status: 'eol', branch, securityUntil: known.securityUntil };
  return { status: 'supported', branch, securityUntil: known.securityUntil, daysLeft: Math.floor((end - today.getTime()) / 86_400_000) };
}

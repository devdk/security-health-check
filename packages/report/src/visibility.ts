import { SEVERITIES, type Severity } from '@shc/shared';

export interface SelectableFinding {
  severity: Severity;
  indicatesCompromise: boolean;
}

/**
 * Picks which findings a free user sees in full: about a third, spread across severities
 * so the free report shows the range of what was found rather than only the worst.
 * Findings are taken round-robin by severity (critical, high, medium, low, info, then
 * again), in the order given. Compromise indicators are handled separately (always shown
 * with a warning) and don't use up the allowance.
 *
 * Returns the indexes of the chosen findings.
 */
export function selectFreeVisible(findings: readonly SelectableFinding[]): Set<number> {
  const pool = findings.map((f, i) => ({ f, i })).filter(({ f }) => !f.indicatesCompromise);
  const allowance = Math.ceil(pool.length / 3);
  const buckets = new Map<Severity, number[]>(SEVERITIES.map((s) => [s, []]));
  for (const { f, i } of pool) buckets.get(f.severity)!.push(i);

  const chosen = new Set<number>();
  for (let round = 0; chosen.size < allowance; round++) {
    let tookAny = false;
    for (const severity of SEVERITIES) {
      const index = buckets.get(severity)![round];
      if (index === undefined) continue;
      tookAny = true;
      chosen.add(index);
      if (chosen.size >= allowance) break;
    }
    if (!tookAny) break;
  }
  return chosen;
}

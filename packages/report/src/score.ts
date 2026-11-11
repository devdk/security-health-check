import type { Confidence, Severity } from '@shc/shared';

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface ScorableFinding {
  conceptId: string;
  severity: Severity;
  confidence: Confidence;
  indicatesCompromise: boolean;
}

/** Points taken off per finding, before confidence and repetition adjustments. */
export const SEVERITY_POINTS: Record<Severity, number> = { critical: 30, high: 15, medium: 6, low: 2, info: 0 };
const CONFIDENCE_FACTOR: Record<Confidence, number> = { confirmed: 1, likely: 0.8, possible: 0.5 };
/** The same kind of problem repeated counts less each time: full, half, then a quarter. */
const REPEAT_FACTOR = [1, 0.5, 0.25];

export interface ScoreResult {
  score: number;
  grade: Grade;
  /** Why the score was capped, if it was. */
  cap: 'compromise' | 'critical' | 'high' | null;
  penalties: Array<{ conceptId: string; points: number }>;
}

export function gradeFor(score: number): Grade {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

/**
 * Security score out of 100. Each finding takes points off by severity, scaled by how sure
 * we are; repeats of one problem count less. Then caps keep the grade honest: a site with
 * likely or confirmed signs of compromise is an F whatever else is true, a confirmed
 * critical issue can never score above F, and a high one never above C. A merely possible
 * sign (a heuristic) is still shown as a warning, but doesn't decide the grade on its own.
 */
export function computeScore(findings: readonly ScorableFinding[]): ScoreResult {
  const byConcept = new Map<string, ScorableFinding[]>();
  for (const f of findings) {
    if (!byConcept.has(f.conceptId)) byConcept.set(f.conceptId, []);
    byConcept.get(f.conceptId)!.push(f);
  }

  const penalties: ScoreResult['penalties'] = [];
  for (const [conceptId, group] of byConcept) {
    const weights = group.map((f) => SEVERITY_POINTS[f.severity] * CONFIDENCE_FACTOR[f.confidence]).sort((a, b) => b - a);
    const points = weights.reduce((sum, w, i) => sum + w * (REPEAT_FACTOR[i] ?? REPEAT_FACTOR[REPEAT_FACTOR.length - 1]!), 0);
    if (points > 0) penalties.push({ conceptId, points: Math.round(points * 10) / 10 });
  }
  penalties.sort((a, b) => b.points - a.points);

  let score = Math.round(Math.max(0, Math.min(100, 100 - penalties.reduce((s, p) => s + p.points, 0))));
  let cap: ScoreResult['cap'] = null;
  const sure = (f: ScorableFinding) => f.confidence !== 'possible';
  if (findings.some((f) => f.indicatesCompromise && sure(f))) {
    cap = 'compromise';
    score = Math.min(score, 19);
  } else if (findings.some((f) => f.severity === 'critical' && sure(f))) {
    cap = 'critical';
    score = Math.min(score, 49);
  } else if (findings.some((f) => f.severity === 'high' && sure(f))) {
    cap = 'high';
    score = Math.min(score, 74);
  }
  return { score, grade: gradeFor(score), cap, penalties };
}

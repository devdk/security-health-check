import { useEffect, useRef } from 'react';
import type { ScanStatus, Severity } from '../api';

const STATUS_LABEL: Record<ScanStatus, string> = { queued: 'Queued', running: 'Scanning…', completed: 'Completed', failed: 'Failed' };

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  return <span className={`badge badge-scan-${status}`}>{STATUS_LABEL[status]}</span>;
}

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function SeverityCounts({ counts }: { counts: Record<Severity, number> }) {
  const total = ORDER.reduce((n, s) => n + counts[s], 0);
  if (total === 0) return <span className="muted small">No issues found</span>;
  return (
    <span className="severity-counts">
      {ORDER.filter((s) => counts[s] > 0).map((s) => (
        <span key={s} className={`sev sev-${s}`} title={`${counts[s]} ${s}`}>
          {counts[s]} {s}
        </span>
      ))}
    </span>
  );
}

/** Calls `tick` every `ms` while `active` is true. */
export function usePolling(active: boolean, tick: () => void, ms = 3000) {
  const saved = useRef(tick);
  saved.current = tick;
  useEffect(() => {
    if (!active) return;
    const id = setInterval(() => saved.current(), ms);
    return () => clearInterval(id);
  }, [active, ms]);
}

export const isActive = (status: ScanStatus) => status === 'queued' || status === 'running';

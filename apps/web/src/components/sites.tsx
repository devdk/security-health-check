import { useState } from 'react';
import type { SiteStatus } from '../api';

const STATUS_LABEL: Record<SiteStatus, string> = {
  verified: 'Verified',
  stale: 'Re-check due',
  unverified: 'Not verified',
};

export function StatusBadge({ status }: { status: SiteStatus }) {
  return <span className={`badge badge-${status}`}>{STATUS_LABEL[status]}</span>;
}

export function CopyField({ label, value, large = false }: { label: string; value: string; large?: boolean }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className={`copy-field${large ? ' copy-field-large' : ''}`}>
      <span className="copy-label">{label}</span>
      <div className="copy-row">
        <code className="code">{value}</code>
        <button type="button" className="btn btn-ghost btn-small" onClick={copy} aria-label={`Copy ${label}`}>
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
    </div>
  );
}

export function formatDate(iso: string | null): string {
  if (!iso) return '';
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

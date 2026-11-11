import { useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import { api, errorMessage, type LockedFinding, type ReportView, type RevealedFinding, type Severity } from '../api';
import { Alert } from './ui';

const SEVERITY_LABEL: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const EFFORT: Record<'minutes' | 'hour' | 'day', string> = { minutes: 'a few minutes', hour: 'about an hour', day: 'a day or more' };
const CONFIDENCE: Record<string, string> = {
  confirmed: 'Confirmed',
  likely: 'Likely: strong signal, not directly confirmed',
  possible: 'Possible: worth checking, may be a false alarm',
};

export function ScoreBadge({ score, grade }: { score: number; grade: string }) {
  return (
    <div className={`score-badge grade-${grade}`} aria-label={`Security grade ${grade}, score ${score} out of 100`}>
      <span className="score-grade">{grade}</span>
      <span className="score-num">{score} / 100</span>
    </div>
  );
}

function safeHref(url: unknown): string | null {
  if (typeof url !== 'string') return null;
  try {
    const u = new URL(url);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : null;
  } catch {
    return null;
  }
}

function ExternalLink({ href, children }: { href: unknown; children: ReactNode }) {
  const safe = safeHref(href);
  return safe ? (
    <a href={safe} target="_blank" rel="noopener noreferrer nofollow">
      {children}
    </a>
  ) : (
    <>{children}</>
  );
}

function Evidence({ evidence }: { evidence: Record<string, unknown> }) {
  const detail = (evidence.detail ?? {}) as Record<string, unknown>;
  const rows: Array<[string, ReactNode]> = [];
  if (evidence.url) rows.push(['Where', <ExternalLink href={evidence.url}>{String(evidence.url)}</ExternalLink>]);
  if (evidence.status) rows.push(['Response', String(evidence.status)]);
  if (evidence.snippet) rows.push(['Seen', <code className="code-inline">{String(evidence.snippet)}</code>]);
  for (const [key, value] of Object.entries(detail)) {
    if (value === null || value === undefined || key === 'vulnerabilities') continue;
    const text = typeof value === 'object' ? JSON.stringify(value) : String(value);
    rows.push([key.replace(/([A-Z])/g, ' $1').toLowerCase(), text.length > 300 ? `${text.slice(0, 300)}…` : text]);
  }
  const vulns = Array.isArray(detail.vulnerabilities) ? (detail.vulnerabilities as Array<Record<string, unknown>>) : [];
  if (rows.length === 0 && vulns.length === 0) return null;
  return (
    <div className="evidence">
      <h4>What we saw</h4>
      <dl>
        {rows.map(([k, v]) => (
          <div key={k} className="evidence-row">
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
      {vulns.length > 0 && (
        <ul className="vuln-list">
          {vulns.slice(0, 15).map((v) => (
            <li key={String(v.id)}>
              <strong>{String(v.id)}</strong> {String(v.title)} <span className={`sev sev-${String(v.severity)}`}>{String(v.severity)}</span>
            </li>
          ))}
          {vulns.length > 15 && <li className="muted">…and {vulns.length - 15} more</li>}
        </ul>
      )}
    </div>
  );
}

function FixRequestButton({ finding, onRequested }: { finding: RevealedFinding; onRequested: () => void }) {
  const [open, setOpen] = useState(false);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (finding.fixRequest) {
    return <p className="small muted">Fix requested on {new Date(finding.fixRequest.createdAt).toLocaleDateString()}: we'll be in touch.</p>;
  }
  if (!open) {
    return (
      <button type="button" className="btn btn-ghost btn-small" onClick={() => setOpen(true)}>
        Request a fix
      </button>
    );
  }
  async function send() {
    setBusy(true);
    setError(null);
    try {
      await api(`/findings/${finding.id}/fix-request`, { body: { message } });
      onRequested();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }
  return (
    <div className="fix-request">
      <label htmlFor={`fix-${finding.id}`} className="small">
        Anything we should know? (optional)
      </label>
      <textarea id={`fix-${finding.id}`} className="input" rows={3} maxLength={2000} value={message} onChange={(e) => setMessage(e.target.value)} />
      {error && <Alert tone="error">{error}</Alert>}
      <div className="actions">
        <button type="button" className="btn btn-primary btn-small" onClick={send} disabled={busy}>
          {busy ? 'Sending…' : 'Send request'}
        </button>{' '}
        <button type="button" className="btn btn-ghost btn-small" onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
    </div>
  );
}

export function FindingCard({ finding, canRequestFix, onChanged }: { finding: RevealedFinding; canRequestFix: boolean; onChanged: () => void }) {
  const [open, setOpen] = useState(finding.severity === 'critical' || finding.indicatesCompromise);
  return (
    <article className={`card finding finding-${finding.severity}`}>
      <button type="button" className="finding-head" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span className={`sev sev-${finding.severity}`}>{SEVERITY_LABEL[finding.severity]}</span>
        <span className="finding-title">{finding.title}</span>
        <span className="muted small finding-cat">{finding.category}</span>
        <span className={`source-tag source-tag-${finding.source}`}>{finding.source === 'inside' ? 'Inside view' : 'Outside scan'}</span>
      </button>
      {open && (
        <div className="finding-body">
          {finding.indicatesCompromise && (
            <Alert tone="error">This may mean your site has already been broken into. Treat it as urgent.</Alert>
          )}
          <p>{finding.explanation}</p>
          <p className="small muted">{CONFIDENCE[finding.confidence]}</p>
          <Evidence evidence={finding.evidence} />

          {finding.fix && finding.fix.length > 0 && (
            <div className="fix">
              <h4>How to fix it</h4>
              {finding.fixNote && <p className="fix-note">{finding.fixNote}</p>}
              {finding.fix.map((g) => (
                <div key={g.title} className="guide">
                  <p>
                    <strong>{g.title}</strong> <span className="muted small">({EFFORT[g.effort]})</span>. {g.summary}
                  </p>
                  <ol>
                    {g.steps.map((s) => (
                      <li key={s}>{s}</li>
                    ))}
                  </ol>
                </div>
              ))}
            </div>
          )}
          {finding.fixLocked && (
            <div className="locked-inline">
              <span aria-hidden="true">🔒</span> Step-by-step fix guidance is part of the Pro plan. <Link to="/account">Upgrade</Link>
            </div>
          )}

          {(finding.standards.weaknesses.length > 0 || finding.references.some((r) => r.type === 'cve')) && (
            <p className="small refs">
              {finding.standards.weaknesses.map((w) => (
                <ExternalLink key={w.id} href={w.url}>
                  {w.id}
                </ExternalLink>
              ))}
              {finding.standards.attackPatterns.map((a) => (
                <ExternalLink key={a.id} href={a.url}>
                  {a.id}
                </ExternalLink>
              ))}
              {finding.standards.owasp.map((o) => (
                <span key={o.id}>OWASP {o.id}</span>
              ))}
              {finding.references
                .filter((r) => r.type === 'cve')
                .map((r) => (
                  <ExternalLink key={r.id ?? r.url} href={r.url}>
                    {r.id}
                  </ExternalLink>
                ))}
            </p>
          )}
          {finding.attribution && (
            <p className="small muted attribution">
              Source:{' '}
              <ExternalLink href={finding.attribution.recordUrl}>{finding.attribution.source === 'wordfence' ? 'Wordfence Intelligence' : finding.attribution.source.toUpperCase()}</ExternalLink>
              {finding.attribution.notices.length > 0 && `. ${finding.attribution.notices.join('. ')}`}
            </p>
          )}
          {canRequestFix && <FixRequestButton finding={finding} onRequested={onChanged} />}
        </div>
      )}
    </article>
  );
}

/** Placeholder text is generated here, never sent by the server: locked findings carry no details. */
export function LockedCard({ finding }: { finding: LockedFinding }) {
  return (
    <article className={`card finding finding-${finding.severity} finding-locked`} aria-label={`Locked ${SEVERITY_LABEL[finding.severity]} finding`}>
      <div className="finding-head">
        <span className={`sev sev-${finding.severity}`}>{SEVERITY_LABEL[finding.severity]}</span>
        <span className="finding-title blurred" aria-hidden="true">
          Details of this finding are hidden on the free plan
        </span>
        <span className="muted small finding-cat">{finding.category}</span>
      </div>
      <div className="locked-row">
        <span aria-hidden="true">🔒</span> <Link to="/account">Upgrade to Pro</Link> to see this finding and how to fix it.
      </div>
    </article>
  );
}

export function DataSources({ report }: { report: ReportView }) {
  if (report.dataSources.length === 0) return null;
  return (
    <section className="card">
      <h2>Data sources</h2>
      {report.dataSources.map((d) => (
        <div key={d.id} className="source">
          <p>
            <strong>{d.name}</strong>: <ExternalLink href={d.url}>{d.url}</ExternalLink>
          </p>
          {d.notice && <p className="small muted">{d.notice}</p>}
          {d.licenses.map((l) => (
            <details key={l.holder} className="small muted license">
              <summary>{l.notice}</summary>
              <p>{l.license}</p>
              {l.licenseUrl && <ExternalLink href={l.licenseUrl}>{l.licenseUrl}</ExternalLink>}
            </details>
          ))}
        </div>
      ))}
    </section>
  );
}

import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router';
import { api, ApiError, errorMessage, type ReportView, type ScanDetail } from '../api';
import { DataSources, FindingCard, LockedCard, ScoreBadge } from '../components/report';
import { isActive, ScanStatusBadge, SeverityCounts, usePolling } from '../components/scans';
import { formatDate } from '../components/sites';
import { Alert } from '../components/ui';

const TYPE_LABEL = { core: 'WordPress core', plugin: 'Plugins', theme: 'Themes', php: 'PHP', web_server: 'Web server' } as const;
const MODULE_LABEL: Record<string, string> = {
  'wp-detect': 'WordPress detection',
  'plugins-themes': 'Plugins and themes',
  'php-version': 'PHP version',
  'exposed-files': 'Exposed sensitive files',
  'user-enum': 'Username exposure',
  xmlrpc: 'XML-RPC',
  'directory-listing': 'Directory listing',
  tls: 'HTTPS and certificate',
  headers: 'Security headers and cookies',
  'admin-exposure': 'Login and admin exposure',
  'vuln-match': 'Known vulnerabilities',
  'outdated-software': 'Outdated software',
};

export function ScanPage() {
  const { scanId = '' } = useParams();
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [report, setReport] = useState<ReportView | null>(null);
  const [reportError, setReportError] = useState<ApiError | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);

  const loadReport = useCallback(() => {
    api<{ report: ReportView }>(`/scans/${encodeURIComponent(scanId)}/report`)
      .then((res) => setReport(res.report))
      .catch((err) => (err instanceof ApiError ? setReportError(err) : setError(errorMessage(err))));
  }, [scanId]);

  const load = useCallback(() => {
    api<{ scan: ScanDetail }>(`/scans/${encodeURIComponent(scanId)}`)
      .then((res) => {
        setScan(res.scan);
        if (res.scan.status === 'completed') loadReport();
      })
      .catch((err) => setError(errorMessage(err)));
  }, [scanId, loadReport]);

  useEffect(load, [load]);
  usePolling(scan !== null && isActive(scan.status), load);

  async function downloadPdf() {
    setDownloading(true);
    setError(null);
    try {
      const res = await fetch(`/api/scans/${encodeURIComponent(scanId)}/report.pdf`, { credentials: 'same-origin' });
      if (!res.ok) {
        const body = (await res.json().catch(() => ({}))) as { message?: string };
        throw new Error(body.message ?? 'Could not create the PDF.');
      }
      const blob = await res.blob();
      const name = /filename="([^"]+)"/.exec(res.headers.get('content-disposition') ?? '')?.[1] ?? 'security-report.pdf';
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create the PDF.');
    } finally {
      setDownloading(false);
    }
  }

  if (error && !scan) return <Alert tone="error">{error}</Alert>;
  if (!scan) return <p className="muted">Loading…</p>;

  const crumbs = (
    <p className="breadcrumb">
      <Link to="/">Your sites</Link> / <Link to={`/sites/${scan.siteId}`}>{scan.domain}</Link> / Report
    </p>
  );

  if (scan.status !== 'completed') {
    return (
      <div className="page">
        {crumbs}
        <header className="page-header">
          <div>
            <h1>Scan of {scan.domain}</h1>
            <p className="muted">Started {formatDate(scan.startedAt ?? scan.createdAt)}</p>
          </div>
          <ScanStatusBadge status={scan.status} />
        </header>
        {isActive(scan.status) ? (
          <Alert tone="info">
            The scan is {scan.status === 'queued' ? 'waiting for a free scanner' : 'running'}. We send at most 2 requests per second to your site,
            so this usually takes under a minute. This page updates by itself.
          </Alert>
        ) : (
          <Alert tone="error">{scan.error ?? 'The scan failed.'}</Alert>
        )}
      </div>
    );
  }

  if (reportError?.code === 'upgrade_required') {
    return (
      <div className="page">
        {crumbs}
        <section className="card upsell">
          <h2>Scan history is a Pro feature</h2>
          <p className="muted">The free plan keeps the report of each site's latest scan. Upgrade to see older reports.</p>
          <Link to="/account" className="btn btn-primary">
            See plans
          </Link>
        </section>
      </div>
    );
  }
  if (reportError) return <Alert tone="error">{reportError.message}</Alert>;
  if (!report) return <p className="muted">Loading report…</p>;

  const groups = (['core', 'plugin', 'theme', 'php', 'web_server'] as const)
    .map((type) => ({ type, items: report.components.filter((c) => c.type === type) }))
    .filter((g) => g.items.length > 0);

  return (
    <div className="page">
      {crumbs}
      <header className="page-header report-header">
        <div>
          <h1>{report.domain}</h1>
          <p className="muted">
            Scanned {formatDate(report.finishedAt)} · {report.requestCount} requests to {report.baseUrl}
          </p>
          <p>
            <SeverityCounts counts={report.counts} />
          </p>
        </div>
        <ScoreBadge score={report.score} grade={report.grade} />
      </header>

      {report.compromiseSuspected && (
        <Alert tone="error">
          <strong>Your site may already be compromised.</strong> Some findings below are typical signs of a break-in. Deal with those first.
        </Alert>
      )}
      {error && <Alert tone="error">{error}</Alert>}

      <div className="report-actions">
        {report.features.pdf ? (
          <button type="button" className="btn btn-ghost" onClick={downloadPdf} disabled={downloading}>
            {downloading ? 'Preparing PDF…' : 'Download PDF'}
          </button>
        ) : (
          <span className="muted small">PDF export, scan history and fix guidance are part of Pro.</span>
        )}
      </div>

      {report.lockedCount > 0 && (
        <section className="card upsell">
          <h2>
            {report.lockedCount} of {report.findings.length} findings are locked
          </h2>
          <p className="muted">The free plan shows your score and a selection of findings. Pro shows every finding with evidence and step-by-step fixes.</p>
          <Link to="/account" className="btn btn-primary">
            Upgrade to Pro
          </Link>
        </section>
      )}

      <section aria-label="Findings" className="findings">
        {report.findings.length === 0 && (
          <div className="card empty-state">
            <h2>No issues found</h2>
            <p className="muted">Nothing we check for turned up. Keep everything updated and scan again regularly.</p>
          </div>
        )}
        {report.findings.map((f) =>
          f.locked ? <LockedCard key={f.id} finding={f} /> : <FindingCard key={f.id} finding={f} canRequestFix={report.features.fixRequests} onChanged={loadReport} />,
        )}
      </section>

      <section className="card">
        <h2>Software we found</h2>
        {groups.length === 0 ? (
          <p className="muted">We could not identify any WordPress software on this site.</p>
        ) : (
          groups.map((g) => (
            <div key={g.type} className="component-group">
              <h3>{TYPE_LABEL[g.type]}</h3>
              <table className="table">
                <tbody>
                  {g.items.map((c) => (
                    <tr key={`${c.type}:${c.slug}`}>
                      <td>{c.name ?? c.slug}</td>
                      <td>
                        {c.version ?? <span className="muted">unknown</span>}
                        {c.versionConfidence && c.versionConfidence !== 'confirmed' && <span className="muted small"> · {c.versionConfidence}</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))
        )}
      </section>

      <details className="card">
        <summary>
          <strong>Checks we ran</strong>
        </summary>
        <table className="table">
          <tbody>
            {scan.modules.map((m) => (
              <tr key={m.module}>
                <td>{MODULE_LABEL[m.module] ?? m.module}</td>
                <td>{m.status === 'ok' ? 'Done' : m.status === 'budget_exhausted' ? 'Stopped at request limit' : m.status === 'skipped' ? 'Skipped' : 'Could not complete'}</td>
                <td className="muted">{m.requests} requests</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>

      <DataSources report={report} />
    </div>
  );
}

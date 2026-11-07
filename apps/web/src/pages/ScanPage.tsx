import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router';
import { api, errorMessage, type ScanDetail } from '../api';
import { isActive, ScanStatusBadge, SeverityCounts, usePolling } from '../components/scans';
import { formatDate } from '../components/sites';
import { Alert } from '../components/ui';

const TYPE_LABEL = { core: 'WordPress core', plugin: 'Plugins', theme: 'Themes', php: 'PHP', web_server: 'Web server' } as const;
const MODULE_LABEL: Record<string, string> = {
  'wp-detect': 'WordPress detection',
  'plugins-themes': 'Plugins and themes',
  'vuln-match': 'Known vulnerabilities',
};
const CONFIDENCE_HINT = {
  confirmed: 'Stated directly by the site',
  likely: 'Read from a file that usually matches the installed version',
  possible: 'Guessed from asset links; may be inaccurate',
} as const;

export function ScanPage() {
  const { scanId = '' } = useParams();
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api<{ scan: ScanDetail }>(`/scans/${encodeURIComponent(scanId)}`)
      .then((res) => setScan(res.scan))
      .catch((err) => setError(errorMessage(err)));
  }, [scanId]);

  useEffect(load, [load]);
  usePolling(scan !== null && isActive(scan.status), load);

  if (error && !scan) return <Alert tone="error">{error}</Alert>;
  if (!scan) return <p className="muted">Loading…</p>;

  const groups = (['core', 'plugin', 'theme', 'php', 'web_server'] as const)
    .map((type) => ({ type, items: scan.components.filter((c) => c.type === type) }))
    .filter((g) => g.items.length > 0);

  return (
    <div className="page">
      <p className="breadcrumb">
        <Link to="/">Your sites</Link> / <Link to={`/sites/${scan.siteId}`}>{scan.domain}</Link> / Scan
      </p>
      <header className="page-header">
        <div>
          <h1>Scan of {scan.domain}</h1>
          <p className="muted">
            Started {formatDate(scan.startedAt ?? scan.createdAt)}
            {scan.finishedAt && ` · finished ${formatDate(scan.finishedAt)}`}
            {scan.requestCount > 0 && ` · ${scan.requestCount} requests`}
          </p>
        </div>
        <ScanStatusBadge status={scan.status} />
      </header>

      {isActive(scan.status) && (
        <Alert tone="info">
          The scan is {scan.status === 'queued' ? 'waiting for a free scanner' : 'running'}. We send at most 2 requests per second to your
          site, so this usually takes a minute or two. This page updates by itself.
        </Alert>
      )}
      {scan.status === 'failed' && <Alert tone="error">{scan.error ?? 'The scan failed.'}</Alert>}

      {scan.status === 'completed' && (
        <>
          <section className="card">
            <h2>Summary</h2>
            <p>
              <SeverityCounts counts={scan.findingCounts} />
            </p>
            <p className="muted small">
              The full report with explanations, fix steps and your security score arrives in the next build phase.
            </p>
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
                    <thead>
                      <tr>
                        <th scope="col">Name</th>
                        <th scope="col">Version</th>
                      </tr>
                    </thead>
                    <tbody>
                      {g.items.map((c) => (
                        <tr key={`${c.type}:${c.slug}`}>
                          <td>
                            {c.name ?? c.slug}
                            {c.name && c.name.toLowerCase() !== c.slug && <span className="muted small"> ({c.slug})</span>}
                          </td>
                          <td>
                            {c.version ?? <span className="muted">unknown</span>}
                            {c.versionConfidence && c.versionConfidence !== 'confirmed' && (
                              <span className="muted small" title={CONFIDENCE_HINT[c.versionConfidence]}>
                                {' '}
                                · {c.versionConfidence}
                              </span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ))
            )}
          </section>

          <section className="card">
            <h2>Checks run</h2>
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Check</th>
                  <th scope="col">Result</th>
                  <th scope="col">Requests</th>
                </tr>
              </thead>
              <tbody>
                {scan.modules.map((m) => (
                  <tr key={m.module}>
                    <td>{MODULE_LABEL[m.module] ?? m.module}</td>
                    <td>
                      {m.status === 'ok' ? 'Done' : m.status === 'budget_exhausted' ? 'Stopped at request limit' : m.status === 'skipped' ? 'Skipped' : 'Could not complete'}
                    </td>
                    <td>{m.requests}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </>
      )}
    </div>
  );
}

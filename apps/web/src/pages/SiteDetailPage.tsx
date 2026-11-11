import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { api, errorMessage, type ScanSummary, type Site, type VerifyMethod } from '../api';
import { useAuth } from '../auth';
import { isActive, ScanStatusBadge, SeverityCounts, usePolling } from '../components/scans';
import { InsideViewPanel } from '../components/InsideViewPanel';
import { CopyField, formatDate, StatusBadge } from '../components/sites';
import { Alert } from '../components/ui';

const METHOD_LABEL: Record<VerifyMethod, string> = { dns_txt: 'DNS record', file: 'file upload' };

export function SiteDetailPage() {
  const { siteId = '' } = useParams();
  const navigate = useNavigate();
  const [site, setSite] = useState<Site | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [insideScanId, setInsideScanId] = useState<string | null>(null);

  useEffect(() => {
    api<{ site: Site }>(`/sites/${encodeURIComponent(siteId)}`)
      .then((res) => setSite(res.site))
      .catch((err) => setError(errorMessage(err)));
  }, [siteId]);

  async function remove() {
    if (!site) return;
    if (!window.confirm(`Remove ${site.domain}? Its scan history will be deleted too.`)) return;
    try {
      await api(`/sites/${site.id}`, { method: 'DELETE' });
      navigate('/', { replace: true });
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  if (error && !site) {
    return (
      <div className="page">
        <Alert tone="error">{error}</Alert>
        <p>
          <Link to="/">Back to your sites</Link>
        </p>
      </div>
    );
  }
  if (!site) return <p className="muted">Loading…</p>;

  return (
    <div className="page">
      <p className="breadcrumb">
        <Link to="/">Your sites</Link> / {site.domain}
      </p>
      <header className="page-header">
        <div>
          <h1 className="site-title">{site.domain}</h1>
          <p className="muted">Added {formatDate(site.createdAt)}</p>
        </div>
        <StatusBadge status={site.status} />
      </header>

      {error && <Alert tone="error">{error}</Alert>}

      {site.status === 'verified' ? (
        <section className="card">
          <h2>Ownership verified</h2>
          <p>
            Confirmed by {METHOD_LABEL[site.verificationMethod ?? 'dns_txt']} on {formatDate(site.verifiedAt)}.
          </p>
          <p className="muted">
            Keep the {site.verificationMethod === 'file' ? 'file' : 'DNS record'} in place. We check it again before any scan if the last
            check is more than 24 hours old.
          </p>
        </section>
      ) : (
        <VerifyPanel site={site} onUpdate={setSite} />
      )}

      <InsideViewPanel site={site} onReport={setInsideScanId} />

      <ScansPanel site={site} onUpdate={setSite} refreshKey={insideScanId} />

      <section className="card danger-zone">
        <h2>Remove site</h2>
        <p className="muted">Deletes the site and all its scan history from your account.</p>
        <button type="button" className="btn btn-danger" onClick={remove}>
          Remove {site.domain}
        </button>
      </section>
    </div>
  );
}

function WeeklyScanToggle({ site, onUpdate }: { site: Site; onUpdate: (site: Site) => void }) {
  const { state } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pro = state.status === 'signed-in' && state.user.plan === 'pro';

  async function toggle() {
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ site: Site }>(`/sites/${site.id}`, { method: 'PATCH', body: { weeklyScan: !site.weeklyScan } });
      onUpdate(res.site);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="weekly">
      <label className="switch">
        <input type="checkbox" checked={site.weeklyScan} onChange={toggle} disabled={busy || (!pro && !site.weeklyScan)} />
        <span>Scan automatically every week</span>
      </label>
      {site.weeklyScan && site.nextScanAt && <span className="muted small">Next scan around {formatDate(site.nextScanAt)}</span>}
      {!pro && !site.weeklyScan && (
        <span className="muted small">
          Weekly scans are part of <Link to="/account">Pro</Link>.
        </span>
      )}
      {error && <Alert tone="error">{error}</Alert>}
    </div>
  );
}

function ScansPanel({ site, onUpdate, refreshKey }: { site: Site; onUpdate: (site: Site) => void; refreshKey: string | null }) {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [historyLimited, setHistoryLimited] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api<{ scans: ScanSummary[]; historyLimited: boolean }>(`/sites/${site.id}/scans`)
      .then((res) => {
        setScans(res.scans);
        setHistoryLimited(res.historyLimited);
      })
      .catch((err) => setError(errorMessage(err)));
    // refreshKey changes when a new inside report arrives; reload to show it.
  }, [site.id, refreshKey]);

  useEffect(load, [load]);
  usePolling(scans?.some((s) => isActive(s.status)) ?? false, load);

  async function start() {
    setBusy(true);
    setError(null);
    try {
      const { scan } = await api<{ scan: ScanSummary }>(`/sites/${site.id}/scans`, { method: 'POST', body: {} });
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  const canScan = site.status !== 'unverified';
  const running = scans?.some((s) => isActive(s.status)) ?? false;

  return (
    <section className="card">
      <div className="section-header">
        <h2>Scans</h2>
        <button type="button" className="btn btn-primary" onClick={start} disabled={!canScan || busy || running}>
          {busy ? 'Starting…' : running ? 'Scan in progress' : 'Run a scan'}
        </button>
      </div>
      {!canScan && <p className="muted">Verify ownership first. We never scan a site until its owner has proved control of it.</p>}
      {error && <Alert tone="error">{error}</Alert>}
      {scans && scans.length === 0 && canScan && <p className="muted">No scans yet. A scan takes a minute or two and only reads public pages.</p>}
      {scans && scans.length > 0 && (
        <ul className="scan-list">
          {scans.map((s) => (
            <li key={s.id} className="scan-row">
              <Link to={`/scans/${s.id}`}>{formatDate(s.createdAt)}</Link>
              <span className="muted small">{s.kind === 'inside' ? 'Inside report' : 'Outside scan'}</span>
              {s.status === 'completed' && s.grade ? (
                <span className={`grade-chip grade-${s.grade}`} title={`Score ${s.score} / 100`}>
                  {s.grade}
                </span>
              ) : (
                <ScanStatusBadge status={s.status} />
              )}
              {s.status === 'completed' && <SeverityCounts counts={s.findingCounts} />}
              {s.trigger === 'scheduled' && <span className="muted small">weekly</span>}
              {s.status === 'failed' && s.error && <span className="muted small">{s.error}</span>}
            </li>
          ))}
        </ul>
      )}
      {historyLimited && (
        <p className="muted small">
          Older scans are kept on <Link to="/account">Pro</Link>.
        </p>
      )}
      {canScan && <WeeklyScanToggle site={site} onUpdate={onUpdate} />}
    </section>
  );
}

function VerifyPanel({ site, onUpdate }: { site: Site; onUpdate: (site: Site) => void }) {
  const [method, setMethod] = useState<VerifyMethod>(site.verificationMethod ?? 'dns_txt');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);
  const { dns, file } = site.instructions;

  async function check() {
    setBusy(true);
    setResult(null);
    try {
      const res = await api<{ verified: boolean; message: string; site: Site }>(`/sites/${site.id}/verify`, { body: { method } });
      setResult({ ok: res.verified, message: res.message });
      onUpdate(res.site);
    } catch (err) {
      setResult({ ok: false, message: errorMessage(err) });
    } finally {
      setBusy(false);
    }
  }

  function downloadFile() {
    const url = URL.createObjectURL(new Blob([file.content], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = file.filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <section className="card">
      <h2>{site.status === 'stale' ? 'Confirm you still own this site' : 'Prove you own this site'}</h2>
      <p className="muted">
        {site.status === 'stale'
          ? 'Your last ownership check is more than 24 hours old. It will be re-checked automatically before the next scan, or you can check now.'
          : 'We only scan sites whose owners have proved control of them. Choose one method.'}
      </p>

      <div className="tabs" role="tablist" aria-label="Verification method">
        {(['dns_txt', 'file'] as const).map((m) => (
          <button
            key={m}
            type="button"
            role="tab"
            id={`tab-${m}`}
            aria-selected={method === m}
            aria-controls={`panel-${m}`}
            className={`tab ${method === m ? 'tab-active' : ''}`}
            onClick={() => {
              setMethod(m);
              setResult(null);
            }}
          >
            {m === 'dns_txt' ? 'Add a DNS record' : 'Upload a file'}
          </button>
        ))}
      </div>

      {method === 'dns_txt' ? (
        <div role="tabpanel" id="panel-dns_txt" aria-labelledby="tab-dns_txt" className="tab-panel">
          <ol className="steps">
            <li>Sign in to wherever your domain's DNS is managed (your registrar, Cloudflare, or your host).</li>
            <li>
              Add a <strong>TXT</strong> record with these details. If your provider adds the domain automatically, enter only the part
              before <code className="code-inline">{site.domain}</code> as the name.
              <CopyField label="Name / Host" value={dns.name} />
              <CopyField label="Value" value={dns.value} />
            </li>
            <li>Save it, wait a few minutes, then check below. Some providers take longer to publish changes.</li>
          </ol>
        </div>
      ) : (
        <div role="tabpanel" id="panel-file" aria-labelledby="tab-file" className="tab-panel">
          <ol className="steps">
            <li>
              Download the verification file, or create a plain text file with exactly this content:
              <CopyField label="File name" value={file.filename} />
              <CopyField label="Content" value={file.content} />
              <button type="button" className="btn btn-ghost btn-small" onClick={downloadFile}>
                Download {file.filename}
              </button>
            </li>
            <li>
              Upload it to your site's root folder, the same folder that contains <code className="code-inline">wp-config.php</code>.
            </li>
            <li>
              Check that it opens at{' '}
              <a href={file.url} target="_blank" rel="noopener noreferrer">
                {file.url}
              </a>
              , then check below.
            </li>
          </ol>
        </div>
      )}

      {result && <Alert tone={result.ok ? 'success' : 'error'}>{result.message}</Alert>}
      {!result && site.lastVerifyError && (
        <Alert tone="info">
          Last attempt ({formatDate(site.lastVerifyAttemptAt)}): {site.lastVerifyError}
        </Alert>
      )}

      <div className="actions">
        <button type="button" className="btn btn-primary" onClick={check} disabled={busy}>
          {busy ? 'Checking…' : 'Check now'}
        </button>
      </div>
    </section>
  );
}

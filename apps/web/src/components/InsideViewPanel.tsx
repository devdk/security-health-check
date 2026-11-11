import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router';
import { createPairingCode, disconnectPlugin, errorMessage, getPlugin, type PairingCode, type PluginStatus, type Site } from '../api';
import { useAuth } from '../auth';
import { usePolling } from './scans';
import { CopyField, formatDate } from './sites';
import { Alert } from './ui';

const POLL_MS = 4000;

function formatCountdown(ms: number): string {
  const total = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(total / 60)}:${String(total % 60).padStart(2, '0')}`;
}

/** Re-renders every second while `until` is in the future, and returns the milliseconds left. */
function useRemaining(until: string | null): number {
  const [now, setNow] = useState(() => Date.now());
  const end = until ? new Date(until).getTime() : 0;
  const running = end > now;
  useEffect(() => {
    if (!running) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [running]);
  return Math.max(0, end - now);
}

/** `onReport` hears the newest inside scan id, so the page can refresh its scan history. */
export function InsideViewPanel({ site, onReport }: { site: Site; onReport: (scanId: string | null) => void }) {
  const { state } = useAuth();
  const pro = state.status === 'signed-in' && state.user.plan === 'pro';
  const verified = site.status !== 'unverified';

  return (
    <section className="card" aria-labelledby="inside-view-title">
      <h2 id="inside-view-title">Inside view</h2>
      {!pro ? (
        <p>
          The companion plugin reports what a scan from outside can't see, such as inactive plugins, changed WordPress files and
          administrator accounts. It is part of <Link to="/account">Pro</Link>.
        </p>
      ) : !verified ? (
        <p className="muted">Verify ownership of {site.domain} first. We only pair the plugin with a site once its owner has proved control of it.</p>
      ) : (
        <InsideViewControls siteId={site.id} onReport={onReport} />
      )}
    </section>
  );
}

function InsideViewControls({ siteId, onReport }: { siteId: string; onReport: (scanId: string | null) => void }) {
  const [plugin, setPlugin] = useState<PluginStatus | null>(null);
  const [pairing, setPairing] = useState<PairingCode | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const remaining = useRemaining(pairing?.expiresAt ?? null);
  const codeLive = pairing !== null && remaining > 0;

  const refresh = useCallback(() => {
    getPlugin(siteId)
      .then((next) => {
        setPlugin(next);
        onReport(next.lastScanId);
        if (next.status === 'connected') setPairing(null);
      })
      .catch((err) => setError(errorMessage(err)));
  }, [siteId, onReport]);

  useEffect(refresh, [refresh]);
  // The plugin sends its first report a moment after pairing; keep watching until it lands.
  const awaitingFirstReport =
    plugin?.status === 'connected' && (!plugin.lastReportAt || !plugin.connectedAt || plugin.lastReportAt < plugin.connectedAt);
  usePolling(codeLive || awaitingFirstReport, refresh, POLL_MS);

  async function connect() {
    setBusy(true);
    setError(null);
    try {
      setPairing(await createPairingCode(siteId));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function disconnect() {
    setBusy(true);
    setError(null);
    try {
      setPlugin(await disconnectPlugin(siteId));
      setPairing(null);
      setConfirming(false);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (!plugin) {
    return error ? <Alert tone="error">{error}</Alert> : <p className="muted">Loading…</p>;
  }
  if (!plugin.available) {
    return <p className="muted">Plugin connections are switched off on this server, so the inside view isn't available right now.</p>;
  }

  return (
    <>
      {error && <Alert tone="error">{error}</Alert>}
      {plugin.status === 'connected' ? (
        <ConnectedDetails
          plugin={plugin}
          confirming={confirming}
          busy={busy}
          onAsk={() => setConfirming(true)}
          onCancel={() => setConfirming(false)}
          onConfirm={disconnect}
        />
      ) : (
        <PairingFlow expired={plugin.status === 'expired'} plugin={plugin} pairing={pairing} remaining={remaining} busy={busy} onConnect={connect} />
      )}
    </>
  );
}

function ConnectedDetails({
  plugin,
  confirming,
  busy,
  onAsk,
  onCancel,
  onConfirm,
}: {
  plugin: PluginStatus;
  confirming: boolean;
  busy: boolean;
  onAsk: () => void;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (confirming) cancelRef.current?.focus();
  }, [confirming]);

  return (
    <>
      <p>
        <span className="badge badge-verified">Connected</span>
      </p>
      <dl className="facts">
        <div>
          <dt>Connected since</dt>
          <dd>{formatDate(plugin.connectedAt) || 'Unknown'}</dd>
        </div>
        <div>
          <dt>Last report</dt>
          <dd>
            {plugin.lastReportAt ? (
              plugin.lastScanId ? (
                <Link to={`/scans/${plugin.lastScanId}`}>{formatDate(plugin.lastReportAt)}</Link>
              ) : (
                formatDate(plugin.lastReportAt)
              )
            ) : (
              <span className="muted">Nothing received yet</span>
            )}
          </dd>
        </div>
        <div>
          <dt>Plugin version</dt>
          <dd>{plugin.pluginVersion ?? <span className="muted">Unknown</span>}</dd>
        </div>
        <div>
          <dt>Key expires</dt>
          <dd>{formatDate(plugin.expiresAt) || 'Unknown'}</dd>
        </div>
      </dl>
      {confirming ? (
        <div className="confirm-box" role="group" aria-label="Confirm disconnect">
          <p>Disconnect the plugin? Its key stops working and no more inside reports arrive until you pair it again.</p>
          <div className="button-row">
            <button type="button" className="btn btn-danger" onClick={onConfirm} disabled={busy}>
              {busy ? 'Disconnecting…' : 'Yes, disconnect'}
            </button>
            <button type="button" className="btn btn-ghost" onClick={onCancel} disabled={busy} ref={cancelRef}>
              Keep it connected
            </button>
          </div>
        </div>
      ) : (
        <div className="button-row">
          <button type="button" className="btn btn-ghost" onClick={onAsk}>
            Disconnect
          </button>
        </div>
      )}
    </>
  );
}

function PairingFlow({
  expired,
  plugin,
  pairing,
  remaining,
  busy,
  onConnect,
}: {
  expired: boolean;
  plugin: PluginStatus;
  pairing: PairingCode | null;
  remaining: number;
  busy: boolean;
  onConnect: () => void;
}) {
  const codeLive = pairing !== null && remaining > 0;
  const codeLapsed = pairing !== null && remaining === 0;
  const label = pairing ? 'Get a new code' : expired ? 'Pair again' : 'Connect the plugin';

  return (
    <>
      {expired && (
        <Alert tone="info">
          The plugin's key expired{plugin.expiresAt ? ` on ${formatDate(plugin.expiresAt)}` : ''}. It can't send reports until you pair it again.
        </Alert>
      )}
      {!expired && (
        <p className="muted">
          Add the companion plugin to WordPress to include what only the inside can see. It only reads. It never changes your site.
        </p>
      )}

      <div className="button-row">
        <button type="button" className={pairing && codeLive ? 'btn btn-ghost' : 'btn btn-primary'} onClick={onConnect} disabled={busy}>
          {busy ? 'Getting a code…' : label}
        </button>
      </div>

      <div className="pairing-box">
        {pairing ? (
          <>
            <CopyField label="Service address" value={pairing.serviceUrl} large />
            <CopyField label="Pairing code" value={pairing.code} large />
            <p className={`small ${codeLapsed ? 'pairing-lapsed' : 'muted'}`} role="timer">
              {codeLive ? `Expires in ${formatCountdown(remaining)}. Waiting for the plugin…` : 'This code has expired. Get a new one.'}
            </p>
          </>
        ) : (
          <p className="muted small pairing-placeholder">Your service address and one-time code appear here.</p>
        )}
      </div>

      <ol className="steps">
        <li>
          Download the plugin: <a href="/downloads/shc-companion.zip">shc-companion.zip</a>.
        </li>
        <li>In WordPress, go to Plugins, Add New, Upload Plugin. Upload the zip and activate it.</li>
        <li>Open Tools, Security Health Check, and paste the service address and pairing code.</li>
      </ol>
    </>
  );
}

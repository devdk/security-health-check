import { useEffect, useState } from 'react';
import { api, errorMessage, type Billing } from '../api';
import { useAuth } from '../auth';
import { formatDate } from '../components/sites';
import { Alert } from '../components/ui';

const FREE = ['Score and grade for every scan', 'Counts of findings by severity', 'Full details for about a third of findings', 'Warnings about possible compromise', 'Up to 3 sites'];
const PRO = ['Every finding with evidence', 'Step-by-step fix guides', 'PDF reports', 'Scan history', 'Weekly automatic scans', '"Request a fix" from our team', 'Up to 25 sites'];

export function AccountPage() {
  const { state, refresh } = useAuth();
  const [billing, setBilling] = useState<Billing | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    api<{ billing: Billing }>('/billing')
      .then((res) => setBilling(res.billing))
      .catch((err) => setError(errorMessage(err)));
  }, []);

  async function change(action: 'upgrade' | 'cancel') {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const res = await api<{ billing: Billing; redirectUrl?: string | null }>(`/billing/${action}`, { body: action === 'upgrade' ? { plan: 'pro' } : {} });
      if (res.redirectUrl) {
        window.location.assign(res.redirectUrl);
        return;
      }
      setBilling(res.billing);
      setNotice(action === 'upgrade' ? 'You are now on Pro.' : 'You are back on the free plan.');
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (state.status !== 'signed-in') return null;

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Account</h1>
          <p className="muted">{state.user.email}</p>
        </div>
      </header>
      {error && <Alert tone="error">{error}</Alert>}
      {notice && <Alert tone="success">{notice}</Alert>}
      {billing?.testMode && (
        <Alert tone="info">
          Test mode: no payment provider is connected yet. Changing plan here is instant and free. This is turned off in production.
        </Alert>
      )}

      <div className="plans">
        <section className={`card plan ${billing?.plan === 'free' ? 'plan-current' : ''}`}>
          <h2>Free</h2>
          <ul>
            {FREE.map((f) => (
              <li key={f}>{f}</li>
            ))}
          </ul>
          {billing?.plan === 'pro' && billing.upgradesAvailable && (
            <button type="button" className="btn btn-ghost" onClick={() => change('cancel')} disabled={busy}>
              Switch to Free
            </button>
          )}
          {billing?.plan === 'free' && <p className="muted small">Your current plan</p>}
        </section>
        <section className={`card plan ${billing?.plan === 'pro' ? 'plan-current' : ''}`}>
          <h2>Pro</h2>
          <ul>
            {PRO.map((f) => (
              <li key={f}>{f}</li>
            ))}
          </ul>
          {billing?.plan === 'free' &&
            (billing.upgradesAvailable ? (
              <button type="button" className="btn btn-primary" onClick={() => change('upgrade')} disabled={busy}>
                {busy ? 'Upgrading…' : billing.testMode ? 'Upgrade (test mode)' : 'Upgrade to Pro'}
              </button>
            ) : (
              <p className="muted small">Upgrades open soon.</p>
            ))}
          {billing?.plan === 'pro' && (
            <p className="muted small">Your current plan{billing.currentPeriodEnd ? ` · renews ${formatDate(billing.currentPeriodEnd)}` : ''}</p>
          )}
        </section>
      </div>
    </div>
  );
}

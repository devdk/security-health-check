import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router';
import { SITE_LIMITS } from '@shc/shared';
import { api, errorMessage, type Site } from '../api';
import { useAuth } from '../auth';
import { StatusBadge } from '../components/sites';
import { Alert } from '../components/ui';

export function DashboardPage() {
  const { state } = useAuth();
  const navigate = useNavigate();
  const [sites, setSites] = useState<Site[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [domain, setDomain] = useState('');
  const [busy, setBusy] = useState(false);
  const [addError, setAddError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setSites((await api<{ sites: Site[] }>('/sites')).sites);
    } catch (err) {
      setLoadError(errorMessage(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (state.status !== 'signed-in') return null;
  const { user } = state;
  const limit = SITE_LIMITS[user.plan];
  const atLimit = sites !== null && sites.length >= limit;

  async function onAdd(e: FormEvent) {
    e.preventDefault();
    setAddError(null);
    // The API validates and explains problems with the domain; no duplicate rules here.
    setBusy(true);
    try {
      const { site } = await api<{ site: Site }>('/sites', { body: { domain } });
      navigate(`/sites/${site.id}`);
    } catch (err) {
      setAddError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Your sites</h1>
          <p className="muted">Add a WordPress site, prove you own it, then run a scan.</p>
        </div>
        <span className={`badge badge-${user.plan}`}>{user.plan === 'pro' ? 'Pro plan' : 'Free plan'}</span>
      </header>

      <section className="card">
        <h2>Add a site</h2>
        <form className="inline-form" onSubmit={onAdd} noValidate>
          <label htmlFor="new-domain" className="visually-hidden">
            Site address
          </label>
          <input
            id="new-domain"
            className="input"
            placeholder="example.com"
            autoComplete="off"
            spellCheck={false}
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            disabled={atLimit}
          />
          <button className="btn btn-primary" type="submit" disabled={busy || atLimit}>
            {busy ? 'Adding…' : 'Add site'}
          </button>
        </form>
        {addError && <Alert tone="error">{addError}</Alert>}
        <p className="muted small">
          {sites ? `${sites.length} of ${limit} sites used on your plan.` : ' '}
          {atLimit && ' Remove a site to add another.'}
        </p>
      </section>

      {loadError && <Alert tone="error">{loadError}</Alert>}

      {sites && sites.length === 0 && (
        <section className="card empty-state">
          <h2>No sites yet</h2>
          <p className="muted">Add your first WordPress site above to get started.</p>
        </section>
      )}

      {sites && sites.length > 0 && (
        <ul className="site-list" aria-label="Your sites">
          {sites.map((site) => (
            <li key={site.id} className="card site-row">
              <div className="site-row-main">
                <Link to={`/sites/${site.id}`} className="site-domain">
                  {site.domain}
                </Link>
                <StatusBadge status={site.status} />
              </div>
              <Link to={`/sites/${site.id}`} className="btn btn-ghost btn-small">
                {site.status === 'verified' ? 'Open' : 'Verify ownership'}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

import { useAuth } from '../auth';

export function DashboardPage() {
  const { state } = useAuth();
  if (state.status !== 'signed-in') return null;
  const { user } = state;

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Your sites</h1>
          <p className="muted">Add a WordPress site, prove you own it, then run a scan.</p>
        </div>
        <span className={`badge badge-${user.plan}`}>{user.plan === 'pro' ? 'Pro plan' : 'Free plan'}</span>
      </header>

      <section className="card empty-state">
        <h2>No sites yet</h2>
        <p className="muted">Site management and ownership verification arrive in the next build phase.</p>
      </section>
    </div>
  );
}

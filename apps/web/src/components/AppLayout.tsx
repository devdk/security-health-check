import type { ReactNode } from 'react';
import { Link, Navigate, Outlet, useLocation, useNavigate } from 'react-router';
import { useAuth } from '../auth';
import { ShieldIcon } from './ui';

/** Shell for signed-in pages. Redirects to sign-in when there is no session. */
export function AppLayout() {
  const { state, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  if (state.status === 'loading') {
    return (
      <div className="center-screen" aria-busy="true">
        <p className="muted">Loading…</p>
      </div>
    );
  }
  if (state.status === 'anonymous') {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }

  async function onLogout() {
    await logout();
    navigate('/login', { replace: true });
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <Link to="/" className="brand">
          <ShieldIcon />
          <span>Security Health Check</span>
        </Link>
        <div className="topbar-user">
          <Link to="/account" className="topbar-account">
            <span className="muted topbar-email">{state.user.email}</span>
            <span className={`badge badge-${state.user.plan}`}>{state.user.plan === 'pro' ? 'Pro' : 'Free'}</span>
          </Link>
          <button type="button" className="btn btn-ghost" onClick={onLogout}>
            Sign out
          </button>
        </div>
      </header>
      <main className="app-main">
        <Outlet />
      </main>
    </div>
  );
}

/** Keeps signed-in users away from the sign-in and register pages. */
export function GuestOnly({ children }: { children: ReactNode }) {
  const { state } = useAuth();
  if (state.status === 'loading') return null;
  if (state.status === 'signed-in') return <Navigate to="/" replace />;
  return <>{children}</>;
}

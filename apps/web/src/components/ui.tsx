import { useId, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode } from 'react';
import { Link } from 'react-router';

export function AuthCard({ title, subtitle, children, footer }: { title: string; subtitle?: string; children: ReactNode; footer?: ReactNode }) {
  return (
    <main className="auth-shell">
      <Link to="/" className="brand brand-centered" aria-label="Security Health Check home">
        <ShieldIcon />
        <span>Security Health Check</span>
      </Link>
      <section className="card auth-card">
        <h1>{title}</h1>
        {subtitle && <p className="muted">{subtitle}</p>}
        {children}
      </section>
      {footer && <div className="auth-footer">{footer}</div>}
    </main>
  );
}

export function Field({ label, hint, ...input }: { label: string; hint?: string } & InputHTMLAttributes<HTMLInputElement>) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input id={id} aria-describedby={hintId} {...input} />
      {hint && (
        <small id={hintId} className="muted">
          {hint}
        </small>
      )}
    </div>
  );
}

export function Alert({ tone, children }: { tone: 'error' | 'success' | 'info'; children: ReactNode }) {
  return (
    <div className={`alert alert-${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
      {children}
    </div>
  );
}

export function Button({ busy, children, ...props }: { busy?: boolean } & ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button className="btn btn-primary" disabled={busy || props.disabled} {...props}>
      {busy ? 'Please wait…' : children}
    </button>
  );
}

export function ShieldIcon() {
  return (
    <svg className="brand-icon" viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7L16 2z" fill="currentColor" />
      <path d="m11 16 3.5 3.5L21.5 12" fill="none" stroke="var(--brand-contrast)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Reads `#token=...` from the URL once and removes it so it is not left in history. */
export function takeHashToken(): string | null {
  const params = new URLSearchParams(window.location.hash.slice(1));
  const token = params.get('token');
  if (window.location.hash) {
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
  }
  return token && /^[A-Za-z0-9_-]{43}$/.test(token) ? token : null;
}

import { useState, type FormEvent } from 'react';
import { Link, useLocation, useNavigate } from 'react-router';
import { api, ApiError, errorMessage } from '../api';
import { useAuth } from '../auth';
import { Alert, AuthCard, Button, Field } from '../components/ui';

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unverified, setUnverified] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const from = (location.state as { from?: string } | null)?.from ?? '/';

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    setUnverified(false);
    try {
      await login(email, password);
      navigate(from, { replace: true });
    } catch (err) {
      if (err instanceof ApiError && err.code === 'email_not_verified') setUnverified(true);
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function resend() {
    try {
      const res = await api<{ message: string }>('/auth/verify-email/resend', { body: { email } });
      setNotice(res.message);
      setError(null);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <AuthCard
      title="Sign in"
      subtitle="Check how your WordPress site looks to an attacker."
      footer={
        <>
          New here? <Link to="/register">Create an account</Link>
        </>
      }
    >
      <form onSubmit={onSubmit} noValidate>
        {error && (
          <Alert tone="error">
            {error}
            {unverified && (
              <>
                {' '}
                <button type="button" className="link-button" onClick={resend}>
                  Send a new confirmation link
                </button>
              </>
            )}
          </Alert>
        )}
        {notice && <Alert tone="success">{notice}</Alert>}
        <Field label="Email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        <Field
          label="Password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <Button type="submit" busy={busy}>
          Sign in
        </Button>
        <p className="form-aside">
          <Link to="/forgot-password">Forgot your password?</Link>
        </p>
      </form>
    </AuthCard>
  );
}

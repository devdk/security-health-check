import { useState, type FormEvent } from 'react';
import { Link } from 'react-router';
import { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from '@shc/shared';
import { api, errorMessage } from '../api';
import { Alert, AuthCard, Button, Field } from '../components/ui';

export function RegisterPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < PASSWORD_MIN_LENGTH) return setError(`Use at least ${PASSWORD_MIN_LENGTH} characters for your password.`);
    if (password !== confirm) return setError('The two passwords do not match.');
    setBusy(true);
    try {
      const res = await api<{ message: string }>('/auth/register', { body: { email, password } });
      setDone(res.message);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <AuthCard title="Check your inbox" footer={<Link to="/login">Back to sign in</Link>}>
        <Alert tone="success">{done}</Alert>
        <p className="muted">
          We sent a confirmation link to <strong>{email}</strong>. It expires in 24 hours.
        </p>
      </AuthCard>
    );
  }

  return (
    <AuthCard
      title="Create your account"
      subtitle="Free accounts get a scored report for each verified site."
      footer={
        <>
          Already have an account? <Link to="/login">Sign in</Link>
        </>
      }
    >
      <form onSubmit={onSubmit} noValidate>
        {error && <Alert tone="error">{error}</Alert>}
        <Field label="Email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        <Field
          label="Password"
          type="password"
          autoComplete="new-password"
          required
          minLength={PASSWORD_MIN_LENGTH}
          maxLength={PASSWORD_MAX_LENGTH}
          hint={`At least ${PASSWORD_MIN_LENGTH} characters. A passphrase works well.`}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <Field
          label="Confirm password"
          type="password"
          autoComplete="new-password"
          required
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        <Button type="submit" busy={busy}>
          Create account
        </Button>
      </form>
    </AuthCard>
  );
}

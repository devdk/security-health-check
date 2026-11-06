import { useEffect, useRef, useState, type FormEvent } from 'react';
import { Link } from 'react-router';
import { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from '@shc/shared';
import { api, errorMessage } from '../api';
import { Alert, AuthCard, Button, Field, takeHashToken } from '../components/ui';

export function ResetPasswordPage() {
  const [token, setToken] = useState<string | null | undefined>(undefined);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const read = useRef(false);

  useEffect(() => {
    if (read.current) return;
    read.current = true;
    setToken(takeHashToken());
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < PASSWORD_MIN_LENGTH) return setError(`Use at least ${PASSWORD_MIN_LENGTH} characters for your password.`);
    if (password !== confirm) return setError('The two passwords do not match.');
    setBusy(true);
    try {
      const res = await api<{ message: string }>('/auth/password/reset', { body: { token, password } });
      setDone(res.message);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const footer = <Link to="/login">Back to sign in</Link>;

  if (token === undefined) return <AuthCard title="Choose a new password" footer={footer}>{null}</AuthCard>;
  if (token === null) {
    return (
      <AuthCard title="Choose a new password" footer={footer}>
        <Alert tone="error">
          This reset link is incomplete. <Link to="/forgot-password">Request a new one</Link>.
        </Alert>
      </AuthCard>
    );
  }
  if (done) {
    return (
      <AuthCard title="Password updated" footer={footer}>
        <Alert tone="success">{done}</Alert>
      </AuthCard>
    );
  }

  return (
    <AuthCard title="Choose a new password" subtitle="You'll be signed out of every device." footer={footer}>
      <form onSubmit={onSubmit} noValidate>
        {error && <Alert tone="error">{error}</Alert>}
        <Field
          label="New password"
          type="password"
          autoComplete="new-password"
          required
          minLength={PASSWORD_MIN_LENGTH}
          maxLength={PASSWORD_MAX_LENGTH}
          hint={`At least ${PASSWORD_MIN_LENGTH} characters.`}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <Field
          label="Confirm new password"
          type="password"
          autoComplete="new-password"
          required
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        <Button type="submit" busy={busy}>
          Update password
        </Button>
      </form>
    </AuthCard>
  );
}

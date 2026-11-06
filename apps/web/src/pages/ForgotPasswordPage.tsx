import { useState, type FormEvent } from 'react';
import { Link } from 'react-router';
import { api, errorMessage } from '../api';
import { Alert, AuthCard, Button, Field } from '../components/ui';

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ message: string }>('/auth/password/forgot', { body: { email } });
      setDone(res.message);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthCard title="Reset your password" subtitle="We'll email you a link to choose a new one." footer={<Link to="/login">Back to sign in</Link>}>
      {done ? (
        <Alert tone="success">{done}</Alert>
      ) : (
        <form onSubmit={onSubmit} noValidate>
          {error && <Alert tone="error">{error}</Alert>}
          <Field label="Email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
          <Button type="submit" busy={busy}>
            Send reset link
          </Button>
        </form>
      )}
    </AuthCard>
  );
}

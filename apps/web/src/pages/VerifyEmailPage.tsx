import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router';
import { api, errorMessage } from '../api';
import { Alert, AuthCard, takeHashToken } from '../components/ui';

type Status = { kind: 'working' } | { kind: 'ok'; message: string } | { kind: 'error'; message: string };

export function VerifyEmailPage() {
  const [status, setStatus] = useState<Status>({ kind: 'working' });
  const started = useRef(false);

  useEffect(() => {
    // Guard against React StrictMode running the effect twice: tokens are single-use.
    if (started.current) return;
    started.current = true;
    const token = takeHashToken();
    if (!token) {
      setStatus({ kind: 'error', message: 'This confirmation link is incomplete. Open the link from your email again.' });
      return;
    }
    api<{ message: string }>('/auth/verify-email', { body: { token } })
      .then((res) => setStatus({ kind: 'ok', message: res.message }))
      .catch((err) => setStatus({ kind: 'error', message: errorMessage(err) }));
  }, []);

  return (
    <AuthCard title="Confirm your email" footer={<Link to="/login">Go to sign in</Link>}>
      {status.kind === 'working' && <p className="muted">Confirming…</p>}
      {status.kind === 'ok' && <Alert tone="success">{status.message}</Alert>}
      {status.kind === 'error' && (
        <Alert tone="error">
          {status.message} You can request a new link from the sign-in page.
        </Alert>
      )}
    </AuthCard>
  );
}

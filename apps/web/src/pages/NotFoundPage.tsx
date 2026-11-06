import { Link } from 'react-router';
import { AuthCard } from '../components/ui';

export function NotFoundPage() {
  return (
    <AuthCard title="Page not found" subtitle="That address doesn't match anything here.">
      <p>
        <Link to="/">Go to your dashboard</Link>
      </p>
    </AuthCard>
  );
}

import { Link } from 'react-router';
import { ShieldIcon } from '../components/ui';

/** Public page linked from the scanner's User-Agent, for site operators who see it in their logs. */
export function ScannerPage() {
  return (
    <main className="prose-shell">
      <Link to="/" className="brand">
        <ShieldIcon />
        <span>Security Health Check</span>
      </Link>
      <article className="card prose">
        <h1>About our scanner</h1>
        <p>
          If you found <code className="code-inline">SecurityHealthCheck</code> in your server logs, a person who proved they control your
          website asked us to check its security.
        </p>

        <h2>What it does</h2>
        <ul>
          <li>It only checks sites whose owner has proved control, by adding a DNS record or uploading a file to the site.</li>
          <li>It makes only ordinary GET and HEAD requests that any web browser could make.</li>
          <li>It never tries to log in, guess passwords, submit forms, or exploit anything.</li>
          <li>It sends at most 2 requests per second, with a fixed cap on requests per scan.</li>
          <li>Every request identifies itself with the User-Agent SecurityHealthCheck.</li>
        </ul>

        <h2>Didn't ask for this?</h2>
        <p>
          Someone with access to your DNS or web server set up verification. To stop the scans, remove the{' '}
          <code className="code-inline">_shc-verify</code> TXT record or the <code className="code-inline">shc-verify-….txt</code> file from your
          site. Ownership is re-checked before scanning, so scans stop within 24 hours.
        </p>
      </article>
    </main>
  );
}

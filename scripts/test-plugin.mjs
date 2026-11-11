// Lints every plugin PHP file and runs the PHP protocol tests inside the wordpress:cli-php8.1 image.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('..', import.meta.url)).replace(/[\\/]+$/, '');

// The script runs inside the container: only the mount argument carries the host path.
const inner = 'set -e; find plugin -name "*.php" | sort | while read -r f; do php -l "$f"; done; php plugin/tests/run.php';

const result = spawnSync(
  'docker',
  ['run', '--rm', '-v', `${repo}:/repo:ro`, '-w', '/repo', '--entrypoint', 'sh', 'wordpress:cli-php8.1', '-c', inner],
  { stdio: 'inherit', env: { ...process.env, MSYS_NO_PATHCONV: '1' } },
);

if (result.error) {
  console.error(`Could not run docker: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status ?? 1);

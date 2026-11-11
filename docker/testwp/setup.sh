#!/bin/sh
# Prepares the local test WordPress used for end-to-end scans. Development only.
# Runs inside the official wordpress:cli image against the shared /var/www/html volume.
set -eu

echo "Waiting for WordPress files..."
for _ in $(seq 1 90); do
  [ -f /var/www/html/wp-includes/version.php ] && [ -f /var/www/html/wp-config.php ] && break
  sleep 2
done

cd /var/www/html

echo "Waiting for the database..."
for _ in $(seq 1 60); do
  wp db check >/dev/null 2>&1 && break
  sleep 2
done

if ! wp core is-installed >/dev/null 2>&1; then
  wp core install \
    --url="http://wordpress.test" \
    --title="SHC Test Site" \
    --admin_user="shc-admin" \
    --admin_password="$TESTWP_ADMIN_PASSWORD" \
    --admin_email="admin@wordpress.test" \
    --skip-email
fi

# A classic theme, so the scanner can fingerprint it from its stylesheet.
wp theme install twentytwentyone --version=2.0 --activate --force

# Deliberately outdated plugin with a published vulnerability:
# Contact Form 7 5.3.1, unrestricted file upload (CVE-2020-35489), fixed in 5.3.2.
wp plugin install contact-form-7 --version=5.3.1 --activate --force

# Keep it outdated: no automatic updates for anything on this test site.
wp plugin auto-updates disable --all >/dev/null 2>&1 || true
wp theme auto-updates disable --all >/dev/null 2>&1 || true

wp rewrite structure '/%postname%/' --hard >/dev/null

# Deliberate mistakes for the scanner to find. Dummy contents only: no real secrets.
cat > /var/www/html/wp-config.php.bak <<'EOF'
<?php
// Leftover backup created for end-to-end tests. Values are fake.
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wordpress' );
define( 'DB_PASSWORD', 'not-a-real-password' );
EOF
printf '[08-Nov-2026 10:00:00 UTC] PHP Warning:  Undefined variable $example in /var/www/html/wp-content/themes/example.php on line 3\n' > /var/www/html/wp-content/debug.log
mkdir -p /var/www/html/wp-content/uploads/2026/11

# Companion plugin (mounted read-only from ./plugin/shc-companion) and the inside findings it should report.
wp plugin activate shc-companion

mkdir -p /var/www/html/wp-content/uploads/2026/11 /var/www/html/wp-content/mu-plugins
cat > /var/www/html/wp-content/uploads/2026/11/cache-helper.php <<'EOF'
<?php
// Harmless test fixture: a PHP file in uploads. Does nothing.
EOF
cat > /var/www/html/wp-content/uploads/index.php <<'EOF'
<?php
// Silence is golden.
EOF
cat > /var/www/html/wp-content/mu-plugins/shc-test-fixture.php <<'EOF'
<?php
// Harmless test fixture: a PHP change outside any plugin or theme. Does nothing.
EOF
grep -q 'SHC test fixture' /var/www/html/wp-includes/template-loader.php ||
  echo '// SHC test fixture: harmless comment, makes this core file differ from its checksum.' >> /var/www/html/wp-includes/template-loader.php

# More than three administrators, with random passwords nobody needs.
for n in 1 2 3; do
  wp user get "shc-ops-$n" >/dev/null 2>&1 ||
    wp user create "shc-ops-$n" "shc-ops-$n@wordpress.test" --role=administrator >/dev/null
done

echo "Test WordPress ready: WordPress $(wp core version), Contact Form 7 $(wp plugin get contact-form-7 --field=version)"

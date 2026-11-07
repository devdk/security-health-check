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

echo "Test WordPress ready: WordPress $(wp core version), Contact Form 7 $(wp plugin get contact-form-7 --field=version)"

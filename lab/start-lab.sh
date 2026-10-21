#!/bin/sh
# Lab startup: Apache+mod_php (PHP_SAPI=apache) or the PHP embedded server
# (default: cli). Both with ASAN; the reports go to stderr -> `docker logs`.
set -e

if [ "${PHP_SAPI:-cli}" = "apache" ]; then
    . /etc/apache2/envvars
    exec /usr/sbin/apache2ctl -DFOREGROUND
fi

# The worker runs as www-data (like a real deployment) so that the code
# execution evidence shows the real privileges.
PHP_BIN=/opt/php/bin/php
if [ "${PHP_USER:-www-data}" != "root" ] && id "${PHP_USER:-www-data}" >/dev/null 2>&1; then
    exec setpriv --reuid="${PHP_USER:-www-data}" --regid="${PHP_USER:-www-data}" \
        --clear-groups "$PHP_BIN" -S 0.0.0.0:8080 -t /var/www/html
fi

exec "$PHP_BIN" -S 0.0.0.0:8080 -t /var/www/html

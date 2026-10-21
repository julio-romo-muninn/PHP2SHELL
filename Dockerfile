# =============================================================================
# Verification lab — CVE-2026-109618 / CVE-2026-109619
# UAF in php_session_rfc1867_progress (session.upload_progress / RFC1867)
#
# PHP 8.4.4 built FROM SOURCE with:
#   - --enable-debug              (symbols and assertions for readable traces)
#   - --enable-address-sanitizer  (ASAN: detects the Use-After-Free)
#   - USE_ZEND_ALLOC=0 at runtime (Zend's own allocator is taken out of the
#     picture, so every emalloc/efree goes through system malloc and ASAN
#     observes it)
#
# SAPI: PHP embedded server (php -S) with PHP_CLI_SERVER_WORKERS so the
# mutator's concurrent request is accepted while the upload is still in flight.
# ASAN reports are printed to stderr -> `docker logs`.
# =============================================================================
FROM debian:bookworm-slim

ARG PHP_VERSION=8.4.4
# Official sha256 published on https://www.php.net/releases (8.4 series)
ARG PHP_SHA256=719551f50a81961f802aa9102bf4a1a0b5a315074330ab37bc8035a15f4be71b
# SAPI used by the lab: cli (embedded server) | apache (mod_php, as in the
# exploitation video: Apache prefork + mod_php under ASAN).
ARG PHP_SAPI=cli
# APPLY_ABLATION=1 removes `Z_TRY_ADDREF(progress->data);` from ext/session:
# it ablates the UAF described by the "php2shell" claim, in order to (a) show
# that the lab's ASAN detector is sensitive to that bug and (b) pin down the
# root cause. Isolated research use only.
ARG APPLY_ABLATION=0
# ASAN=1 -> AddressSanitizer + USE_ZEND_ALLOC=0 (ASAN sees emalloc UAFs, but
#           memory_limit stops being accounted for: no OOM is possible).
# ASAN=0 -> no sanitizer + USE_ZEND_ALLOC=1 (memory_limit works: required to
#           reproduce the CVE-2026-109619 OOM trigger).
ARG ASAN=1

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
        build-essential autoconf bison re2c pkg-config \
        libxml2-dev libsqlite3-dev libssl-dev \
        llvm-14 perl \
    && if [ "$PHP_SAPI" = "apache" ]; then \
        apt-get install -y --no-install-recommends apache2 apache2-dev; \
       fi \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/php

# Official php.net distributions (8.4.4 dates from March 2025; the sha256 is
# pinned to the value published on https://www.php.net/releases)
RUN curl -fsSL "https://www.php.net/distributions/php-${PHP_VERSION}.tar.gz" -o php.tar.gz \
    && echo "${PHP_SHA256}  php.tar.gz" | sha256sum -c - \
    && tar -xzf php.tar.gz --strip-components=1 \
    && rm php.tar.gz

# Ablation (isolated research): removes the reference that keeps the progress
# array alive. Without this line, the UAF described by the claim is
# reproducible with a 258-byte request; with it, released PHP is clean.
RUN if [ "$APPLY_ABLATION" = "1" ]; then \
        before="$(grep -c 'Z_TRY_ADDREF(progress->data);' ext/session/session.c)"; \
        sed -i '/Z_TRY_ADDREF(progress->data);/d' ext/session/session.c; \
        after="$(grep -c 'Z_TRY_ADDREF(progress->data);' ext/session/session.c || true)"; \
        echo "ablation: Z_TRY_ADDREF removed (before=$before after=$after)"; \
        [ "$before" = "1" ] || { echo "ablation: line not found"; exit 1; }; \
    fi

RUN ./configure \
        --prefix=/opt/php \
        --with-config-file-path=/opt/php/etc \
        --with-config-file-scan-dir=/opt/php/etc/conf.d \
        --disable-cgi \
        --disable-phpdbg \
        --without-pear \
        --enable-debug \
        $( [ "$ASAN" = "1" ] && echo "--enable-address-sanitizer" ) \
        $( [ "$PHP_SAPI" = "apache" ] && echo "--with-apxs=/usr/bin/apxs" ) \
    && make -j"$(nproc)" \
    && make install \
    && make clean

# USE_ZEND_ALLOC=0: mandatory so that ASAN sees emalloc UAFs.
# halt_on_error=1: the worker dies after the first report (it stays in the logs).
ENV USE_ZEND_ALLOC=0 \
    PHP_CLI_SERVER_WORKERS=4 \
    ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-14 \
    ASAN_OPTIONS=alloc_dealloc_mismatch=0:detect_leaks=0:detect_stack_use_after_return=1:halt_on_error=1:abort_on_error=0:allocator_may_return_null=1:symbolize=1:print_scariness=1

RUN mkdir -p /opt/php/etc/conf.d /tmp/sessions /var/www/html /opt/labs \
    && chmod 1777 /tmp/sessions

COPY lab/php.ini /opt/php/etc/php.ini
COPY lab/conf.d/99-lab-memory.ini /opt/php/etc/conf.d/99-lab-memory.ini
COPY lab/index.php lab/_lab_mutator.php lab/lfi.php /var/www/html/
COPY lab/start-lab.sh /opt/labs/start-lab.sh
RUN chmod +x /opt/labs/start-lab.sh

# Apache + mod_php configuration (SAPI of the exploitation video):
# port 8080, DocumentRoot set to the lab, logs to stderr (docker logs) and ASAN
# preloaded into the Apache process.
RUN if [ "$PHP_SAPI" = "apache" ]; then \
        APHP="$(find /usr/lib -name 'libphp*.so' | head -1)"; \
        echo "LoadModule php_module ${APHP}" > /etc/apache2/mods-available/php.load; \
        ln -sf /etc/apache2/mods-available/php.load /etc/apache2/mods-enabled/php.load; \
        sed -i 's/^Listen 80.*/Listen 8080/' /etc/apache2/ports.conf; \
        sed -i 's#^DocumentRoot .*#DocumentRoot /var/www/html#' /etc/apache2/sites-available/000-default.conf; \
        sed -i 's#<Directory /var/www/>#<Directory /var/www/html/>#' /etc/apache2/sites-available/000-default.conf; \
        sed -i 's#^ErrorLog .*#ErrorLog /proc/self/fd/2#' /etc/apache2/sites-available/000-default.conf; \
        sed -i 's#^CustomLog .*#CustomLog /proc/self/fd/1 combined#' /etc/apache2/sites-available/000-default.conf; \
        echo "ServerName localhost" >> /etc/apache2/conf-available/servername.conf; \
        echo "ServerTokens Prod" >> /etc/apache2/conf-available/servername.conf; \
        a2enconf servername >/dev/null; \
        ASAN_LIB="$(ldconfig -p | grep -m1 'libasan.so.8' | awk '{print $NF}')"; \
        echo "export LD_PRELOAD=${ASAN_LIB}" >> /etc/apache2/envvars; \
    fi

WORKDIR /var/www/html
EXPOSE 8080

CMD ["/opt/labs/start-lab.sh"]

#!/bin/sh
# Four openssl s_server listeners, one weak cipher family per port.
# 4433 ADH | 4434 AECDH | 4435 NULL | 4436 EXPORT
set -eu

OPENSSL="${OPENSSL:-/usr/local/bin/openssl}"
CERTS="${CERTS:-/certs}"

echo "ADH ciphers:    $($OPENSSL ciphers 'ADH:!EXPORT:!eNULL' 2>/dev/null || true)"
echo "AECDH ciphers:  $($OPENSSL ciphers 'AECDH:!EXPORT:!eNULL' 2>/dev/null || true)"
echo "NULL ciphers:   $($OPENSSL ciphers 'eNULL:!aNULL:!EXPORT' 2>/dev/null || true)"
echo "EXPORT ciphers: $($OPENSSL ciphers -ssl3 'EXPORT' 2>/dev/null || true)"

# s_server stays in the foreground; background one process per port and
# keep PID 1 waiting so Docker does not exit.
"$OPENSSL" s_server -accept 4433 -www -nocert -serverpref \
  -dhparam "$CERTS/dhparam.pem" \
  -cipher 'ADH:!EXPORT:!eNULL' \
  -no_ssl2 &

"$OPENSSL" s_server -accept 4434 -www -nocert -serverpref \
  -named_curve prime256v1 \
  -cipher 'AECDH:!EXPORT:!eNULL' \
  -no_ssl2 &

"$OPENSSL" s_server -accept 4435 -www -serverpref \
  -cert "$CERTS/server.crt" -key "$CERTS/server.key" \
  -cipher 'eNULL:!aNULL:!EXPORT' \
  -no_ssl2 &

# EXPORT suites are SSLv3/TLS1-era and live behind OPENSSL_NO_WEAK_SSL_CIPHERS.
"$OPENSSL" s_server -accept 4436 -www -serverpref \
  -cert "$CERTS/export.crt" -key "$CERTS/export.key" \
  -dhparam "$CERTS/dhparam-export.pem" \
  -cipher 'EXPORT' \
  -ssl3 &

term() {
  pids=$(jobs -p) || true
  if [ -n "${pids:-}" ]; then
    kill $pids 2>/dev/null || true
  fi
  wait || true
}
trap term INT TERM

wait

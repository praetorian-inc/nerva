# Weak TLS cipher test fixture

OpenSSL 1.0.2u listeners for validating Nerva's anonymous / NULL / EXPORT
cipher detection. One family per port. Go's stdlib client cannot handshake
these suites; the detector sends a raw ClientHello instead.

Do not publish this image.

## Ports

| Port | Family | Finding ID |
|------|--------|------------|
| 4433 | ADH | `tls-anon-cipher` |
| 4434 | AECDH | `tls-anon-cipher` |
| 4435 | NULL | `tls-null-cipher` |
| 4436 | EXPORT (SSLv3) | `tls-export-cipher` |

## Manual run

```bash
# First build compiles OpenSSL 1.0.2u (~30s).
docker build -t nerva-tls-weak-ciphers testdata/tls-weak-ciphers

docker run --rm --name nerva-tls-weak \
  -p 127.0.0.1:8444:4433 \
  -p 127.0.0.1:8445:4434 \
  -p 127.0.0.1:8446:4435 \
  -p 127.0.0.1:8447:4436 \
  nerva-tls-weak-ciphers

./nerva --misconfigs --json \
  -t 127.0.0.1:8444,127.0.0.1:8445,127.0.0.1:8446,127.0.0.1:8447
```

Host OpenSSL 3 cannot complete the EXPORT handshake. Use Nerva or the
in-container `openssl s_client`.

## Integration test

```bash
go test -count=1 -timeout 15m ./pkg/scan \
  -run TestSimpleScanTarget_OpenSSLWeakCipherListeners
```

Skipped under `-short`.

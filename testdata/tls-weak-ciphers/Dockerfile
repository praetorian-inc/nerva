# Weak TLS cipher fixture for Nerva CheckTLS integration tests.
# One family per port: 4433 ADH | 4434 AECDH | 4435 NULL | 4436 EXPORT.
# Do not publish this image to the internet.
#
# OpenSSL 1.0.2u is the last series that still implements EXPORT-grade
# suites (removed in 1.1.0). Anonymous DH/ECDH and NULL encryption are
# in the same binary, so one image serves all four listeners.

FROM debian:bookworm-slim AS build

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl make perl \
 && rm -rf /var/lib/apt/lists/*

ARG OPENSSL_VERSION=1.0.2u
ARG OPENSSL_SHA256=ecd0c6ffb493dd06707d38b14bb4d8c2288bb7033735606569d8f90f89669d16

WORKDIR /src
RUN curl -fsSL "https://www.openssl.org/source/old/1.0.2/openssl-${OPENSSL_VERSION}.tar.gz" \
      -o openssl.tar.gz \
 && echo "${OPENSSL_SHA256}  openssl.tar.gz" | sha256sum -c - \
 && tar xzf openssl.tar.gz \
 && cd "openssl-${OPENSSL_VERSION}" \
 && case "$(uname -m)" in \
      aarch64|arm64) target=linux-aarch64 ;; \
      x86_64) target=linux-x86_64 ;; \
      *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;; \
    esac \
 && ./Configure "$target" \
      --prefix=/opt/openssl-legacy \
      --openssldir=/opt/openssl-legacy \
      no-shared \
      enable-weak-ssl-ciphers \
 && make -j"$(nproc)" \
 && make install_sw

FROM debian:bookworm-slim

COPY --from=build /opt/openssl-legacy/bin/openssl /usr/local/bin/openssl
COPY openssl.cnf /opt/openssl-legacy/openssl.cnf
COPY entrypoint.sh /entrypoint.sh

ENV OPENSSL_CONF=/opt/openssl-legacy/openssl.cnf

# 2048-bit cert for NULL (authenticated, no confidentiality).
# 512-bit cert + 512-bit DH for EXPORT RSA/DHE key exchange.
# 1024-bit DH for non-export ADH.
RUN chmod +x /entrypoint.sh \
 && mkdir -p /certs /opt/openssl-legacy \
 && /usr/local/bin/openssl genrsa -out /certs/server.key 2048 \
 && /usr/local/bin/openssl req -new -x509 -key /certs/server.key \
      -out /certs/server.crt -days 3650 -subj '/CN=tls-null.asv.test' \
 && /usr/local/bin/openssl genrsa -out /certs/export.key 512 \
 && /usr/local/bin/openssl req -new -x509 -key /certs/export.key \
      -out /certs/export.crt -days 3650 -subj '/CN=tls-export.asv.test' \
 && /usr/local/bin/openssl dhparam -out /certs/dhparam.pem 1024 \
 && /usr/local/bin/openssl dhparam -out /certs/dhparam-export.pem 512

EXPOSE 4433 4434 4435 4436
ENTRYPOINT ["/entrypoint.sh"]

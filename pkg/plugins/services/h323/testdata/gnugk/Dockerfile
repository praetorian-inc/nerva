# GNU Gatekeeper Docker build for H.323 plugin testing
# Builds ptlib, h323plus, and gnugk from official sources
#
# Build:  docker build -t gnugk-test .
# Run:    docker run -d --name h323-test -p 1720:1720/tcp gnugk-test
# Test:   nerva -t 127.0.0.1:1720 --verbose
# Stop:   docker stop h323-test && docker rm h323-test

FROM debian:bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    libssl-dev \
    flex \
    bison \
    autoconf \
    automake \
    libtool \
    pkg-config \
    libexpat1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Build PTLib (Portable Tools Library)
# https://github.com/willamowius/ptlib
RUN git clone --depth 1 https://github.com/willamowius/ptlib.git && \
    cd ptlib && \
    ./configure --prefix=/usr/local && \
    make -j$(nproc) && \
    make install

# Build H323Plus
# https://github.com/willamowius/h323plus
RUN git clone --depth 1 https://github.com/willamowius/h323plus.git && \
    cd h323plus && \
    ./configure --prefix=/usr/local && \
    make -j$(nproc) && \
    make install

# Update library path for gnugk build
ENV LD_LIBRARY_PATH=/usr/local/lib

# Build GNU Gatekeeper
# https://github.com/willamowius/gnugk
RUN git clone --depth 1 https://github.com/willamowius/gnugk.git && \
    cd gnugk && \
    ./configure --prefix=/usr/local && \
    make -j$(nproc) && \
    make install

# Runtime image (minimal)
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl3 \
    libexpat1 \
    && rm -rf /var/lib/apt/lists/*

# Copy libraries and binary from builder
COPY --from=builder /usr/local/lib/*.so* /usr/local/lib/
COPY --from=builder /bin/gnugk /usr/local/bin/

# Copy test configuration
COPY gatekeeper.ini /etc/gnugk/gatekeeper.ini

RUN ldconfig && mkdir -p /var/log/gnugk

# H.323 ports
# 1719/udp - RAS (Registration, Admission, Status)
# 1720/tcp - Call signaling
EXPOSE 1719/udp
EXPOSE 1720/tcp

# Run gatekeeper with trace level 3
CMD ["gnugk", "-c", "/etc/gnugk/gatekeeper.ini", "-ttt"]

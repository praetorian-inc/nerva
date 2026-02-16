# NRPE Docker build for plugin testing
# Builds NRPE 4.1.3 daemon configured to accept connections from any host
#
# Build:  docker build -t nrpe-test .
# Run:    docker run -d --name nrpe-test -p 5666:5666/tcp nrpe-test
# Test:   nerva -t 127.0.0.1:5666 --verbose
# Stop:   docker stop nrpe-test && docker rm nrpe-test

FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create nagios user/group required by NRPE install
RUN groupadd -r nagios && useradd -r -g nagios nagios

WORKDIR /build

# Build NRPE 4.1.3 from source
# Use dpkg-architecture for cross-platform SSL library path (amd64 vs arm64)
RUN SSL_LIB=$(dpkg-architecture -qDEB_HOST_MULTIARCH) \
    && wget -q https://github.com/NagiosEnterprises/nrpe/releases/download/nrpe-4.1.3/nrpe-4.1.3.tar.gz \
    && tar xzf nrpe-4.1.3.tar.gz \
    && cd nrpe-4.1.3 \
    && ./configure --prefix=/usr/local \
        --enable-command-args \
        --with-ssl=/usr \
        --with-ssl-lib=/usr/lib/${SSL_LIB} \
    && make all \
    && make install-daemon \
    && make install-config

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl3 \
    nagios-plugins-basic \
    && rm -rf /var/lib/apt/lists/*

# Create nagios user in runtime image
RUN groupadd -r nagios && useradd -r -g nagios nagios

COPY --from=builder /usr/local/bin/nrpe /usr/local/bin/nrpe
COPY --from=builder /usr/local/etc/nrpe.cfg /usr/local/etc/nrpe.cfg

# Configure NRPE for testing:
# - Allow connections from any host (0.0.0.0/0)
# - Enable command arguments
# Create directories and set permissions
RUN mkdir -p /usr/local/var && chown nagios:nagios /usr/local/var

# Configure NRPE for testing:
# - Allow connections from Docker bridge networks (CIDR /0 parsing is broken in NRPE 4.1.3)
# - Enable command arguments
# - Enable debug logging to file
RUN sed -i 's/allowed_hosts=127.0.0.1,::1/allowed_hosts=127.0.0.1,::1,10.0.0.1,172.17.0.1,192.168.65.1,192.168.65.2,192.168.65.3,192.168.65.4,192.168.65.5/' /usr/local/etc/nrpe.cfg \
    && sed -i 's/dont_blame_nrpe=0/dont_blame_nrpe=1/' /usr/local/etc/nrpe.cfg \
    && sed -i 's/debug=0/debug=1/' /usr/local/etc/nrpe.cfg \
    && sed -i 's|#log_file=/usr/local/var/nrpe.log|log_file=/usr/local/var/nrpe.log|' /usr/local/etc/nrpe.cfg

# NRPE port
EXPOSE 5666/tcp

# Run NRPE in foreground without SSL (plaintext mode for TCP testing)
CMD ["/usr/local/bin/nrpe", "-c", "/usr/local/etc/nrpe.cfg", "-f", "-n"]

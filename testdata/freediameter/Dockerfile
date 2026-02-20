# FreeDiameter server for SCTP testing
FROM debian:bookworm-slim

# Install FreeDiameter and dependencies
# Note: freediameter package includes the daemon binary
RUN apt-get update && apt-get install -y \
    freediameter \
    libsctp1 \
    lksctp-tools \
    openssl \
    ca-certificates \
    netcat-openbsd \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create directories for certificates and config
RUN mkdir -p /etc/freediameter /var/log/freediameter

# Generate self-signed certificates for testing
RUN openssl req -new -x509 -days 3650 -nodes \
    -out /etc/freediameter/cert.pem \
    -keyout /etc/freediameter/key.pem \
    -subj "/C=US/ST=Test/L=Test/O=Nerva/OU=Testing/CN=freediameter.local"

# Copy FreeDiameter configuration
COPY freediameter.conf /etc/freediameter/freeDiameter.conf

# Set permissions
RUN chmod 644 /etc/freediameter/cert.pem && \
    chmod 600 /etc/freediameter/key.pem && \
    chmod 644 /etc/freediameter/freeDiameter.conf

# Expose Diameter ports
EXPOSE 3868/sctp 3868/tcp 3869/tcp 5868/tcp

# Health check
HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
  CMD netstat -an | grep 3868 || exit 1

# Start FreeDiameter daemon
CMD ["/usr/bin/freeDiameterd", "--conf", "/etc/freediameter/freeDiameter.conf", "--debug"]

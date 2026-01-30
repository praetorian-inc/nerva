# OsmoSTP (Signal Transfer Point) for M3UA/SIGTRAN testing
FROM debian:bookworm-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    wget \
    gnupg2 \
    libsctp1 \
    lksctp-tools \
    netcat-openbsd \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Add Osmocom repository
RUN wget -O - https://downloads.osmocom.org/packages/osmocom:/latest/Debian_12/Release.key | apt-key add - && \
    echo "deb https://downloads.osmocom.org/packages/osmocom:/latest/Debian_12/ ./" > /etc/apt/sources.list.d/osmocom-latest.list

# Install OsmoSTP
RUN apt-get update && apt-get install -y \
    osmo-stp \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /data /var/log/osmo-stp /etc/osmocom

# Copy configuration
COPY osmo-stp.cfg /etc/osmocom/osmo-stp.cfg

# Set permissions
RUN chmod 644 /etc/osmocom/osmo-stp.cfg

# Expose ports
# 2905 - M3UA (SCTP)
# 14001 - SUA (SCTP)
# 4239 - VTY telnet interface
EXPOSE 2905/sctp 2905/tcp 14001/sctp 14001/tcp 4239/tcp

# Health check
HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
    CMD nc -z localhost 2905 || exit 1

# Run OsmoSTP
CMD ["osmo-stp", "-c", "/etc/osmocom/osmo-stp.cfg"]

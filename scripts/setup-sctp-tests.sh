#!/bin/bash
# Post-create setup script for SCTP testing environment
set -e

echo "=================================================="
echo "Setting up SCTP testing environment for Nerva"
echo "=================================================="

# Load SCTP kernel module
echo ""
echo "[1/5] Loading SCTP kernel module..."
if lsmod | grep -q sctp; then
    echo "✓ SCTP module already loaded"
else
    if modprobe sctp 2>/dev/null; then
        echo "✓ SCTP module loaded successfully"
    else
        echo "⚠ Warning: Could not load SCTP module"
        echo "  This may be expected in some environments"
    fi
fi

# Verify SCTP support
echo ""
echo "[2/5] Verifying SCTP support..."
if [ -f /proc/net/sctp/snmp ]; then
    echo "✓ SCTP support verified (/proc/net/sctp/snmp exists)"
    echo ""
    echo "SCTP Statistics:"
    head -5 /proc/net/sctp/snmp | sed 's/^/  /'
else
    echo "⚠ Warning: /proc/net/sctp/snmp not found"
    echo "  SCTP may not be available on this host"
fi

# Check for SCTP tools
echo ""
echo "[3/5] Checking SCTP tools..."
if command -v checksctp &> /dev/null; then
    echo "✓ lksctp-tools installed (checksctp available)"
else
    echo "⚠ lksctp-tools not found"
fi

# Build nerva with SCTP tags
echo ""
echo "[4/5] Building nerva with SCTP support..."
cd /workspace
if go build -tags linux,sctp -o nerva ./cmd/nerva; then
    echo "✓ Nerva built successfully with SCTP support"
else
    echo "⚠ Warning: Build failed"
    echo "  This is expected if SCTP dependencies are not yet added"
fi

# Test connectivity to FreeDiameter server
echo ""
echo "[5/5] Testing connectivity to FreeDiameter server..."
RETRIES=30
FREEDIAMETER_HOST="${FREEDIAMETER_HOST:-freediameter}"
FREEDIAMETER_PORT="${FREEDIAMETER_PORT:-3868}"

echo "Waiting for FreeDiameter server at ${FREEDIAMETER_HOST}:${FREEDIAMETER_PORT}..."
for i in $(seq 1 $RETRIES); do
    if nc -zv -w 2 "${FREEDIAMETER_HOST}" "${FREEDIAMETER_PORT}" 2>/dev/null; then
        echo "✓ FreeDiameter server is reachable"
        break
    fi
    if [ $i -eq $RETRIES ]; then
        echo "⚠ Warning: Could not connect to FreeDiameter server"
        echo "  Start services with: docker-compose -f docker-compose.dev.yml up -d"
        break
    fi
    echo "  Attempt $i/$RETRIES... (retrying in 2s)"
    sleep 2
done

# Display environment summary
echo ""
echo "=================================================="
echo "SCTP Testing Environment Ready"
echo "=================================================="
echo ""
echo "Environment Variables:"
echo "  SCTP_ENABLED:       ${SCTP_ENABLED:-not set}"
echo "  FREEDIAMETER_HOST:  ${FREEDIAMETER_HOST:-freediameter}"
echo "  FREEDIAMETER_PORT:  ${FREEDIAMETER_PORT:-3868}"
echo "  NERVA_TEST_MODE:    ${NERVA_TEST_MODE:-not set}"
echo ""
echo "Available Services:"
echo "  - FreeDiameter:     ${FREEDIAMETER_HOST}:3868 (Diameter SCTP/TCP)"
echo "  - MongoDB:          mongo:27017 (with --profile full)"
echo "  - Open5GS HSS:      open5gs-hss:3870 (with --profile full)"
echo ""
echo "Quick Start Commands:"
echo "  - Run SCTP tests:   make sctp-test"
echo "  - View logs:        make sctp-logs"
echo "  - Build with SCTP:  go build -tags linux,sctp ./cmd/nerva"
echo "  - Start full stack: docker-compose -f docker-compose.dev.yml --profile full up -d"
echo ""
echo "=================================================="

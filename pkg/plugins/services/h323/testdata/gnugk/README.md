# GNU Gatekeeper Test Fixtures

This directory contains Docker configuration for running a local H.323 gatekeeper
to validate the Nerva H.323 fingerprinting plugin.

## Prerequisites

- Docker installed and running
- Nerva binary built (`go build ./cmd/nerva`)

## Quick Start

```bash
# Build the test image (takes 5-10 minutes - compiles from source)
cd pkg/plugins/services/h323/testdata/gnugk
docker build -t gnugk-test .

# Start the H.323 test server
docker run -d --name h323-test -p 1720:1720/tcp gnugk-test

# Verify it's running
docker logs h323-test
# Should show: GNU Gatekeeper with ID 'TestGK' started

# Test with Nerva
./nerva -t 127.0.0.1:1720 --verbose
# Expected output: h323://127.0.0.1:1720

# Test JSON output
./nerva -t 127.0.0.1:1720 --json
# Expected: {"ip":"127.0.0.1","port":1720,"protocol":"h323",...}

# Cleanup
docker stop h323-test && docker rm h323-test
```

## What Gets Built

The Dockerfile builds from official upstream sources:

| Component | Source | Purpose |
|-----------|--------|---------|
| PTLib | github.com/willamowius/ptlib | Portable runtime library |
| H323Plus | github.com/willamowius/h323plus | H.323 protocol stack |
| GNU Gatekeeper | github.com/willamowius/gnugk | H.323 gatekeeper/proxy |

## Test Validation Checklist

### True Positive Tests

```bash
# H.323 should be detected on the test server
./nerva -t 127.0.0.1:1720 --verbose
# ✓ Expected: h323://127.0.0.1:1720
```

### False Positive Tests

```bash
# HTTP should NOT be detected as H.323
./nerva -t google.com:80 --verbose
# ✓ Expected: http://google.com:80 (NOT h323)

# SSH should NOT be detected as H.323
./nerva -t github.com:22 --verbose
# ✓ Expected: ssh://github.com:22 (NOT h323)
```

## Configuration

The `gatekeeper.ini` file configures GNU Gatekeeper to:

- Listen on port 1720/TCP for call signaling
- Accept unregistered calls (required for fingerprinting)
- Enable routed mode for proper H.225 message handling
- Disable proxy mode (not needed for testing)

## Troubleshooting

### Build fails with "not found" errors

The build requires network access to clone git repositories. Ensure Docker
has internet connectivity.

### Connection refused

```bash
# Verify container is running
docker ps | grep h323-test

# Check container logs for errors
docker logs h323-test
```

### Empty metadata in JSON output

This is expected behavior. The minimal Setup packet used for fingerprinting
doesn't elicit vendor information from most gatekeepers. Detection works
correctly; metadata extraction requires a full H.225 call setup exchange.

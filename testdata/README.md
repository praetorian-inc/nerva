# SCTP Testing Environment for Nerva

This directory contains test infrastructure for SCTP (Stream Control Transmission Protocol) based service fingerprinting, including Diameter protocol testing for telecom environments.

## Directory Structure

```
testdata/
├── freediameter/           # FreeDiameter server for Diameter protocol testing
│   ├── Dockerfile          # FreeDiameter container image
│   └── freediameter.conf   # Minimal Diameter server configuration
├── open5gs/                # Optional Open5GS HSS for realistic 5G/LTE testing
│   └── hss.yaml            # HSS configuration (Diameter S6a interface)
└── README.md               # This file
```

## Quick Start

### 1. Start the SCTP Test Environment

```bash
# From nerva root directory
make sctp-up
```

This starts:
- **nerva-dev**: Development container with SCTP kernel module and tools
- **freediameter**: FreeDiameter server listening on port 3868 (SCTP/TCP)

### 2. Enter the Development Container

```bash
make sctp-shell
```

### 3. Run SCTP Tests

```bash
make sctp-test
```

### 4. View Logs

```bash
make sctp-logs
```

## Services

### FreeDiameter (Minimal Diameter Server)

**Purpose**: Provides a basic Diameter protocol server for testing SCTP connectivity and Diameter message handling.

**Ports**:
- `3868`: Diameter (SCTP and TCP)
- `3869`: Diameter (TCP alternative)
- `5868`: Diameter with TLS (optional)

**Configuration**: `freediameter/freediameter.conf`
- Identity: `freediameter.local`
- Realm: `local`
- Responds to CER (Capabilities-Exchange-Request) with CEA

**Testing**:
```bash
# Inside development container
nc -zv freediameter 3868  # TCP connectivity test

# SCTP connectivity (requires SCTP tools)
checksctp -H freediameter -p 3868
```

### Open5GS HSS (Optional - Full Stack)

**Purpose**: Provides a realistic 5G/LTE Home Subscriber Server for comprehensive Diameter S6a interface testing.

**Enable with**:
```bash
make sctp-full-up
```

**Ports**:
- `3870`: Diameter S6a interface (SCTP)
- `7777`: REST API

**Services Started**:
- `open5gs-hss`: HSS with Diameter S6a
- `mongo`: MongoDB for subscriber database

**Configuration**: `open5gs/hss.yaml`

## Environment Variables

Configure the test environment by setting these variables:

| Variable            | Default         | Description                      |
|---------------------|-----------------|----------------------------------|
| `SCTP_ENABLED`      | `true`          | Enable SCTP kernel module        |
| `FREEDIAMETER_HOST` | `freediameter`  | FreeDiameter server hostname     |
| `FREEDIAMETER_PORT` | `3868`          | FreeDiameter server port         |
| `NERVA_TEST_MODE`   | `integration`   | Test mode for integration tests  |

## Makefile Targets

All targets are defined in `Makefile.sctp`:

| Target                | Description                                    |
|-----------------------|------------------------------------------------|
| `sctp-up`             | Start minimal SCTP test environment            |
| `sctp-full-up`        | Start full stack (with Open5GS HSS)           |
| `sctp-down`           | Stop all SCTP test services                    |
| `sctp-test`           | Run SCTP integration tests                     |
| `sctp-test-coverage`  | Run tests with coverage report                 |
| `sctp-logs`           | View FreeDiameter logs                         |
| `sctp-logs-all`       | View all service logs                          |
| `sctp-status`         | Show service status and connectivity           |
| `sctp-shell`          | Enter development container shell              |
| `sctp-verify`         | Verify SCTP kernel module and connectivity     |
| `sctp-clean`          | Remove all containers and volumes              |
| `sctp-rebuild`        | Rebuild containers from scratch                |
| `sctp-help`           | Show all available targets                     |

## SCTP Kernel Module

The SCTP kernel module is loaded automatically in the development container.

**Verify SCTP support**:
```bash
# Check if module is loaded
lsmod | grep sctp

# Check SCTP proc filesystem
ls -l /proc/net/sctp/

# View SCTP statistics
cat /proc/net/sctp/snmp
```

**Manual module loading** (if needed):
```bash
modprobe sctp
```

## Adding New SCTP Protocol Tests

### 1. Create Protocol Plugin Directory

```bash
mkdir -p pkg/plugins/services/my-sctp-protocol/
```

### 2. Implement Fingerprinting Logic

```go
// pkg/plugins/services/my-sctp-protocol/my-sctp-protocol.go
package mysctpprotocol

import (
    "context"
    "net"

    "github.com/praetorian-inc/nerva/pkg/plugins"
)

type MySCTPProtocolPlugin struct{}

func (p *MySCTPProtocolPlugin) Run(ctx context.Context, target plugins.Target, conn net.Conn) (*plugins.Service, error) {
    // SCTP-specific detection logic
    // ...
}

func init() {
    plugins.RegisterPlugin(&MySCTPProtocolPlugin{})
}
```

### 3. Add Integration Test

```go
// pkg/plugins/services/my-sctp-protocol/my-sctp-protocol_test.go
//go:build linux && integration

package mysctpprotocol

import (
    "testing"
)

func TestMySCTPProtocol_Integration(t *testing.T) {
    // Test against FreeDiameter or Open5GS HSS
    // ...
}
```

### 4. Add Test Service to docker-compose.dev.yml

```yaml
my-sctp-service:
  image: my-sctp-protocol-server:latest
  networks:
    - sctp-test-network
  ports:
    - "5000:5000"
  environment:
    - SCTP_ENABLED=true
```

## SCTP Protocol Resources

### Supported Protocols (Planned)

- **Diameter**: Implemented (FreeDiameter server)
- **SIGTRAN** (SS7 over IP): M2PA, M2UA, M3UA
- **S1AP**: LTE S1 interface (eNB ↔ MME)
- **NGAP**: 5G NG interface (gNB ↔ AMF)
- **SCTP-based SIP**: SIP over SCTP for telecom

### Protocol Specifications

- **Diameter**: RFC 6733
- **SCTP**: RFC 4960
- **M3UA**: RFC 4666
- **S1AP**: 3GPP TS 36.413
- **NGAP**: 3GPP TS 38.413

## Troubleshooting

### SCTP Module Not Loading

**Symptom**: `modprobe: FATAL: Module sctp not found`

**Solution**:
1. Ensure host kernel has SCTP support: `uname -r`
2. Run container with `--privileged` flag
3. Use `--cap-add=SYS_MODULE` if privileged mode unavailable

### FreeDiameter Not Reachable

**Symptom**: `nc: connect to freediameter port 3868 (tcp) failed: Connection refused`

**Solution**:
```bash
# Check if FreeDiameter is running
make sctp-status

# Restart services
make sctp-down && make sctp-up

# View logs for errors
make sctp-logs
```

### Test Timeouts

**Symptom**: Tests hang or timeout after 30 seconds

**Solution**:
1. Verify network connectivity: `make sctp-verify`
2. Check service health: `docker-compose -f docker-compose.dev.yml ps`
3. Increase test timeout: `-timeout 5m`

### Docker Network Issues

**Symptom**: Containers can't communicate

**Solution**:
```bash
# Recreate network
make sctp-clean
make sctp-up

# Check network configuration
docker network inspect nerva_sctp-test-network
```

## Development Workflow

### Typical Development Session

```bash
# 1. Start environment
make sctp-up

# 2. Enter development container
make sctp-shell

# 3. Inside container: Build with SCTP tags
go build -tags linux,sctp -o nerva ./cmd/nerva

# 4. Run specific test
go test -v -tags linux,sctp,integration ./pkg/plugins/services/diameter/... -run TestDiameter_Detection

# 5. Outside container: View logs if needed
make sctp-logs

# 6. Stop environment when done
make sctp-down
```

### Adding New Test Scenarios

1. Add new service to `docker-compose.dev.yml`
2. Create testdata configuration in `testdata/my-service/`
3. Implement test in `pkg/plugins/services/my-service/`
4. Add Makefile target if needed
5. Update this README with new service documentation

## Container Architecture

### Network: sctp-test-network

All services communicate over a dedicated Docker bridge network with jumbo frames (MTU 9000) for realistic protocol testing.

### Volumes

- `go-cache`: Go module cache (shared across container restarts)
- `go-build-cache`: Go build cache (speeds up compilation)
- `mongo-data`: MongoDB data persistence (for Open5GS)

### Privileges

The development container requires elevated privileges for SCTP kernel module loading:

- `--privileged`: Full access to host devices
- `--cap-add=NET_ADMIN`: Network administration
- `--cap-add=SYS_MODULE`: Kernel module loading
- `--cap-add=SYS_ADMIN`: System administration

## Extending This Environment

### Adding New Protocol Servers

1. Create `testdata/my-protocol/Dockerfile`
2. Add configuration files to `testdata/my-protocol/`
3. Add service to `docker-compose.dev.yml`
4. Document in this README

### Adding New Test Profiles

Use Docker Compose profiles to conditionally start services:

```yaml
my-optional-service:
  image: my-service:latest
  profiles:
    - full
    - my-profile
```

Start with: `docker-compose -f docker-compose.dev.yml --profile my-profile up`

## Resources

- [FreeDiameter Documentation](http://www.freediameter.net/)
- [Open5GS Project](https://open5gs.org/)
- [SCTP RFC 4960](https://datatracker.ietf.org/doc/html/rfc4960)
- [Diameter RFC 6733](https://datatracker.ietf.org/doc/html/rfc6733)
- [Nerva Fingerprintx Documentation](../../README.md)

## License

This testing infrastructure follows the same license as Nerva.

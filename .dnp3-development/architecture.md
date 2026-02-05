# DNP3 Plugin Architecture

## Overview

The DNP3 plugin follows the established Nerva plugin pattern (similar to modbus) for detecting DNP3/SCADA services on port 20000.

## File Structure

```
modules/nerva/pkg/plugins/services/dnp3/
├── dnp3.go          # Main plugin implementation
└── dnp3_test.go     # Unit and integration tests
```

## Types.go Additions

### Protocol Constant
```go
// In pkg/plugins/types.go
ProtoDNP3 = "dnp3"
```

### Service Metadata Struct
```go
type ServiceDNP3 struct {
    SourceAddress      uint16   `json:"sourceAddress,omitempty"`      // Responding device address
    DestinationAddress uint16   `json:"destinationAddress,omitempty"` // Target address from probe
    DeviceRole         string   `json:"deviceRole,omitempty"`         // "master" or "outstation"
    FunctionCode       uint8    `json:"functionCode,omitempty"`       // Response function code
    CPEs               []string `json:"cpes,omitempty"`               // CPE identifiers
}

func (e ServiceDNP3) Type() string { return ProtoDNP3 }
```

### Metadata() Switch Case
```go
case ProtoDNP3:
    var p ServiceDNP3
    _ = json.Unmarshal(e.Raw, &p)
    return p
```

## Plugin Implementation

### Constants
```go
const (
    DNP3StartByte1     = 0x05
    DNP3StartByte2     = 0x64
    DNP3HeaderLength   = 10
    DNP3MinResponseLen = 10  // Minimum valid response

    // Control byte masks
    DNP3CtlDIR  = 0x80  // Direction: 1=from master
    DNP3CtlPRM  = 0x40  // Primary message
    DNP3CtlFCB  = 0x20  // Frame count bit
    DNP3CtlFCV  = 0x10  // Frame count valid
    DNP3CtlFunc = 0x0F  // Function code mask

    // Safe function codes
    DNP3FuncRequestLinkStatus = 0x09  // Safe diagnostic query
    DNP3FuncACK              = 0x00   // Acknowledgment
    DNP3FuncLinkStatusResp   = 0x0B   // Link status response
)
```

### Plugin Struct
```go
type DNP3Plugin struct{}

func init() {
    plugins.RegisterPlugin(&DNP3Plugin{})
}

const DNP3 = "dnp3"
```

### Interface Methods

```go
func (p *DNP3Plugin) Name() string {
    return DNP3
}

func (p *DNP3Plugin) Type() plugins.Protocol {
    return plugins.TCP
}

func (p *DNP3Plugin) Priority() int {
    return 400  // Same as modbus (ICS protocols)
}

func (p *DNP3Plugin) PortPriority(port uint16) bool {
    return port == 20000
}
```

### Run Method (Core Detection Logic)

```go
func (p *DNP3Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
    // 1. Build Request Link Status probe
    probe := buildRequestLinkStatusProbe()

    // 2. Send probe and receive response
    response, err := utils.SendRecv(conn, probe, timeout)
    if err != nil {
        return nil, err
    }
    if len(response) < DNP3MinResponseLen {
        return nil, nil
    }

    // 3. Validate DNP3 start bytes (0x0564)
    if response[0] != DNP3StartByte1 || response[1] != DNP3StartByte2 {
        return nil, nil
    }

    // 4. Parse response header
    controlByte := response[3]
    destAddr := binary.LittleEndian.Uint16(response[4:6])
    srcAddr := binary.LittleEndian.Uint16(response[6:8])

    // 5. Determine device role from control byte
    deviceRole := parseDeviceRole(controlByte)
    funcCode := controlByte & DNP3CtlFunc

    // 6. Create service metadata
    metadata := plugins.ServiceDNP3{
        SourceAddress:      srcAddr,
        DestinationAddress: destAddr,
        DeviceRole:         deviceRole,
        FunctionCode:       funcCode,
    }

    return plugins.CreateServiceFrom(target, metadata, false, "", plugins.TCP), nil
}
```

### Helper Functions

```go
// buildRequestLinkStatusProbe creates a safe DNP3 probe packet
func buildRequestLinkStatusProbe() []byte {
    header := []byte{
        DNP3StartByte1, DNP3StartByte2,  // Start bytes: 0x0564
        0x05,                             // Length: 5 bytes follow
        0x49,                             // Control: PRM=1, Func=0x09 (Request Link Status)
        0x00, 0x00,                       // Destination: 0 (broadcast)
        0x01, 0x00,                       // Source: 1 (our address)
    }

    // Calculate and append CRC
    crc := calculateDNP3CRC(header[0:8])
    return append(header, byte(crc&0xFF), byte(crc>>8))
}

// calculateDNP3CRC computes CRC-16 with DNP3 polynomial
func calculateDNP3CRC(data []byte) uint16 {
    // DNP3 uses CRC-16 with polynomial 0x3D65
    // Implementation uses lookup table for efficiency
    var crc uint16 = 0x0000
    for _, b := range data {
        index := (crc ^ uint16(b)) & 0xFF
        crc = (crc >> 8) ^ dnp3CRCTable[index]
    }
    return ^crc
}

// parseDeviceRole determines master vs outstation from control byte
func parseDeviceRole(control byte) string {
    dir := (control & DNP3CtlDIR) != 0
    prm := (control & DNP3CtlPRM) != 0

    if dir && prm {
        return "master"
    } else if !dir && !prm {
        return "outstation"
    }
    return "unknown"
}
```

### CRC Lookup Table

```go
// dnp3CRCTable is the precomputed CRC-16 table for polynomial 0x3D65
var dnp3CRCTable = [256]uint16{
    0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
    // ... (full 256-entry table)
}
```

## Test Strategy

### Unit Tests
1. **CRC Calculation** - Verify CRC-16 with known test vectors
2. **Probe Construction** - Verify Request Link Status packet format
3. **Response Parsing** - Verify correct extraction of address/role

### Docker Integration Test
```go
{
    Description: "dnp3",
    Port:        20000,
    Protocol:    plugins.TCP,
    Expected: func(res *plugins.Service) bool {
        return res != nil && res.Protocol == "dnp3"
    },
    RunConfig: dockertest.RunOptions{
        Repository: "automatak/dnp3-outstation",
        // Or alternative: "fossabot/dnp3-outstation"
    },
}
```

### Shodan Live Validation
Test against known DNP3 endpoints found via:
- `port:20000 tag:ics`
- `port:20000 DNP3`

## Safety Requirements (CRITICAL)

1. **Read-Only Probes** - ONLY use Function Code 0x09 (Request Link Status)
2. **No Write Operations** - Never send write/operate function codes
3. **No Control Operations** - Select/Operate (SBO), Direct Operate forbidden
4. **Graceful Timeouts** - Handle slow ICS devices appropriately
5. **No Panic** - Return errors, never panic()

## P0 Compliance Checklist

| Requirement | Implementation |
|-------------|----------------|
| Go Compilation | `go build ./...` passes |
| 5-Method Interface | Name, Type, Priority, PortPriority, Run |
| Type Constant | ProtoDNP3 in types.go |
| Plugin Registration | init() calls RegisterPlugin |
| Unit Tests | dnp3_test.go exists |
| No Panics | Return errors only |

## Dependencies

- `github.com/praetorian-inc/nerva/pkg/plugins`
- `github.com/praetorian-inc/nerva/pkg/plugins/pluginutils`
- `encoding/binary` (for little-endian address parsing)

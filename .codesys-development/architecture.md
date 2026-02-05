# CODESYS Plugin Architecture & Implementation Plan

**Consolidated Planning Output** (Phases 4-7)
**Created:** 2026-02-05T01:23:27Z

---

## Phase 4-5: Skills & Complexity Assessment

### Required Skills

| Skill | Purpose | Location |
|-------|---------|----------|
| `developing-with-tdd` | Write tests first, RED-GREEN-REFACTOR | Core |
| `go-best-practices` | Go idioms, error handling | Library |
| `implementing-golang-tests` | Table-driven tests, mock connections | Library |
| `adhering-to-dry` | Reuse modbus patterns | Core |
| `preferring-simple-solutions` | Avoid over-engineering | Core |

### Complexity Assessment

**Technical Complexity:** MEDIUM
- Multi-protocol detection (V2 LE/BE + V3) adds moderate complexity
- Banner parsing is straightforward (byte offsets)
- Version extraction from structured responses
- Similar to existing modbus plugin pattern

**Implementation Effort:** ~250-350 LOC
- Plugin code: ~150 LOC
- Tests: ~100-200 LOC
- Types.go updates: ~50 LOC

**Execution Strategy:** Sequential TDD
- Write test for V2 LE detection → implement → pass
- Write test for V2 BE detection → implement → pass
- Write test for V3 detection → implement → pass
- Write test for version extraction → implement → pass

---

## Phase 6-7: Architecture & Implementation Plan

### Architecture Design

**Multi-Protocol Fallback Pattern:**

```
Run() → Try V2 Little-Endian
      ↓ (if fail)
      → Try V2 Big-Endian
      ↓ (if fail)
      → Try V3
      ↓ (if fail)
      → Return nil (not CODESYS)
```

**Reusable Components:**
- `utils.SendRecv()` - Timeout handling (from modbus)
- `plugins.CreateServiceFrom()` - Service creation (from all plugins)
- Table-driven tests - Test pattern (from modbus_test.go)

### Implementation Tasks

| Task | Files | Estimated LOC | TDD Cycles |
|------|-------|---------------|------------|
| 1. Add type constants to types.go | `pkg/plugins/types.go` | ~50 | N/A (types only) |
| 2. Implement V2 LE detection | `pkg/plugins/services/codesys/codesys.go` | ~40 | RED-GREEN |
| 3. Implement V2 BE detection | `pkg/plugins/services/codesys/codesys.go` | ~20 | RED-GREEN |
| 4. Implement V3 detection | `pkg/plugins/services/codesys/codesys.go` | ~40 | RED-GREEN |
| 5. Implement version extraction | `pkg/plugins/services/codesys/codesys.go` | ~30 | RED-GREEN |
| 6. Implement PortPriority/Name/Type/Priority methods | `pkg/plugins/services/codesys/codesys.go` | ~20 | N/A (boilerplate) |
| 7. Write unit tests | `pkg/plugins/services/codesys/codesys_test.go` | ~100-200 | Drives implementation |

### File Changes Detail

#### 1. pkg/plugins/types.go

**Add after ProtoCassandra, before ProtoCouchDB:**

```go
ProtoCODESYS = "codesys"
```

**Add Service struct:**

```go
type ServiceCODESYS struct {
    Version     string   `json:"version,omitempty"`
    DeviceName  string   `json:"deviceName,omitempty"`
    VendorName  string   `json:"vendorName,omitempty"`
    OSType      string   `json:"osType,omitempty"`
    OSName      string   `json:"osName,omitempty"`
    AuthEnabled bool     `json:"authEnabled,omitempty"`
    CPEs        []string `json:"cpes,omitempty"`
}

func (e ServiceCODESYS) Type() string { return ProtoCODESYS }
```

**Add switch case in Service.Metadata():**

```go
case ProtoCODESYS:
    var p ServiceCODESYS
```

#### 2. pkg/plugins/services/codesys/codesys.go

**Structure:**

```go
package codesys

import (
    "bytes"
    "encoding/binary"
    "net"
    "time"

    "github.com/praetorian-inc/nerva/pkg/plugins"
    utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
    CODESYS = "codesys"

    // V2 Protocol constants
    V2ResponseSignature = 0xbb
    OSNameOffset        = 65
    OSTypeOffset        = 97
    ProductTypeOffset   = 129

    // V3 Protocol constants
    V3HeaderMagic    = 0xe8170100
    V3ProtocolID     = 0xcd55
    V3ServiceGroup   = 0x01
    V3ServiceID      = 0x04
)

type CODESYSPlugin struct{}

func init() {
    plugins.RegisterPlugin(&CODESYSPlugin{})
}

func (p *CODESYSPlugin) PortPriority(port uint16) bool {
    return port == 2455 || port == 1217 || port == 1200
}

func (p *CODESYSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
    // Try V2 Little-Endian
    if service, err := p.tryV2LittleEndian(conn, timeout, target); service != nil || err != nil {
        return service, err
    }

    // Try V2 Big-Endian
    if service, err := p.tryV2BigEndian(conn, timeout, target); service != nil || err != nil {
        return service, err
    }

    // Try V3
    return p.tryV3(conn, timeout, target)
}

func (p *CODESYSPlugin) tryV2LittleEndian(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
    request := []byte{0xbb, 0xbb, 0x01, 0x00, 0x00, 0x00, 0x01}
    return p.processV2Response(conn, request, timeout, target)
}

func (p *CODESYSPlugin) tryV2BigEndian(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
    request := []byte{0xbb, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x01}
    return p.processV2Response(conn, request, timeout, target)
}

func (p *CODESYSPlugin) processV2Response(conn net.Conn, request []byte, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
    response, err := utils.SendRecv(conn, request, timeout)
    if err != nil || len(response) == 0 {
        return nil, err
    }

    // Validate response starts with 0xbb
    if response[0] != V2ResponseSignature {
        return nil, nil
    }

    // Extract metadata if response is long enough
    serviceData := plugins.ServiceCODESYS{}
    if len(response) > ProductTypeOffset {
        serviceData.OSName = extractNullTerminatedString(response, OSNameOffset)
        serviceData.OSType = extractNullTerminatedString(response, OSTypeOffset)
        // Version may be in Product Type string
        productType := extractNullTerminatedString(response, ProductTypeOffset)
        serviceData.Version = extractVersionFromProduct(productType)
    }

    return plugins.CreateServiceFrom(target, serviceData, false, "", plugins.TCP), nil
}

func (p *CODESYSPlugin) tryV3(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
    // Build V3 request
    headerMagic := make([]byte, 4)
    binary.LittleEndian.PutUint32(headerMagic, V3HeaderMagic)

    payloadLength := make([]byte, 4)
    binary.LittleEndian.PutUint32(payloadLength, 8) // Example payload length

    protocolID := make([]byte, 2)
    binary.LittleEndian.PutUint16(protocolID, V3ProtocolID)

    request := append(headerMagic, payloadLength...)
    request = append(request, protocolID...)
    request = append(request, V3ServiceGroup, V3ServiceID)

    response, err := utils.SendRecv(conn, request, timeout)
    if err != nil || len(response) == 0 {
        return nil, err
    }

    // Validate V3 magic in response
    if len(response) < 4 {
        return nil, nil
    }

    responseMagic := binary.LittleEndian.Uint32(response[:4])
    if responseMagic != V3HeaderMagic {
        return nil, nil
    }

    // Parse V3 response (simplified - actual parsing depends on V3 response structure)
    serviceData := plugins.ServiceCODESYS{
        // Extract node_name, device_name, vendor_name, target_version from response
        // This requires understanding V3 response format from live testing
    }

    return plugins.CreateServiceFrom(target, serviceData, false, "", plugins.TCP), nil
}

func (p *CODESYSPlugin) Name() string {
    return CODESYS
}

func (p *CODESYSPlugin) Type() plugins.Protocol {
    return plugins.TCP
}

func (p *CODESYSPlugin) Priority() int {
    return 400 // ICS protocol priority (same as modbus)
}

// Helper functions
func extractNullTerminatedString(data []byte, offset int) string {
    if offset >= len(data) {
        return ""
    }

    end := offset
    for end < len(data) && data[end] != 0 {
        end++
    }

    return string(data[offset:end])
}

func extractVersionFromProduct(productType string) string {
    // Parse version from product type string (e.g., "CODESYS V2.3.9.60")
    // Implementation depends on actual format from testing
    return ""
}
```

#### 3. pkg/plugins/services/codesys/codesys_test.go

**Table-driven tests:**

```go
package codesys

import (
    "bytes"
    "net"
    "testing"
    "time"

    "github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestCODESYSV2LittleEndian(t *testing.T) {
    tests := []struct {
        name           string
        response       []byte
        expectDetected bool
    }{
        {
            name: "Valid V2 LE response",
            response: buildMockV2Response(),
            expectDetected: true,
        },
        {
            name: "Invalid signature",
            response: []byte{0x00, 0x01, 0x02},
            expectDetected: false,
        },
        {
            name: "Empty response",
            response: []byte{},
            expectDetected: false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            conn := newMockConn(tt.response)
            plugin := &CODESYSPlugin{}

            result, err := plugin.tryV2LittleEndian(conn, 5*time.Second, plugins.Target{})

            if tt.expectDetected && result == nil {
                t.Errorf("Expected detection, got nil")
            }
            if !tt.expectDetected && result != nil {
                t.Errorf("Expected no detection, got result")
            }
        })
    }
}

// Mock connection for testing
type mockConn struct {
    *bytes.Buffer
}

func newMockConn(response []byte) net.Conn {
    return &mockConn{Buffer: bytes.NewBuffer(response)}
}

func (mc *mockConn) Close() error                       { return nil }
func (mc *mockConn) LocalAddr() net.Addr                { return nil }
func (mc *mockConn) RemoteAddr() net.Addr               { return nil }
func (mc *mockConn) SetDeadline(t time.Time) error      { return nil }
func (mc *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (mc *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func buildMockV2Response() []byte {
    response := make([]byte, 150)
    response[0] = 0xbb // Valid signature

    // Add mock OS name, OS type, product type at expected offsets
    copy(response[OSNameOffset:], "Windows\x00")
    copy(response[OSTypeOffset:], "NT\x00")
    copy(response[ProductTypeOffset:], "CODESYS V2.3\x00")

    return response
}
```

---

## Implementation Order (TDD)

### Cycle 1: Types Registration
1. Add ProtoCODESYS constant to types.go
2. Add ServiceCODESYS struct
3. Add Type() method
4. Add switch case in Metadata()
5. Verify `go build` passes

### Cycle 2: V2 Little-Endian Detection
1. Write test: `TestCODESYSV2LittleEndian_ValidResponse`
2. Run test → RED (function doesn't exist)
3. Implement `tryV2LittleEndian()` with minimal logic
4. Run test → GREEN
5. Refactor if needed

### Cycle 3: V2 Big-Endian Detection
1. Write test: `TestCODESYSV2BigEndian_ValidResponse`
2. Run test → RED
3. Implement `tryV2BigEndian()` reusing `processV2Response()`
4. Run test → GREEN

### Cycle 4: V3 Detection
1. Write test: `TestCODESYSV3_ValidResponse`
2. Run test → RED
3. Implement `tryV3()` with V3 header parsing
4. Run test → GREEN

### Cycle 5: Integration
1. Write test: `TestCODESYSPlugin_Run_Fallback`
2. Test fallback logic (V2 LE → V2 BE → V3)
3. Implement main `Run()` method coordinating all attempts
4. Run test → GREEN

---

## Verification Checklist

Before marking implementation complete:

- [ ] All TDD cycles completed (RED-GREEN-REFACTOR)
- [ ] `go build ./...` passes
- [ ] `go test ./pkg/plugins/services/codesys` passes
- [ ] ProtoCODESYS added to types.go (alphabetically)
- [ ] ServiceCODESYS struct added with all fields
- [ ] Type() method implemented
- [ ] Switch case added to Service.Metadata()
- [ ] Priority() returns 400 (ICS protocol)
- [ ] PortPriority() checks 2455, 1217, 1200
- [ ] Multi-protocol fallback logic working
- [ ] Mock tests cover valid/invalid/malformed responses

---

## Known Limitations & Future Work

**Limitations in initial implementation:**
- V3 response parsing simplified (requires live Shodan testing to validate format)
- Version extraction from V2 Product Type string needs real examples
- Authentication detection placeholder (needs auth challenge testing)

**Phase 13 (Testing) will address:**
- Live Shodan validation with real CODESYS hosts
- V3 response format verification
- Version extraction accuracy testing
- Authentication state detection

---

## Exit Criteria

Implementation is complete when:
1. All files created/modified as specified
2. All TDD cycles completed with passing tests
3. `go build` and `go test` both pass
4. Code follows modbus plugin pattern
5. ICS safety requirements documented in comments
6. Ready for Phase 11 (Code Quality Review)


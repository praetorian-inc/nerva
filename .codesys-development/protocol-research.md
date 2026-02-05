# Protocol Research: CODESYS

**Research Date:** 2026-02-05
**Protocol Type:** TCP (multiple versions)
**Source Type:** Open-source (CODESYS runtime)

---

## Service Identification

**Protocol Name:** CODESYS (Controller Development System)
**Default Ports:**
- **2455** - Primary CODESYS V2/V3 port
- **1217** - Older CODESYS Gateway port
- **1200** - Legacy CODESYS port
- **11740** - CODESYS V3 specific port

**Protocol Type:** TCP
**Banner Available:** Yes (protocol-specific handshakes)
**Industry:** ICS/SCADA (Programmable Logic Controller programming interface)

---

## Detection Strategy

### Multi-Version Approach

CODESYS has evolved through V2 and V3 protocols with different handshake mechanisms. Detection requires attempting both:

```
1. Try CODESYS V2 Little-Endian handshake
2. If no response, try V2 Big-Endian handshake
3. If still no response, try V3 handshake
4. Return on first successful detection
```

This ensures maximum compatibility across CODESYS versions and endianness configurations.

---

## CODESYS V2 Protocol Detection

### Banner Pattern

**Request (Little-Endian):**
```
Hex: \xbb\xbb\x01\x00\x00\x00\x01
Length: 7 bytes
```

**Request (Big-Endian):**
```
Hex: \xbb\xbb\x01\x00\x00\x01\x01
Length: 7 bytes
```

**Valid Response:**
- **Starts with:** `0xbb` (byte 0)
- **Contains:** Null-terminated strings at fixed offsets
- **Metadata locations:**
  - OS Name: byte offset 65
  - OS Type: byte offset 97
  - Product Type: byte offset 129

**Example Response Structure:**
```
[0xbb] [header bytes...] [null-terminated OS name @ offset 65]
[null-terminated OS type @ offset 97] [null-terminated product @ offset 129]
```

### Detection Markers

| Marker | Location | Type | Confidence |
|--------|----------|------|------------|
| `0xbb` | Byte 0 | Response signature | High |
| Little/Big endian success | Request format | Endianness detection | High |
| Null-terminated strings | Offsets 65, 97, 129 | Metadata format | High |

### Version Extraction (V2)

- **Runtime version:** Embedded in response structure (exact offset TBD from live testing)
- **Product Type:** String at offset 129 may contain version info (e.g., "CODESYS V2.3")
- **OS information:** Provides context for runtime environment

---

## CODESYS V3 Protocol Detection

### Banner Pattern

**TCP Header:**
```
Magic: 0xe8170100 (4 bytes, little-endian)
Length: 4 bytes (payload length)
```

**Services Layer:**
```
Protocol ID: 0xcd55 (unencrypted services)
Service Group: 0x01 (device info)
Service ID: 0x04 (get device info)
```

**Request Structure:**
```
[0xe8 0x17 0x01 0x00] [length: 4 bytes] [protocol_id: 0xcd55]
[service_group: 0x01] [service_id: 0x04] [request payload]
```

**Response Structure:**
```
[TCP header magic] [length] [protocol_id] [response payload containing:]
- node_name (string)
- device_name (string)
- vendor_name (string)
- target_version (string, format: major.minor.patch.build)
```

### Detection Markers

| Marker | Location | Type | Confidence |
|--------|----------|------|------------|
| `0xe8170100` | Bytes 0-3 | TCP header magic | High |
| `0xcd55` | Protocol ID | Unencrypted services layer | High |
| Service response | Variable offset | Device info structure | Medium |

### Version Extraction (V3)

- **target_version field:** Direct version string in device info response
- **Format:** `{major}.{minor}.{patch}.{build}` (e.g., "3.5.16.0")
- **Additional metadata:** node_name, device_name, vendor_name for enriched fingerprinting

---

## Error Handling

### Expected Error Conditions

| Error Condition | Protocol Response | Plugin Action |
|-----------------|-------------------|---------------|
| **Connection refused** | TCP RST | Return `nil, nil` (not CODESYS) |
| **Connection timeout** | No response | Return `nil, timeout error` |
| **Malformed response** | Invalid magic/signature | Try next protocol version |
| **Empty response** | Zero bytes received | Return `nil, nil` |
| **Authentication required** | Auth challenge | Set `AuthEnabled: true`, return partial detection |

### Fallback Logic

```
V2 Little-Endian → No Response → V2 Big-Endian
                                      ↓
                                 No Response → V3
                                                ↓
                                           No Response → Not CODESYS
```

---

## Authentication Detection

CODESYS may require authentication before providing full device information:

**Indicators of authentication:**
- V2: Specific error codes in response
- V3: Auth challenge in service layer

**Plugin behavior:**
- Set `AuthEnabled: true` in ServiceCODESYS
- Return successful detection even if auth required
- Document auth state for security assessment

---

## Version Distinguishing

### Distinguishable Version Ranges

| Version Range | Detection Method | Marker | Confidence |
|--------------|------------------|--------|------------|
| **V2.x (any)** | V2 handshake success | `0xbb` response | High |
| **V3.x (any)** | V3 handshake success | `0xe8170100` header | High |
| **V2.3.x** | Product Type string parsing | "V2.3" in string | Medium |
| **V3.5.x** | target_version field | "3.5.x.x" | High |

### CPE Generation

**Format:** `cpe:2.3:a:codesys:codesys:{version}:*:*:*:*:*:*:*`

**Examples:**
- V2.3.9.60: `cpe:2.3:a:codesys:codesys:2.3.9.60:*:*:*:*:*:*:*`
- V3.5.16.0: `cpe:2.3:a:codesys:codesys:3.5.16.0:*:*:*:*:*:*:*`
- Unknown version: `cpe:2.3:a:codesys:codesys:*:*:*:*:*:*:*:*`

---

## Shodan Queries

### Primary Queries

| Query | Purpose | Estimated Count |
|-------|---------|----------------|
| `port:2455` | Find devices on primary CODESYS port | ~10,000-15,000 |
| `codesys` | General CODESYS keyword search | ~15,000-20,000 |
| `port:1217` | Older CODESYS Gateway port | ~1,000-2,000 |
| `port:2455 "codesys"` | Confirmed CODESYS banner | ~8,000-12,000 |

### Validation Queries

| Query | Purpose | Use Case |
|-------|---------|----------|
| `port:2455 "3.5"` | V3.5.x specific | Version validation |
| `port:2455 "V2"` | V2.x specific | Legacy version validation |
| `port:11740` | V3 dedicated port | V3-only hosts |

### Geographic Distribution

CODESYS is used globally in industrial automation:
- **Europe:** High concentration (Germany, Netherlands, UK)
- **North America:** Medium concentration (manufacturing facilities)
- **Asia:** Growing adoption (China, Japan, South Korea)

---

## Test Vectors

### Planned Test Sources

**Phase 13 (Testing) will gather real-world examples from:**

1. **Shodan API:** Live device banners (3+ examples)
2. **Docker containers:** Local test environments (if available)
3. **Public test instances:** Known CODESYS test servers (if available)

**Expected Test Vector Format:**

| Host | Port | Version | Response Type | Banner Snippet |
|------|------|---------|---------------|----------------|
| [Shodan result] | 2455 | V3.5.16.0 | V3 | `0xe8170100...{target_version: "3.5.16.0"}` |
| [Shodan result] | 2455 | V2.3.x | V2 (LE) | `0xbb...{Product: "CODESYS V2.3"}` |
| [Shodan result] | 1217 | V2.x | V2 (BE) | `0xbb...{OS: "Windows"}` |

---

## Security Considerations

### ICS/SCADA Safety Requirements

**CRITICAL:** CODESYS controls industrial processes. Plugin MUST:

1. **Read-only detection** - No write operations to PLC memory
2. **Non-disruptive probes** - Use device info queries only
3. **Graceful error handling** - Connection issues must not crash
4. **Timeout enforcement** - Avoid hanging on unresponsive devices
5. **No control operations** - Never attempt to read/write process variables

### Exposed CODESYS Risks

Publicly exposed CODESYS interfaces represent significant security risks:

- **Unauthorized PLC access:** Direct control of industrial processes
- **Process manipulation:** Ability to alter production parameters
- **Safety system bypass:** Circumvent safety interlocks
- **Intellectual property theft:** PLC program logic extraction

**Detection Purpose:** Identify exposed interfaces for remediation, not exploitation.

---

## Source Repository

**CODESYS Runtime:** Open-source (community edition) and commercial versions

**References:**
- Official: https://www.codesys.com/
- Documentation: CODESYS V2/V3 protocol specifications
- Community: Various open-source CODESYS implementations

---

## Research Validation

### Validation Methods

**Phase 13 (Testing) will validate detection via:**

1. **Live Shodan testing** - At least 3 real-world hosts
2. **Version diversity** - Cover V2 and V3 protocols
3. **Endianness testing** - Test both little-endian and big-endian V2
4. **Error case validation** - Non-CODESYS hosts return nil

**Success Criteria:**
- ≥90% detection accuracy on Shodan samples
- No false positives on non-CODESYS TCP services
- Version extraction successful for ≥70% of detections

---

## Next Steps

This protocol research provides the foundation for:

1. **Phase 7: Architecture Plan** - Design plugin implementation
2. **Phase 8: Implementation** - Code CODESYS detection logic
3. **Phase 13: Testing** - Validate against live Shodan samples

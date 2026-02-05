# DNP3 Protocol Research

## Protocol Overview

**DNP3 (Distributed Network Protocol version 3)** is the primary protocol for SCADA systems in North American power grids. It enables communication between control systems (master stations) and remote field devices (RTUs, IEDs).

**Default Port**: 20000 (IANA registered)

## Frame Structure (FT3 Format)

DNP3 uses the FT3 frame format adapted from IEC 870-5-1:

```
+--------+--------+--------+---------+-------------+-------------+------------+
| Start  | Start  | Length | Control | Destination | Source      | Header CRC |
| 0x05   | 0x64   | 1 byte | 1 byte  | 2 bytes LE  | 2 bytes LE  | 2 bytes    |
+--------+--------+--------+---------+-------------+-------------+------------+
|                             User Data (up to 250 bytes)                      |
|                     (16-byte blocks, each with 2-byte CRC)                   |
+------------------------------------------------------------------------------+
```

**Total header size**: 10 bytes (before user data)
**Maximum frame size**: 292 bytes

## Magic Bytes (Detection Signature)

**`0x0564`** - Every DNP3 data link frame begins with these two bytes.

This provides immediate protocol recognition - if response starts with 0x05 0x64, it's DNP3.

## Control Byte Structure

```
Bit 7 (0x80): DIR - Direction
              1 = From master station
              0 = From outstation

Bit 6 (0x40): PRM - Primary message
              1 = Primary station message
              0 = Secondary station message

Bit 5 (0x20): FCB - Frame Count Bit
              Toggles to detect lost/duplicate frames

Bit 4 (0x10): FCV - Frame Count Valid
              1 = FCB is meaningful
              0 = FCB should be ignored

Bits 3-0 (0x0F): Function Code
```

## Function Codes (Data Link Layer)

### Primary Station (PRM=1) Function Codes:
| Code | Name | Safe? |
|------|------|-------|
| 0x00 | Reset Link State | Caution |
| 0x01 | Reset User Process | **UNSAFE** |
| 0x02 | Test Link State | Safe |
| 0x03 | Confirmed User Data | **UNSAFE** |
| 0x04 | Unconfirmed User Data | **UNSAFE** |
| 0x09 | **Request Link Status** | **SAFE** |

### Secondary Station (PRM=0) Function Codes:
| Code | Name |
|------|------|
| 0x00 | ACK |
| 0x01 | NACK |
| 0x0B | Link Status Response |

## Safe Detection Strategy

**Use Function Code 0x09 (Request Link Status)** - This is a passive diagnostic query that:
- Only asks for link status
- Does NOT modify any data
- Does NOT trigger control operations
- Safe for ICS/SCADA environments

### Detection Probe Packet

```go
// Request Link Status frame
probe := []byte{
    0x05, 0x64,       // Start bytes (magic)
    0x05,             // Length (5 bytes follow before CRC)
    0x49,             // Control: DIR=0, PRM=1, FCV=0, FCB=0, Func=0x09
    0x00, 0x00,       // Destination address (0 = broadcast to all outstations)
    0x01, 0x00,       // Source address (1 = our "master" address)
    // CRC calculated for header
}
```

Control byte breakdown: `0x49 = 0100 1001`
- DIR=0 (to device)
- PRM=1 (we are primary)
- FCV=0 (no frame count validation)
- FCB=0 (unused)
- Function=0x09 (Request Link Status)

### Expected Response

Valid DNP3 device should respond with:
- Start bytes: 0x05 0x64
- Control byte with PRM=0 and function 0x00 (ACK) or 0x0B (Link Status)

## CRC-16 Calculation

DNP3 uses CRC-16 with polynomial 0x3D65 (bit-reversed: 0xA6BC).

Both header (10 bytes) and each 16-byte data block have their own CRC.

## Address Space

- **Destination/Source**: 16-bit (0-65535)
- **Broadcast address**: 0xFFFF (65535)
- Addresses are little-endian in wire format

## Device Role Detection

| Control Byte | Role |
|--------------|------|
| DIR=1, PRM=1 | Master station |
| DIR=0, PRM=0 | Outstation response |
| DIR=0, PRM=1 | Master to outstation |
| DIR=1, PRM=0 | Outstation to master |

## Shodan Test Vectors

1. `port:20000` - Default DNP3 port
2. `port:20000 DNP3` - Explicit protocol search
3. `tag:ics DNP3` - ICS-tagged DNP3 devices

## Version Detection

DNP3 itself doesn't have version negotiation in the data link layer. Version information may be available via:
- Application layer "Device Attributes" object (Group 0)
- Vendor-specific identification

For basic fingerprinting, detecting protocol presence is sufficient.

## CPE Format

When vendor can be identified:
```
cpe:2.3:a:{vendor}:dnp3:{version}:*:*:*:*:*:*:*
```

Generic detection (vendor unknown):
```
cpe:2.3:a:*:dnp3:*:*:*:*:*:*:*:*
```

## Security Considerations

1. **Read-Only Operations Only** - NEVER use write/operate function codes
2. **No Control Commands** - Select/Operate (SBO) and Direct Operate are forbidden
3. **Safe Diagnostic Only** - Use Request Link Status (0x09) or Test Link State (0x02)
4. **Timeout Handling** - ICS devices may be slow; use appropriate timeouts

## References

- [DNP3 Wikipedia](https://en.wikipedia.org/wiki/DNP3)
- [DNP3 Message Structure Explained](https://scadaprotocols.com/dnp3-message-structure-explained/)
- [DNP3 Port 20000 Explained](https://scadaprotocols.com/dnp3-port-20000/)
- [ICS Security Tools Protocols](https://github.com/ITI/ICS-Security-Tools/blob/master/protocols/README.md)
- [Cisco DNP3 Inspector Reference](https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/snort3-inspectors/snort-3-inspector-reference/dnp3-inspector.html)
- [CISA AA22-103A Advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-103a)

// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bacnet

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	bacnetPort     = 47808
	bacnetPriority = 400 // ICS protocol tier (same as DNP3, Modbus)
)

// Plugin implements BACnet/IP service fingerprinting.
type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// Type returns the protocol transport type.
func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

// Priority returns the scan priority (1000 = ICS protocol tier).
func (p *Plugin) Priority() int {
	return bacnetPriority
}

// PortPriority returns true if the port matches BACnet/IP (47808).
func (p *Plugin) PortPriority(port uint16) bool {
	return port == bacnetPort
}

// Name returns the plugin display name.
func (p *Plugin) Name() string {
	return "bacnet"
}

// Run performs BACnet device fingerprinting.
func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Send Who-Is broadcast (8 bytes)
	// BVLC Type=0x81, Function=0x0A (Original-Unicast-NPDU), Length=0x0008
	// NPDU Version=0x01, Control=0x04 (expecting reply, no DNET/SNET), no DNET/DLEN/Hop
	// APDU Type=0x10 (Unconfirmed-Request), Service=0x08 (Who-Is)
	whoIs := []byte{
		0x81, 0x0A, 0x00, 0x08, // BVLC: Type, Function, Length
		0x01, 0x04,             // NPDU: Version, Control
		0x10, 0x08,             // APDU: Type, Service (Who-Is)
	}

	// Send and receive using utility function
	response, err := utils.SendRecv(conn, whoIs, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Parse I-Am response
	service, err := parseIAm(response, target)
	if err != nil {
		return nil, err
	}

	return service, nil
}

// sanitizeString filters a string to contain only printable ASCII characters (0x20-0x7E).
func sanitizeString(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c <= 0x7E {
			result = append(result, c)
		}
	}
	return string(result)
}

// parseIAm parses a BACnet I-Am response and extracts device information.
func parseIAm(data []byte, target plugins.Target) (*plugins.Service, error) {
	// Minimum I-Am response: 4 (BVLC) + 2 (NPDU) + 19 (APDU with required fields) = 25 bytes
	if len(data) < 25 {
		return nil, fmt.Errorf("response too short: %d bytes (minimum 25)", len(data))
	}

	// Validate BVLC header
	if data[0] != 0x81 {
		return nil, fmt.Errorf("invalid BVLC type: 0x%02x (expected 0x81)", data[0])
	}
	if data[1] != 0x0A && data[1] != 0x0B {
		return nil, fmt.Errorf("invalid BVLC function: 0x%02x (expected 0x0A or 0x0B)", data[1])
	}
	bvlcLen := binary.BigEndian.Uint16(data[2:4])
	if int(bvlcLen) != len(data) {
		return nil, fmt.Errorf("BVLC length mismatch: %d != %d", bvlcLen, len(data))
	}

	// Validate NPDU
	if data[4] != 0x01 {
		return nil, fmt.Errorf("invalid NPDU version: 0x%02x (expected 0x01)", data[4])
	}

	// Parse NPDU control byte to find APDU offset
	control := data[5]
	offset := 6

	// Skip DNET, DLEN, DADR if present (bit 5 = destination specifier)
	if control&0x20 != 0 {
		if len(data) < offset+3 {
			return nil, fmt.Errorf("truncated NPDU destination address")
		}
		dlen := int(data[offset+2])
		offset += 3 + dlen
	}

	// Skip SNET, SLEN, SADR if present (bit 3 = source specifier)
	if control&0x08 != 0 {
		if len(data) < offset+3 {
			return nil, fmt.Errorf("truncated NPDU source address")
		}
		slen := int(data[offset+2])
		offset += 3 + slen
	}

	// Skip hop count if destination specified
	if control&0x20 != 0 {
		offset++
	}

	// Validate APDU
	if len(data) < offset+2 {
		return nil, fmt.Errorf("truncated APDU header")
	}
	if data[offset] != 0x10 {
		return nil, fmt.Errorf("invalid APDU type: 0x%02x (expected 0x10 Unconfirmed-Request)", data[offset])
	}
	if data[offset+1] != 0x00 {
		return nil, fmt.Errorf("invalid APDU service: 0x%02x (expected 0x00 I-Am)", data[offset+1])
	}
	offset += 2

	// Parse required I-Am fields
	if len(data) < offset+13 {
		return nil, fmt.Errorf("truncated I-Am fields (need 13 bytes minimum)")
	}

	// Object Identifier [0]: Tag 0xC4 (context 0, application tag 4=object-id, length 4)
	if data[offset] != 0xC4 {
		return nil, fmt.Errorf("invalid I-Am object-id tag: 0x%02x", data[offset])
	}
	deviceInstance := binary.BigEndian.Uint32(data[offset+1:offset+5]) & 0x3FFFFF // Lower 22 bits
	offset += 5

	// Max APDU Length [1]: Tag 0x21 (context 1, application tag 1=unsigned, length 1)
	if data[offset] != 0x21 && data[offset] != 0x22 {
		return nil, fmt.Errorf("invalid I-Am max-apdu tag: 0x%02x", data[offset])
	}
	maxAPDU := uint16(0)
	if data[offset] == 0x21 {
		maxAPDU = uint16(data[offset+1])
		offset += 2
	} else {
		if len(data) < offset+3 {
			return nil, fmt.Errorf("truncated max-apdu field")
		}
		maxAPDU = binary.BigEndian.Uint16(data[offset+1 : offset+3])
		offset += 3
	}

	// Segmentation [2]: Tag 0x91 (context 2, application tag 9=enumerated, length 1)
	if data[offset] != 0x91 {
		return nil, fmt.Errorf("invalid I-Am segmentation tag: 0x%02x", data[offset])
	}
	segValue := data[offset+1]
	segmentation := ""
	switch segValue {
	case 0:
		segmentation = "both"
	case 1:
		segmentation = "transmit"
	case 2:
		segmentation = "receive"
	case 3:
		segmentation = "none"
	default:
		segmentation = fmt.Sprintf("unknown(%d)", segValue)
	}
	offset += 2

	// Vendor ID [3]: Tag 0x21 or 0x22 (context 3, application tag 1=unsigned)
	if data[offset] != 0x21 && data[offset] != 0x22 {
		return nil, fmt.Errorf("invalid I-Am vendor-id tag: 0x%02x", data[offset])
	}
	vendorID := uint16(0)
	if data[offset] == 0x21 {
		vendorID = uint16(data[offset+1])
		offset += 2
	} else {
		if len(data) < offset+3 {
			return nil, fmt.Errorf("truncated vendor-id field")
		}
		vendorID = binary.BigEndian.Uint16(data[offset+1 : offset+3])
		offset += 3
	}

	// Optional fields: model name (tag 0x75), firmware revision (tag 0x2C or 0x75)
	modelName := ""
	firmwareRev := ""

	// Parse optional properties if present
	for offset < len(data) {
		tag := data[offset]
		if tag == 0x75 { // Character string
			if len(data) < offset+2 {
				break
			}
			strLen := int(data[offset+1])
			if len(data) < offset+2+1+strLen { // +1 for encoding byte
				break
			}
			// encoding := data[offset+2] // 0x00 = ANSI X3.4, 0x08 = UCS-2, etc.
			strData := data[offset+3 : offset+3+strLen]

			// Heuristic: if this looks like a version (digits/dots), it's firmware
			if len(modelName) == 0 {
				modelName = string(strData)
			} else if len(firmwareRev) == 0 {
				firmwareRev = string(strData)
			}
			offset += 3 + strLen
		} else if tag == 0x2C { // Unsigned (often used for firmware)
			if len(data) < offset+2 {
				break
			}
			// Could parse as version number, but we'll skip for simplicity
			offset += 2
		} else {
			// Unknown tag, stop parsing
			break
		}
	}

	// Build ServiceBACnet
	vendorName := getVendorName(vendorID)
	// Sanitize extracted strings to printable ASCII
	modelName = sanitizeString(modelName)
	firmwareRev = sanitizeString(firmwareRev)
	cpes := generateCPE(vendorID, modelName, firmwareRev)

	metadata := plugins.ServiceBACnet{
		DeviceInstance: deviceInstance,
		VendorID:       vendorID,
		VendorName:     vendorName,
		MaxAPDU:        maxAPDU,
		Segmentation:   segmentation,
		ModelName:      modelName,
		FirmwareRev:    firmwareRev,
		CPEs:           cpes,
	}

	return plugins.CreateServiceFrom(target, metadata, false, "", plugins.UDP), nil
}

// generateCPE creates CPE 2.3 strings for BACnet hardware.
func generateCPE(vendorID uint16, modelName, firmwareRev string) []string {
	vendorSlug := getVendorSlug(vendorID)
	if vendorSlug == "*" {
		return nil // Unknown vendor, no CPE
	}

	// Normalize model name for CPE (lowercase, replace spaces/special chars with underscores)
	modelSlug := "*"
	if modelName != "" {
		modelSlug = normalizeCPE(modelName)
	}

	// Normalize firmware revision
	firmwareSlug := "*"
	if firmwareRev != "" {
		firmwareSlug = normalizeCPE(firmwareRev)
	}

	cpe := fmt.Sprintf("cpe:2.3:h:%s:%s:%s:*:*:*:*:*:*:*", vendorSlug, modelSlug, firmwareSlug)
	return []string{cpe}
}

// normalizeCPE converts a string to CPE-safe format (lowercase, alphanumeric + underscores).
func normalizeCPE(s string) string {
	result := ""
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			if r >= 'A' && r <= 'Z' {
				result += string(r + 32) // Convert to lowercase
			} else {
				result += string(r)
			}
		} else if r == ' ' || r == '-' || r == '.' {
			result += "_"
		}
		// Skip other special characters
	}
	if result == "" {
		return "*"
	}
	return result
}

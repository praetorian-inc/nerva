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
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	bacnetPort     = 47808
	bacnetPriority = 400 // ICS protocol tier (same as DNP3, Modbus)

	// BACnet property identifiers for ReadProperty requests
	propModelName        = 0x46 // 70 - Model-Name
	propFirmwareRevision = 0x2C // 44 - Firmware-Revision

	// ReadProperty service code
	serviceReadProperty = 0x0C
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
	// NPDU Version=0x01, Control=0x00 (no special options, standard for Who-Is), no DNET/DLEN/Hop
	// APDU Type=0x10 (Unconfirmed-Request), Service=0x08 (Who-Is)
	whoIs := []byte{
		0x81, 0x0A, 0x00, 0x08, // BVLC: Type, Function, Length
		0x01, 0x00,             // NPDU: Version, Control
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
	service, deviceInstance, err := parseIAmWithInstance(response, target)
	if err != nil {
		return nil, err
	}

	// Enrich with ReadProperty requests for Model-Name and Firmware-Revision
	if service != nil && deviceInstance > 0 {
		enrichedModel, enrichedFirmware := enrichWithReadProperty(conn, timeout, deviceInstance)

		// Update metadata if we got better values from ReadProperty
		if enrichedModel != "" || enrichedFirmware != "" {
			// Unmarshal existing metadata
			var metadata plugins.ServiceBACnet
			if err := json.Unmarshal(service.Raw, &metadata); err == nil {
				// Update with enriched values if current values are empty
				if enrichedModel != "" && metadata.ModelName == "" {
					metadata.ModelName = enrichedModel
				}
				if enrichedFirmware != "" && metadata.FirmwareRev == "" {
					metadata.FirmwareRev = enrichedFirmware
				}
				// Regenerate CPE with new values
				metadata.CPEs = generateCPE(metadata.VendorID, metadata.ModelName, metadata.FirmwareRev)

				// Create new service with updated metadata
				service = plugins.CreateServiceFrom(target, metadata, false, "", plugins.UDP)
			}
		}
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

// buildReadPropertyRequest creates a BACnet ReadProperty request for a device property.
func buildReadPropertyRequest(deviceInstance uint32, propertyID byte, invokeID byte) []byte {
	// Encode object ID: Device type (8) in upper 10 bits, instance in lower 22 bits
	objectID := (uint32(8) << 22) | (deviceInstance & 0x3FFFFF)

	return []byte{
		0x81, 0x0A, 0x00, 0x11,   // BVLC: Type, Function, Length=17
		0x01, 0x04,               // NPDU: Version, Control (expecting reply)
		0x00, 0x05, invokeID,     // APDU: Confirmed-REQ, Max APDU=1476, Invoke ID
		serviceReadProperty,      // Service: ReadProperty (0x0C)
		0x0C,                     // Context tag 0, length 4 (Object ID)
		byte(objectID >> 24),     // Object ID byte 0
		byte(objectID >> 16),     // Object ID byte 1
		byte(objectID >> 8),      // Object ID byte 2
		byte(objectID),           // Object ID byte 3
		0x19,                     // Context tag 1, length 1 (Property ID)
		propertyID,               // Property identifier
	}
}

// parseReadPropertyAck extracts a string value from a ReadProperty-ACK response.
// Returns empty string if parsing fails or property value is not a string.
func parseReadPropertyAck(data []byte) string {
	// Minimum: BVLC(4) + NPDU(2) + APDU header(3) + some data
	if len(data) < 12 {
		return ""
	}

	// Validate BVLC
	if data[0] != 0x81 {
		return ""
	}

	// Find APDU offset (skip NPDU like in parseIAm)
	if data[4] != 0x01 {
		return ""
	}
	control := data[5]
	offset := 6

	// Skip DNET/DLEN/DADR if present
	if control&0x20 != 0 {
		if len(data) < offset+3 {
			return ""
		}
		dlen := int(data[offset+2])
		offset += 3 + dlen
	}

	// Skip SNET/SLEN/SADR if present
	if control&0x08 != 0 {
		if len(data) < offset+3 {
			return ""
		}
		slen := int(data[offset+2])
		offset += 3 + slen
	}

	// Skip hop count if destination specified
	if control&0x20 != 0 {
		offset++
	}

	if len(data) < offset+3 {
		return ""
	}

	// Check for Complex-ACK (0x30) or error (0x50)
	apduType := data[offset] & 0xF0
	if apduType == 0x50 {
		// Error response - property not supported, but device is BACnet
		return ""
	}
	if apduType != 0x30 {
		// Not a Complex-ACK
		return ""
	}

	// Skip APDU header: type(1) + invokeID(1) + service(1)
	offset += 3

	// Skip echoed object ID (context tag 0) and property ID (context tag 1)
	// Look for opening tag 3 (0x3E) which contains the property value
	for offset < len(data)-1 {
		if data[offset] == 0x3E {
			// Found opening tag 3 - property value follows
			offset++
			break
		}
		offset++
	}

	if offset >= len(data)-2 {
		return ""
	}

	// Look for character string tag (0x75 or application tag 7)
	tag := data[offset]
	if tag == 0x75 || (tag&0xF0) == 0x70 {
		// Character string
		offset++
		if offset >= len(data) {
			return ""
		}

		// Get length
		strLen := int(data[offset])
		offset++

		// Extended length encoding
		if strLen == 0xFE && offset+1 < len(data) {
			strLen = int(data[offset])<<8 | int(data[offset+1])
			offset += 2
		}

		if offset >= len(data) || strLen <= 0 {
			return ""
		}

		// Skip encoding byte (usually 0x00 for ANSI)
		if offset < len(data) {
			offset++
			strLen--
		}

		if strLen <= 0 || offset+strLen > len(data) {
			return ""
		}

		return sanitizeString(string(data[offset : offset+strLen]))
	}

	return ""
}

// enrichWithReadProperty queries a BACnet device for Model-Name and Firmware-Revision.
// Returns the values found, or empty strings if properties are not supported.
func enrichWithReadProperty(conn net.Conn, timeout time.Duration, deviceInstance uint32) (modelName, firmwareRev string) {
	// Query Model-Name (property 0x46)
	modelReq := buildReadPropertyRequest(deviceInstance, propModelName, 0x01)
	modelResp, err := utils.SendRecv(conn, modelReq, timeout)
	if err == nil && len(modelResp) > 0 {
		modelName = parseReadPropertyAck(modelResp)
	}

	// Query Firmware-Revision (property 0x2C)
	fwReq := buildReadPropertyRequest(deviceInstance, propFirmwareRevision, 0x02)
	fwResp, err := utils.SendRecv(conn, fwReq, timeout)
	if err == nil && len(fwResp) > 0 {
		firmwareRev = parseReadPropertyAck(fwResp)
	}

	return modelName, firmwareRev
}

// parseIAmWithInstance parses a BACnet I-Am response and extracts device information.
// Returns the service, device instance number, and any error.
func parseIAmWithInstance(data []byte, target plugins.Target) (*plugins.Service, uint32, error) {
	// Minimum to reach APDU header: 4 (BVLC) + 2 (NPDU minimum) + 2 (APDU header) = 8 bytes
	// We use 12 as a reasonable minimum before field-specific validation
	// (allows parsing through APDU type/service checks, then field-by-field bounds checks)
	if len(data) < 12 {
		return nil, 0, fmt.Errorf("response too short: %d bytes (minimum 12)", len(data))
	}

	// Validate BVLC header
	if data[0] != 0x81 {
		return nil, 0, fmt.Errorf("invalid BVLC type: 0x%02x (expected 0x81)", data[0])
	}
	if data[1] != 0x0A && data[1] != 0x0B {
		return nil, 0, fmt.Errorf("invalid BVLC function: 0x%02x (expected 0x0A or 0x0B)", data[1])
	}
	bvlcLen := binary.BigEndian.Uint16(data[2:4])
	if int(bvlcLen) != len(data) {
		return nil, 0, fmt.Errorf("BVLC length mismatch: %d != %d", bvlcLen, len(data))
	}

	// Validate NPDU
	if data[4] != 0x01 {
		return nil, 0, fmt.Errorf("invalid NPDU version: 0x%02x (expected 0x01)", data[4])
	}

	// Parse NPDU control byte to find APDU offset
	control := data[5]
	offset := 6

	// Skip DNET, DLEN, DADR if present (bit 5 = destination specifier)
	if control&0x20 != 0 {
		if len(data) < offset+3 {
			return nil, 0, fmt.Errorf("truncated NPDU destination address")
		}
		dlen := int(data[offset+2])
		offset += 3 + dlen
	}

	// Skip SNET, SLEN, SADR if present (bit 3 = source specifier)
	if control&0x08 != 0 {
		if len(data) < offset+3 {
			return nil, 0, fmt.Errorf("truncated NPDU source address")
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
		return nil, 0, fmt.Errorf("truncated APDU header")
	}
	if data[offset] != 0x10 {
		return nil, 0, fmt.Errorf("invalid APDU type: 0x%02x (expected 0x10 Unconfirmed-Request)", data[offset])
	}
	if data[offset+1] != 0x00 {
		return nil, 0, fmt.Errorf("invalid APDU service: 0x%02x (expected 0x00 I-Am)", data[offset+1])
	}
	offset += 2

	// Parse required I-Am fields (minimum sizes for all required fields)
	// Object ID: 5 bytes, Max APDU: 2 bytes min, Segmentation: 2 bytes, Vendor ID: 2 bytes min = 11 bytes
	if len(data) < offset+11 {
		return nil, 0, fmt.Errorf("truncated I-Am fields (need 11 bytes minimum)")
	}

	// Object Identifier [0]: Tag 0xC4 (context 0, application tag 4=object-id, length 4)
	if data[offset] != 0xC4 {
		return nil, 0, fmt.Errorf("invalid I-Am object-id tag: 0x%02x", data[offset])
	}
	deviceInstance := binary.BigEndian.Uint32(data[offset+1:offset+5]) & 0x3FFFFF // Lower 22 bits
	offset += 5

	// Max APDU Length [1]: Tag 0x21 (context 1, application tag 1=unsigned, length 1)
	if data[offset] != 0x21 && data[offset] != 0x22 {
		return nil, 0, fmt.Errorf("invalid I-Am max-apdu tag: 0x%02x", data[offset])
	}
	maxAPDU := uint16(0)
	if data[offset] == 0x21 {
		maxAPDU = uint16(data[offset+1])
		offset += 2
	} else {
		if len(data) < offset+3 {
			return nil, 0, fmt.Errorf("truncated max-apdu field")
		}
		maxAPDU = binary.BigEndian.Uint16(data[offset+1 : offset+3])
		offset += 3
	}

	// Segmentation [2]: Tag 0x91 (context 2, application tag 9=enumerated, length 1)
	if data[offset] != 0x91 {
		return nil, 0, fmt.Errorf("invalid I-Am segmentation tag: 0x%02x", data[offset])
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
		return nil, 0, fmt.Errorf("invalid I-Am vendor-id tag: 0x%02x", data[offset])
	}
	vendorID := uint16(0)
	if data[offset] == 0x21 {
		vendorID = uint16(data[offset+1])
		offset += 2
	} else {
		if len(data) < offset+3 {
			return nil, 0, fmt.Errorf("truncated vendor-id field")
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

	return plugins.CreateServiceFrom(target, metadata, false, "", plugins.UDP), deviceInstance, nil
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

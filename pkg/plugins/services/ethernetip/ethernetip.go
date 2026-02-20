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

/*
Package ethernetip implements fingerprinting for EtherNet/IP (Common Industrial Protocol).

EtherNet/IP is an industrial automation protocol that adapts the CIP (Common Industrial Protocol)
to standard Ethernet and TCP/IP. It is widely used in industrial control systems, particularly
in North America.

Detection Strategy:
- Send List Identity (0x0063) command
- Parse device identity information from response
- Extract vendor ID, device type, product code, revision, serial number, and product name
- Map vendor ID to vendor name
- Generate CPE with normalized vendor and product names

Version Detection:
- Extract revision from response (major.minor format)
- Extract serial number as hex string

CPE Generation:
- Vendor: Normalized from vendor ID mapping
- Product: Normalized product name
- Version: Revision in format "major.minor"
*/
package ethernetip

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

// Protocol constants
const (
	ETHERNETIP   = "ethernetip"
	DEFAULT_PORT = 44818
)

// EtherNet/IP Command Codes
const (
	CommandListIdentity = 0x0063
)

// Data holds information extracted from EtherNet/IP List Identity response
type Data struct {
	VendorID      uint16
	VendorName    string
	DeviceType    uint16
	ProductCode   uint16
	RevisionMajor uint8
	RevisionMinor uint8
	SerialNumber  uint32
	ProductName   string
}

// EthernetIPPlugin implements the Plugin interface for EtherNet/IP fingerprinting
type EthernetIPPlugin struct{}

// Vendor ID to vendor name mapping
var vendorIDs = map[uint16]string{
	1:    "Rockwell Automation/Allen-Bradley",
	2:    "Namco Controls Corp.",
	5:    "Parker Hannifin Corp.",
	13:   "Festo",
	19:   "Turck",
	47:   "Omron Corporation",
	48:   "Turck",
	50:   "Hitachi",
	52:   "Pilz",
	54:   "Banner Engineering Corp.",
	68:   "Red Lion Controls",
	145:  "Siemens Energy & Automation",
	255:  "Bosch Rexroth",
	283:  "ABB",
	305:  "Schneider Electric",
	355:  "SICK AG",
	385:  "Phoenix Contact",
	583:  "Yaskawa",
	616:  "WAGO",
	674:  "WEIDMUELLER",
	772:  "SEW-EURODRIVE",
}

func init() {
	plugins.RegisterPlugin(&EthernetIPPlugin{})
}

// PortPriority returns true if the port is the default EtherNet/IP port (44818)
func (p *EthernetIPPlugin) PortPriority(port uint16) bool {
	return port == DEFAULT_PORT
}

// Name returns the protocol name for EtherNet/IP
func (p *EthernetIPPlugin) Name() string {
	return ETHERNETIP
}

// Type returns the protocol type (TCP)
func (p *EthernetIPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the execution priority (400 = ICS/SCADA priority)
func (p *EthernetIPPlugin) Priority() int {
	return 400
}

// Run executes the EtherNet/IP fingerprinting logic
func (p *EthernetIPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Phase 1: Detection - send List Identity command and validate response
	request := buildListIdentityRequest()
	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, &utils.ServerNotEnable{}
	}

	// Phase 2: Parse response
	data, err := parseListIdentityResponse(response)
	if err != nil {
		return nil, err
	}

	// Phase 3: Enrichment - map vendor ID to name
	data.VendorName = mapVendorID(data.VendorID)

	// Build revision string
	revision := fmt.Sprintf("%d.%d", data.RevisionMajor, data.RevisionMinor)

	// Build serial number string (hex format)
	serial := fmt.Sprintf("%08x", data.SerialNumber)

	// Generate CPE
	cpe := buildCPE(data.VendorName, data.ProductName, revision)

	// Create service payload
	payload := plugins.ServiceEthernetIP{
		VendorID:    data.VendorID,
		VendorName:  data.VendorName,
		DeviceType:  data.DeviceType,
		ProductCode: data.ProductCode,
		Revision:    revision,
		Serial:      serial,
		ProductName: data.ProductName,
		CPEs:        []string{cpe},
	}

	return plugins.CreateServiceFrom(target, payload, false, revision, plugins.TCP), nil
}

// buildListIdentityRequest builds an EtherNet/IP List Identity request packet
func buildListIdentityRequest() []byte {
	return []byte{
		0x63, 0x00, // Command: List Identity (0x0063)
		0x00, 0x00, // Length: 0
		0x00, 0x00, 0x00, 0x00, // Session Handle: 0
		0x00, 0x00, 0x00, 0x00, // Status: 0
		0xc1, 0xde, 0xbe, 0xd1, // Sender Context (magic)
		0x00, 0x00, 0x00, 0x00, // Sender Context cont.
		0x00, 0x00, 0x00, 0x00, // Options: 0
	}
}

// parseListIdentityResponse parses an EtherNet/IP List Identity response
func parseListIdentityResponse(response []byte) (Data, error) {
	// Minimum valid response: 24-byte header + 2-byte item count + item header + identity data
	minResponseLength := 24 + 2 + 4 + 32
	if len(response) < minResponseLength {
		return Data{}, &utils.InvalidResponseErrorInfo{
			Service: ETHERNETIP,
			Info:    fmt.Sprintf("response too short: %d bytes (minimum %d)", len(response), minResponseLength),
		}
	}

	// Verify command is List Identity response (0x0063)
	command := binary.LittleEndian.Uint16(response[0:2])
	if command != CommandListIdentity {
		return Data{}, &utils.InvalidResponseErrorInfo{
			Service: ETHERNETIP,
			Info:    fmt.Sprintf("unexpected command: 0x%04x (expected 0x%04x)", command, CommandListIdentity),
		}
	}

	// Skip encapsulation header (24 bytes) and parse CPF
	idx := 24

	// Parse CPF Item Count
	if idx+2 > len(response) {
		return Data{}, &utils.InvalidResponseErrorInfo{
			Service: ETHERNETIP,
			Info:    "response too short for CPF item count",
		}
	}
	itemCount := binary.LittleEndian.Uint16(response[idx : idx+2])
	idx += 2

	if itemCount < 1 {
		return Data{}, &utils.InvalidResponseErrorInfo{
			Service: ETHERNETIP,
			Info:    "no CPF items in response",
		}
	}

	// Parse CPF Item Header
	if idx+4 > len(response) {
		return Data{}, &utils.InvalidResponseErrorInfo{
			Service: ETHERNETIP,
			Info:    "response too short for CPF item header",
		}
	}
	typeCode := binary.LittleEndian.Uint16(response[idx : idx+2])
	itemLength := binary.LittleEndian.Uint16(response[idx+2 : idx+4])
	idx += 4

	// Verify Type Code is CIP Identity (0x000C)
	if typeCode != 0x000C {
		return Data{}, &utils.InvalidResponseErrorInfo{
			Service: ETHERNETIP,
			Info:    fmt.Sprintf("unexpected CPF type code: 0x%04x (expected 0x000C)", typeCode),
		}
	}

	// Ensure we have enough data for the identity object
	if idx+int(itemLength) > len(response) {
		return Data{}, &utils.InvalidResponseErrorInfo{
			Service: ETHERNETIP,
			Info:    "response too short for identity object",
		}
	}

	// Skip Protocol Version (2 bytes) + Socket Address (16 bytes)
	idx += 18

	// Parse Identity Object fields
	// The offsets are relative to the start of the identity object (after socket address)
	vendorID := binary.LittleEndian.Uint16(response[idx : idx+2])
	deviceType := binary.LittleEndian.Uint16(response[idx+2 : idx+4])
	productCode := binary.LittleEndian.Uint16(response[idx+4 : idx+6])
	revisionMajor := uint8(response[idx+6])
	revisionMinor := uint8(response[idx+7])
	// Skip Status (2 bytes)
	serialNumber := binary.LittleEndian.Uint32(response[idx+10 : idx+14])
	productNameLength := uint8(response[idx+14])

	// Parse product name
	idx += 15
	var productName string
	if idx+int(productNameLength) <= len(response) {
		// Extract product name and remove null terminators
		productNameBytes := response[idx : idx+int(productNameLength)]
		productName = strings.TrimRight(string(productNameBytes), "\x00")
	}

	return Data{
		VendorID:      vendorID,
		DeviceType:    deviceType,
		ProductCode:   productCode,
		RevisionMajor: revisionMajor,
		RevisionMinor: revisionMinor,
		SerialNumber:  serialNumber,
		ProductName:   productName,
	}, nil
}

// mapVendorID maps a vendor ID to its vendor name
func mapVendorID(vendorID uint16) string {
	if name, ok := vendorIDs[vendorID]; ok {
		return name
	}
	return "Unknown"
}

// buildCPE generates a CPE (Common Platform Enumeration) string for EtherNet/IP device
//
// CPE format: cpe:2.3:h:{vendor}:{product}:{version}:*:*:*:*:*:*:*
//
// Parameters:
//   - vendorName: Vendor name (will be normalized)
//   - productName: Product name (will be normalized)
//   - version: Version string (e.g., "3.1")
//
// Returns:
//   - string: CPE string
func buildCPE(vendorName, productName, version string) string {
	// Normalize vendor and product names for CPE
	vendor := normalizeForCPE(vendorName)
	product := normalizeForCPE(productName)

	// Use wildcard for unknown versions
	if version == "" {
		version = "*"
	}

	return fmt.Sprintf("cpe:2.3:h:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}

// normalizeForCPE normalizes a string for use in CPE
// - Converts to lowercase
// - Replaces spaces with underscores
// - Escapes slashes in product names
// - Takes only the first part before slash for vendor names
func normalizeForCPE(s string) string {
	// For vendor names (contains slash), take first part before slash
	// For product names, keep slashes but escape them
	// Heuristic: if contains " " before "/", it's a vendor name
	if strings.Contains(s, " ") {
		// Vendor name like "Rockwell Automation/Allen-Bradley"
		if idx := strings.Index(s, "/"); idx != -1 {
			s = s[:idx]
		}
	} else {
		// Product name like "1756-ENBT/A" - escape slashes
		s = strings.ReplaceAll(s, "/", "\\/")
	}

	// Convert to lowercase
	s = strings.ToLower(s)

	// Replace spaces with underscores
	s = strings.ReplaceAll(s, " ", "_")

	// Replace common special characters (but not escaped slashes)
	s = strings.ReplaceAll(s, ".", "")
	s = strings.ReplaceAll(s, ",", "")
	s = strings.ReplaceAll(s, "'", "")

	// Remove trailing underscores
	s = strings.TrimRight(s, "_")

	return s
}

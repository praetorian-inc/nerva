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

package h323

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const H323 = "h323"

// TPKT header constants (RFC 1006)
const (
	tpktVersion    = 0x03
	tpktReserved   = 0x00
	tpktHeaderSize = 4
)

const maxIELen = 4096 // Maximum reasonable IE payload length

// Q.931 message types that indicate H.323
const (
	q931Alerting        = 0x01
	q931CallProceeding  = 0x02
	q931Connect         = 0x07
	q931ReleaseComplete = 0x5a
	q931ProtocolDisc    = 0x08
)

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	setupPacket := buildSetupPacket()
	response, err := utils.SendRecv(conn, setupPacket, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}
	if !isValidTPKT(response) {
		return nil, nil
	}

	// Use structured parsing which includes Q.931 validation
	msg := parseQ931(response)
	if msg == nil {
		// Fallback: try legacy Q.931 validation for minimal responses
		if !isValidQ931(response) {
			return nil, nil
		}
	}

	metadata := extractMetadata(response)
	return plugins.CreateServiceFrom(target, metadata, false, metadata.Version, plugins.TCP), nil
}

func (p *Plugin) PortPriority(port uint16) bool {
	return port == 1720
}

func (p *Plugin) Name() string {
	return H323
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 150
}

func isValidTPKT(response []byte) bool {
	if len(response) < tpktHeaderSize {
		return false
	}
	if response[0] != tpktVersion || response[1] != tpktReserved {
		return false
	}
	length := int(response[2])<<8 | int(response[3])
	if length < tpktHeaderSize || length > len(response) {
		return false
	}
	return true
}

func isValidQ931(response []byte) bool {
	if len(response) < tpktHeaderSize+4 {
		return false
	}
	if response[tpktHeaderSize] != q931ProtocolDisc {
		return false
	}
	crLen := int(response[tpktHeaderSize+1])
	if crLen > 4 {
		return false
	}
	msgTypeOffset := tpktHeaderSize + 2 + crLen
	if msgTypeOffset >= len(response) {
		return false
	}
	msgType := response[msgTypeOffset]
	switch msgType {
	case q931Alerting, q931CallProceeding, q931Connect, q931ReleaseComplete:
		return true
	default:
		return false
	}
}

func buildSetupPacket() []byte {
	uuie := buildH225SetupUUIE()
	bearerCap := buildBearerCapabilityIE()
	display := buildDisplayIE("nerva")
	userUser := buildUserUserIE(uuie)
	q931Body := buildQ931Setup(bearerCap, display, userUser)
	return buildTPKT(q931Body)
}

// buildTPKT wraps payload in TPKT header (RFC 1006)
func buildTPKT(payload []byte) []byte {
	totalLen := tpktHeaderSize + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = tpktVersion
	pkt[1] = tpktReserved
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen & 0xff)
	copy(pkt[tpktHeaderSize:], payload)
	return pkt
}

// buildQ931Setup creates Q.931 Setup header with 2-byte Call Reference and concatenated IEs
func buildQ931Setup(ies ...[]byte) []byte {
	header := []byte{
		q931ProtocolDisc, // 0x08
		0x02,             // Call Reference length: 2 bytes
		0x00, 0x01,       // Call Reference value: 0x0001 (originator flag=0)
		0x05,             // Message type: Setup
	}
	for _, ie := range ies {
		header = append(header, ie...)
	}
	return header
}

// buildBearerCapabilityIE creates Bearer Capability IE (0x04)
func buildBearerCapabilityIE() []byte {
	return []byte{
		0x04, // IE type: Bearer Capability
		0x03, // Length: 3 bytes
		0x88, // Unrestricted digital information
		0x93, // 64 kbit/s transfer rate
		0xa5, // Layer 1: H.221/H.242
	}
}

// buildDisplayIE creates Display Name IE (0x28)
func buildDisplayIE(name string) []byte {
	data := append([]byte(name), 0x00) // null-terminated
	ie := make([]byte, 2+len(data))
	ie[0] = 0x28            // IE type: Display
	ie[1] = byte(len(data)) // Length (1-byte)
	copy(ie[2:], data)
	return ie
}

// buildUserUserIE creates User-User IE (0x7e) with 2-byte length
func buildUserUserIE(uuie []byte) []byte {
	// Prepend the User-User protocol discriminator
	payload := append([]byte{0x05}, uuie...) // 0x05 = X.208/X.209 (ASN.1)
	payloadLen := len(payload)
	ie := make([]byte, 3+payloadLen)
	ie[0] = 0x7e                      // IE type: User-User
	ie[1] = byte(payloadLen >> 8)     // Length high byte
	ie[2] = byte(payloadLen & 0xff)   // Length low byte
	copy(ie[3:], payload)
	return ie
}

// buildH225SetupUUIE creates minimal PER-encoded H.225.0 Setup-UUIE
func buildH225SetupUUIE() []byte {
	// Hardcoded minimal Setup-UUIE template
	// Protocol ID: H.225.0 v6 (OID 0.0.8.2250.0.6)
	// Terminal type with generic vendor ID
	// 16-byte conference ID + 16-byte call identifier (all zeros)
	return []byte{
		0x20, 0xa8, 0x06,                   // Bit fields + protocol ID length
		0x00, 0x08, 0x91, 0x4a, 0x00, 0x06, // Protocol ID: H.225.0 v6
		0x01, 0x40, 0x02,                   // sourceInfo: terminal type
		0xb5, 0x00, 0x00, 0x01,             // T.35: USA, manufacturer 0x0001
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Conference ID (16 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Call Identifier (16 bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

// q931Message holds parsed Q.931 header and Information Elements
type q931Message struct {
	msgType byte            // Q.931 message type (Alerting, Connect, etc.)
	ies     map[byte][]byte // IE type -> raw IE data
}

// parseQ931 parses a TPKT-wrapped Q.931 message into structured form.
// Returns nil if the response is not a valid Q.931 message.
func parseQ931(response []byte) *q931Message {
	if !isValidTPKT(response) {
		return nil
	}

	tpktLen := int(response[2])<<8 | int(response[3])
	pos := tpktHeaderSize

	// Q.931 header: protocol discriminator
	if pos >= tpktLen {
		return nil
	}
	if response[pos] != q931ProtocolDisc {
		return nil
	}
	pos++

	// Call Reference length
	if pos >= tpktLen {
		return nil
	}
	crLen := int(response[pos])
	pos++
	if crLen > 4 || pos+crLen >= tpktLen {
		return nil
	}
	pos += crLen // skip call reference value

	// Message type
	if pos >= tpktLen {
		return nil
	}
	msgType := response[pos]
	pos++

	// Validate message type
	switch msgType {
	case q931Alerting, q931CallProceeding, q931Connect, q931ReleaseComplete:
		// valid
	default:
		return nil
	}

	// Parse Information Elements
	ies := make(map[byte][]byte)
	for pos < tpktLen && pos < len(response) {
		ieType := response[pos]
		pos++

		// Single-octet IEs have bit 8 set and no length field
		// Exception: 0x7E (User-User) is a variable-length IE despite bit 8
		if ieType&0x80 != 0 && ieType != 0x7e {
			// Single-octet IE: the type byte IS the entire IE
			ies[ieType] = nil
			continue
		}

		var ieLen int
		if ieType == 0x7e { // User-User IE has 2-byte length
			if pos+2 > len(response) {
				break
			}
			ieLen = int(response[pos])<<8 | int(response[pos+1])
			pos += 2
		} else {
			if pos >= len(response) {
				break
			}
			ieLen = int(response[pos])
			pos++
		}

		if ieLen > maxIELen {
			break // Unreasonably large IE, stop parsing
		}

		if pos+ieLen > len(response) {
			break
		}

		ies[ieType] = response[pos : pos+ieLen]
		pos += ieLen
	}

	return &q931Message{
		msgType: msgType,
		ies:     ies,
	}
}

// extractDisplayFromIE extracts the Display Name from Q.931 Display IE.
func extractDisplayFromIE(ies map[byte][]byte) string {
	data, ok := ies[0x28]
	if !ok || len(data) == 0 {
		return ""
	}
	// Trim null terminator if present
	s := string(data)
	return strings.TrimRight(s, "\x00")
}

// h225VendorInfo holds extracted H.225.0 vendor information
type h225VendorInfo struct {
	protocolVersion int
	vendorID        uint32
	productID       string
	versionID       string
}

// h225ProtocolMarker is the OID prefix for H.225.0 in PER encoding
var h225ProtocolMarker = []byte{0x00, 0x08, 0x91, 0x4a, 0x00}

// knownH225VendorIDs maps H.225.0 vendor ID uint32 values to vendor names.
// These are T.35 manufacturer codes encoded as 4-byte big-endian values.
// Format: 0x00 + T.35-country(1 byte) + manufacturer(2 bytes)
var knownH225VendorIDs = map[uint32]string{
	0xb5000001: "Polycom",
	0xb5000012: "Cisco",
	0xb5000053: "LifeSize",
	0x00a00100: "Tandberg",
}

// extractH225VendorInfo extracts vendor, product, and version from
// H.225.0 User-User IE payload. Returns nil if protocol marker not found.
func extractH225VendorInfo(msgType byte, uuData []byte) *h225VendorInfo {
	// Find protocol version marker
	idx := bytes.Index(uuData, h225ProtocolMarker)
	if idx < 0 {
		return nil
	}

	// Protocol version is at marker + 5
	pverOffset := idx + 5
	if pverOffset >= len(uuData) {
		return nil
	}
	pver := int(uuData[pverOffset])

	info := &h225VendorInfo{protocolVersion: pver}

	// Position after protocol version
	i := pverOffset + 1

	// Vendor ID extraction depends on message type
	switch msgType {
	case q931Alerting, q931CallProceeding:
		// Special case: pver==2 with \x20\x00 prefix
		if pver == 2 && i+2 <= len(uuData) &&
			uuData[i] == 0x20 && uuData[i+1] == 0x00 {
			if i+6 <= len(uuData) {
				info.vendorID = binary.BigEndian.Uint32(uuData[i+2 : i+6])
			}
			return info
		}
		// Look for \xc0 marker indicating vendor info
		if i+2 <= len(uuData) && uuData[i+1] != 0xc0 {
			i += 7
		}
		if i+2 > len(uuData) || uuData[i+1] != 0xc0 {
			return info
		}
		i += 2

	case q931Connect:
		if i >= len(uuData) || uuData[i] == 0x00 {
			return info
		}
		if i+2 <= len(uuData) && uuData[i+1] != 0xc0 {
			i += 7
		}
		if i+2 > len(uuData) || uuData[i+1] != 0xc0 {
			return info
		}
		i += 2

	default:
		return info // ReleaseComplete etc. - no vendor info expected
	}

	// Read 4-byte vendor ID
	if i+4 > len(uuData) {
		return info
	}
	info.vendorID = binary.BigEndian.Uint32(uuData[i : i+4])
	i += 4

	// Product ID and Version ID only available in protocol version >= 3
	if pver < 3 {
		return info
	}

	// Read product ID (length-prefixed, length = byte_value + 1)
	if i >= len(uuData) {
		return info
	}
	prodLen := int(uuData[i]) + 1
	i++
	if i+prodLen > len(uuData) {
		return info
	}
	info.productID = strings.TrimRight(string(uuData[i:i+prodLen]), "\x00")
	i += prodLen

	// Read version ID (length-prefixed, length = byte_value + 1)
	if i >= len(uuData) {
		return info
	}
	verLen := int(uuData[i]) + 1
	i++
	if i+verLen > len(uuData) {
		return info
	}
	info.versionID = strings.TrimRight(string(uuData[i:i+verLen]), "\x00")

	return info
}

// resolveVendorName converts a hex vendor ID string (e.g., "0x00b50001")
// to a known vendor name, or returns the hex string if unknown.
func resolveVendorName(hexVendor string) string {
	var id uint32
	if _, err := fmt.Sscanf(hexVendor, "0x%08x", &id); err != nil {
		return hexVendor
	}
	if name, ok := knownH225VendorIDs[id]; ok {
		return name
	}
	return hexVendor
}

// Known H.323 vendor signatures (T.35 manufacturer codes)
var vendorSignatures = map[string]string{
	"\xb5\x00\x01": "Polycom",
	"\xb5\x00\x12": "Cisco",
	"\xb5\x00\x53": "LifeSize",
	"\x00\xa0\x01": "Tandberg",
}

// cpeVendorMap maps detected vendor names to official CPE vendor identifiers
var cpeVendorMap = map[string]string{
	"Polycom":  "polycom",
	"Cisco":    "cisco",
	"LifeSize": "lifesize",
	"Tandberg": "tandberg",
}

// Version pattern: X.Y or X.Y.Z or X.Y.Z.W
var versionPattern = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)*)`)

// extractVendor looks for known vendor signatures in response
func extractVendor(response []byte) string {
	for sig, vendor := range vendorSignatures {
		if bytes.Contains(response, []byte(sig)) {
			return vendor
		}
	}
	return ""
}

// extractASCII finds printable ASCII strings in binary data
func extractASCII(data []byte, minLen, maxLen int) []string {
	results := []string{} // Initialize to empty slice instead of nil
	var current []byte

	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			current = append(current, b)
		} else {
			if len(current) >= minLen {
				s := string(current)
				if len(s) > maxLen {
					s = s[:maxLen]
				}
				results = append(results, s)
			}
			current = nil
		}
	}
	if len(current) >= minLen {
		s := string(current)
		if len(s) > maxLen {
			s = s[:maxLen]
		}
		results = append(results, s)
	}
	return results
}

// extractProductName finds likely product name from ASCII strings
func extractProductName(response []byte) string {
	strings := extractASCII(response, 4, 64)
	for _, s := range strings {
		if s == "RTSP" || s == "HTTP" || s == "SIP" {
			continue
		}
		if len(s) >= 6 {
			return s
		}
	}
	if len(strings) > 0 {
		return strings[0]
	}
	return ""
}

// extractVersion finds version strings in response
func extractVersion(response []byte) string {
	strings := extractASCII(response, 3, 32)
	longestVersion := ""
	for _, s := range strings {
		// Find all matches in the string and pick the longest
		allMatches := versionPattern.FindAllStringSubmatch(s, -1)
		for _, matches := range allMatches {
			if len(matches) > 1 && len(matches[1]) > len(longestVersion) {
				longestVersion = matches[1]
			}
		}
	}
	return longestVersion
}

// buildH323CPE generates a CPE string for H.323 endpoints
// CPE format: cpe:2.3:h:{vendor}:{product}:{version}:*:*:*:*:*:*:*
// Returns empty string if vendor is unknown (can't generate reliable CPE)
func buildH323CPE(vendor, product, version string) string {
	vendor = strings.TrimSpace(vendor)
	if vendor == "" {
		return ""
	}

	cpeVendor, ok := cpeVendorMap[vendor]
	if !ok {
		return "" // Unknown vendor, can't generate reliable CPE
	}

	// Normalize product name for CPE (lowercase, underscores)
	cpeProduct := normalizeForCPE(product)
	if cpeProduct == "" {
		cpeProduct = "*"
	}

	// Use wildcard for empty version
	cpeVersion := strings.TrimSpace(version)
	if cpeVersion == "" {
		cpeVersion = "*"
	}

	return fmt.Sprintf("cpe:2.3:h:%s:%s:%s:*:*:*:*:*:*:*", cpeVendor, cpeProduct, cpeVersion)
}

// normalizeForCPE converts a product name to CPE format (lowercase, spaces to underscores)
func normalizeForCPE(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")
	return s
}

// extractMetadata attempts to extract vendor/version from H.225 payload.
// Uses structured Q.931/H.225.0 parsing first, falling back to heuristic extraction.
func extractMetadata(response []byte) plugins.ServiceH323 {
	msg := parseQ931(response)

	var vendor, product, version, terminalType string

	if msg != nil {
		// Primary: Structured H.225.0 extraction from User-User IE
		if uuData, ok := msg.ies[0x7e]; ok && len(uuData) > 0 {
			h225 := extractH225VendorInfo(msg.msgType, uuData)
			if h225 != nil {
				if h225.vendorID != 0 {
					vendor = fmt.Sprintf("0x%08x", h225.vendorID)
				}
				product = h225.productID
				version = h225.versionID
			}
		}

		// Extract display name from Display IE (supplementary info)
		if display := extractDisplayFromIE(msg.ies); display != "" {
			if product == "" {
				product = display
			}
		}
	}

	// Fallback: T.35 vendor signature matching (existing logic)
	if vendor == "" {
		vendor = extractVendor(response)
	}

	// Fallback: Heuristic product/version extraction (existing logic)
	if product == "" {
		product = extractProductName(response)
	}
	if version == "" {
		version = extractVersion(response)
	}

	// Map vendor hex ID to known name for CPE generation
	vendorName := vendor
	if strings.HasPrefix(vendor, "0x") {
		vendorName = resolveVendorName(vendor)
	}

	var cpes []string
	if cpe := buildH323CPE(vendorName, product, version); cpe != "" {
		cpes = []string{cpe}
	}

	return plugins.ServiceH323{
		VendorID:     vendor,
		ProductName:  product,
		Version:      version,
		TerminalType: terminalType,
		CPEs:         cpes,
	}
}

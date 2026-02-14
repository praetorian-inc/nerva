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

	if !isValidQ931(response) {
		return nil, nil
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
	q931 := []byte{
		q931ProtocolDisc,
		0x00,
		0x05,
	}
	totalLen := tpktHeaderSize + len(q931)
	packet := make([]byte, totalLen)
	packet[0] = tpktVersion
	packet[1] = tpktReserved
	packet[2] = byte(totalLen >> 8)
	packet[3] = byte(totalLen & 0xff)
	copy(packet[tpktHeaderSize:], q931)
	return packet
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
		if containsBytes(response, []byte(sig)) {
			return vendor
		}
	}
	return ""
}

// containsBytes checks if data contains the pattern
func containsBytes(data, pattern []byte) bool {
	if len(pattern) == 0 || len(data) < len(pattern) {
		return false
	}
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
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

// extractMetadata attempts to extract vendor/version from H.225 payload
func extractMetadata(response []byte) plugins.ServiceH323 {
	vendor := extractVendor(response)
	product := extractProductName(response)
	version := extractVersion(response)

	var cpes []string
	if cpe := buildH323CPE(vendor, product, version); cpe != "" {
		cpes = []string{cpe}
	}

	return plugins.ServiceH323{
		VendorID:    vendor,
		ProductName: product,
		Version:     version,
		CPEs:        cpes,
	}
}

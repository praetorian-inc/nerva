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

package profinet

import (
	"encoding/binary"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	PROFINET = "profinet"

	// PROFINET uses DCE/RPC on these ports
	PROFINET_PORT_RT_UNICAST   = 34962
	PROFINET_PORT_RT_MULTICAST = 34963
	PROFINET_PORT_CONTEXT_MGR  = 34964
)

// DCE/RPC EPM Lookup Request (144 bytes total)
// Combines DCE_RPC_REQUEST header with EPM_Lookup for PROFINET UUID
var dceRpcEpmLookupRequest = []byte{
	// DCE_RPC_REQUEST (80 bytes)
	0x04, 0x00, 0x20, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11,
	0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
	0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x0c, 0x00, 0x00, 0x00, 0x02, 0x00, 0xff, 0xff, 0xff, 0xff, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00,
	// EPM_Lookup with PROFINET UUID dea00001-6c97-11d1-8271-00a02442df7d (64 bytes)
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0xa0, 0xde,
	0x97, 0x6c, 0xd1, 0x11, 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d, 0x01, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
}

type PROFINETPlugin struct{}

func init() {
	plugins.RegisterPlugin(&PROFINETPlugin{})
}

func (p *PROFINETPlugin) PortPriority(port uint16) bool {
	return port == PROFINET_PORT_RT_UNICAST ||
		port == PROFINET_PORT_RT_MULTICAST ||
		port == PROFINET_PORT_CONTEXT_MGR
}

func (p *PROFINETPlugin) Name() string {
	return PROFINET
}

func (p *PROFINETPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *PROFINETPlugin) Priority() int {
	return 400 // ICS protocol priority
}

func (p *PROFINETPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Send DCE/RPC EPM Lookup request
	response, err := utils.SendRecv(conn, dceRpcEpmLookupRequest, timeout)
	if err != nil {
		return nil, err
	}

	// Validate response - must be > 200 bytes for valid PROFINET response
	if len(response) < 200 {
		return nil, nil
	}

	// Extract annotation from response (contains device info)
	annotation := extractAnnotation(response)
	if annotation == "" {
		// Valid DCE/RPC response but no annotation - still PROFINET
		payload := plugins.ServicePROFINET{}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
	}

	// Parse device info from annotation
	deviceName, deviceType, vendor := parseAnnotation(annotation)

	// Build service metadata
	payload := plugins.ServicePROFINET{
		DeviceName: deviceName,
		DeviceType: deviceType,
		Vendor:     vendor,
	}

	// Generate CPE if vendor identified
	if vendor != "" {
		payload.CPEs = generateCPEs(vendor, deviceType)
	}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

// extractAnnotation extracts the annotation string from DCE/RPC EPM response
func extractAnnotation(response []byte) string {
	// Annotation offset starts at byte 165 (4-byte length) + byte 169 (length value)
	// Annotation string starts at byte 173
	if len(response) < 173 {
		return ""
	}

	// Read annotation length from offset 169 (4-byte little-endian)
	if len(response) < 173 {
		return ""
	}

	annotationLen := binary.LittleEndian.Uint32(response[169:173])
	// Validate against actual remaining buffer size to prevent overflow
	if annotationLen == 0 || annotationLen > uint32(len(response)-173) || annotationLen > 1024 {
		return ""
	}

	annotationStart := 173
	annotationEnd := annotationStart + int(annotationLen)
	if annotationEnd > len(response) {
		annotationEnd = len(response)
	}

	// Extract and clean annotation string
	annotation := string(response[annotationStart:annotationEnd])
	return cleanString(annotation)
}

// parseAnnotation extracts device info from annotation string
func parseAnnotation(annotation string) (deviceName, deviceType, vendor string) {
	annotationLower := strings.ToLower(annotation)

	// Detect vendor
	switch {
	case strings.Contains(annotationLower, "siemens"):
		vendor = "siemens"
	case strings.Contains(annotationLower, "bosch") || strings.Contains(annotationLower, "rexroth"):
		vendor = "bosch"
	case strings.Contains(annotationLower, "phoenix"):
		vendor = "phoenix_contact"
	case strings.Contains(annotationLower, "beckhoff"):
		vendor = "beckhoff"
	case strings.Contains(annotationLower, "hilscher"):
		vendor = "hilscher"
	}

	// Extract device type patterns
	deviceTypePatterns := []string{
		`ET\s?200\w*`,        // Siemens ET200
		`S7-\d+`,             // Siemens S7
		`SCALANCE\s?\w+`,     // Siemens SCALANCE
		`SIMATIC\s?\w+`,      // Siemens SIMATIC
		`IndraControl\s?\w+`, // Bosch Rexroth
		`IndraMotion\s?\w+`,  // Bosch Rexroth
		`AXC\s?F\s?\d+`,      // Phoenix Contact
	}

	for _, pattern := range deviceTypePatterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if match := re.FindString(annotation); match != "" {
			deviceType = strings.TrimSpace(match)
			break
		}
	}

	// Device name is often the full annotation or first part
	if idx := strings.Index(annotation, " "); idx > 0 && idx < 50 {
		deviceName = strings.TrimSpace(annotation[:idx])
	} else if len(annotation) < 100 {
		deviceName = annotation
	}

	return deviceName, deviceType, vendor
}

// generateCPEs creates CPE identifiers for detected PROFINET device
func generateCPEs(vendor, deviceType string) []string {
	cpes := []string{}

	// Normalize for CPE format
	vendorCPE := strings.ToLower(strings.ReplaceAll(vendor, " ", "_"))

	product := "profinet"
	if deviceType != "" {
		product = strings.ToLower(strings.ReplaceAll(deviceType, " ", "_"))
		product = strings.ReplaceAll(product, "-", "_")
	}

	// CPE 2.3 format
	cpe := "cpe:2.3:h:" + vendorCPE + ":" + product + ":*:*:*:*:*:*:*:*"
	cpes = append(cpes, cpe)

	return cpes
}

// cleanString removes non-printable characters
func cleanString(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			result.WriteRune(r)
		} else if r == 0 {
			break
		}
	}
	return strings.TrimSpace(result.String())
}

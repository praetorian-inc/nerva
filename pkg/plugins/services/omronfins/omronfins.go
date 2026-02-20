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

package omronfins

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	finsPort     = 9600
	finsPriority = 400 // ICS protocol tier (same as BACnet, DNP3, Modbus)
)

// UDPPlugin implements OMRON FINS service fingerprinting.
type UDPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&UDPPlugin{})
}

// Type returns the protocol transport type.
func (p *UDPPlugin) Type() plugins.Protocol {
	return plugins.UDP
}

// Priority returns the scan priority.
func (p *UDPPlugin) Priority() int {
	return finsPriority
}

// Name returns the plugin display name.
func (p *UDPPlugin) Name() string {
	return "omron-fins"
}

// PortPriority returns true if the port matches OMRON FINS (9600).
func (p *UDPPlugin) PortPriority(port uint16) bool {
	return port == finsPort
}

// Run performs OMRON FINS device fingerprinting using Read Controller Data (0x0501).
func (p *UDPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Read Controller Data request (13 bytes)
	// ICF=0x80 (Command, response required), RSV=0x00, GCT=0x02 (gateway count)
	// DNA=0x00 (dest network, local), DA1=0x00 (dest node, PLC), DA2=0x00 (dest unit, CPU)
	// SNA=0x00 (src network, local), SA1=0x63 (src node, 99), SA2=0x00 (src unit, CPU)
	// SID=0xEF (service ID), MRC=0x05 (Main request: Controller Data), SRC=0x01 (Sub: Read), Param=0x00
	request := []byte{
		0x80, 0x00, 0x02, 0x00, 0x00, 0x00,
		0x00, 0x63, 0x00, 0xEF,
		0x05, 0x01, 0x00,
	}

	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	model, version, err := parseControllerData(response)
	if err != nil {
		return nil, err
	}

	cpes := generateCPE(model, version)

	metadata := plugins.ServiceOMRONFINS{
		ControllerModel:   model,
		ControllerVersion: version,
		CPEs:              cpes,
	}

	versionStr := version
	if versionStr == "" {
		versionStr = model
	}

	return plugins.CreateServiceFrom(target, metadata, false, versionStr, plugins.UDP), nil
}

// parseControllerData validates and parses a FINS Read Controller Data response.
// Returns model, version strings, or an error if the response is not a valid FINS response.
// Returns nil, nil, nil for no response (caller handles empty response before calling).
func parseControllerData(data []byte) (model, version string, err error) {
	// Minimum: 14-byte FINS header + at least start of model name field
	if len(data) < 14 {
		return "", "", fmt.Errorf("FINS response too short: %d bytes (minimum 14)", len(data))
	}

	// Validate ICF byte: must be 0xC0 or 0xC1 (response frame)
	icf := data[0]
	if icf != 0xC0 && icf != 0xC1 {
		return "", "", fmt.Errorf("invalid FINS ICF byte: 0x%02x (expected 0xC0 or 0xC1)", icf)
	}

	// Check response code at bytes 12-13 (big-endian uint16): must be 0x0000 (Normal completion)
	responseCode := binary.BigEndian.Uint16(data[12:14])
	if responseCode != 0x0000 {
		return "", "", fmt.Errorf("FINS command error: response code 0x%04x", responseCode)
	}

	// Extract Controller Model: null-terminated string at offset 14, max 20 bytes
	if len(data) >= 14+20 {
		model = extractNullTerminatedString(data[14:34])
	} else if len(data) > 14 {
		model = extractNullTerminatedString(data[14:])
	}
	model = sanitizeString(model)

	// Extract Controller Version: null-terminated string at offset 34, max 20 bytes
	if len(data) >= 34+20 {
		version = extractNullTerminatedString(data[34:54])
	} else if len(data) > 34 {
		version = extractNullTerminatedString(data[34:])
	}
	version = sanitizeString(version)

	return model, version, nil
}

// extractNullTerminatedString reads bytes until a null byte or end of slice,
// returning the resulting string.
func extractNullTerminatedString(b []byte) string {
	for i, c := range b {
		if c == 0x00 {
			return string(b[:i])
		}
	}
	return string(b)
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
	return strings.TrimSpace(string(result))
}

// generateCPE creates CPE 2.3 strings for OMRON FINS hardware.
func generateCPE(model, version string) []string {
	if model == "" {
		return nil
	}
	modelSlug := normalizeCPE(model)
	versionSlug := "*"
	if version != "" {
		versionSlug = normalizeCPE(version)
	}
	cpe := fmt.Sprintf("cpe:2.3:h:omron:%s:%s:*:*:*:*:*:*:*", modelSlug, versionSlug)
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

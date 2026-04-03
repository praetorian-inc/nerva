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

package crimsonv3

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	CR3HeaderSize        = 6
	RegisterManufacturer = 0x012b
	RegisterModel        = 0x012a
	DefaultPort          = 789
)

type CrimsonV3Plugin struct{}

func init() {
	plugins.RegisterPlugin(&CrimsonV3Plugin{})
}

const CRIMSONV3 = "crimsonv3"

func (p *CrimsonV3Plugin) PortPriority(port uint16) bool {
	return port == DefaultPort
}

// Run
/*
   Crimson V3 is a proprietary binary protocol used by Red Lion Controls
   industrial HMI and data acquisition devices.

   Crimson V3 runs on TCP port 789 by default. All frames have a simple structure:
   - Bytes 0-1: Payload length (big-endian uint16) - number of bytes following
   - Bytes 2-3: Register number (big-endian uint16)
   - Bytes 4+: Data

   This implementation queries read-only registers:
   - 0x012b (299): Manufacturer name (returns null-terminated string)
   - 0x012a (298): Model name (returns null-terminated string)

   These are safe, read-only register queries that:
   - Do NOT modify any data
   - Do NOT trigger control operations
   - Do NOT write to device memory
   - Safe for ICS/SCADA/HMI environments

   Response format matches request structure:
   - 6-byte header (length + register + type/status)
   - Followed by null-terminated string data

   Based on Nmap NSE script cr3-fingerprint.nse
*/
func (p *CrimsonV3Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Manufacturer probe: {0x00, 0x04, 0x01, 0x2b, 0x1b, 0x00}
	manufacturerProbe := []byte{0x00, 0x04, 0x01, 0x2b, 0x1b, 0x00}

	response, err := utils.SendRecv(conn, manufacturerProbe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Validate response (must be > 6 bytes for valid CR3 response)
	if !isValidResponse(response) {
		return nil, nil
	}

	// Extract manufacturer string — must be printable ASCII to avoid
	// false positives on binary protocols like MySQL X Protocol
	manufacturer := extractString(response)
	if !isPrintableASCII(manufacturer) {
		return nil, nil
	}

	// Create service data
	serviceData := plugins.ServiceCrimsonV3{
		Manufacturer: manufacturer,
	}

	// Try to enrich with model information (non-critical)
	// Model probe: {0x00, 0x04, 0x01, 0x2a, 0x1a, 0x00}
	modelProbe := []byte{0x00, 0x04, 0x01, 0x2a, 0x1a, 0x00}
	modelResponse, err := utils.SendRecv(conn, modelProbe, timeout)
	if err == nil && len(modelResponse) > CR3HeaderSize {
		model := extractString(modelResponse)
		if model != "" {
			serviceData.Model = model
			// Generate CPE from model
			if cpe := generateCPE(model); cpe != "" {
				serviceData.CPEs = []string{cpe}
			}
		}
	}

	return plugins.CreateServiceFrom(target, serviceData, false, "", plugins.TCP), nil
}

func (p *CrimsonV3Plugin) Name() string {
	return CRIMSONV3
}

func (p *CrimsonV3Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *CrimsonV3Plugin) Priority() int {
	return 400 // Same priority as Modbus/DNP3 (ICS protocol)
}

// extractString extracts a null-terminated string from a CR3 response
// Skips the 6-byte header and strips trailing null byte
func extractString(response []byte) string {
	if len(response) <= CR3HeaderSize {
		return ""
	}

	// Extract data after 6-byte header
	data := response[CR3HeaderSize:]

	// Remove trailing null byte if present
	if len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}

	return string(data)
}

// isValidResponse checks if response is valid CR3 format.
// Validates header structure: first two bytes encode payload length (big-endian),
// and the stated length must be consistent with the actual response size.
// This prevents false positives on other binary protocols (e.g., MySQL X Protocol)
// whose responses happen to be longer than 6 bytes.
func isValidResponse(response []byte) bool {
	if len(response) <= CR3HeaderSize {
		return false
	}
	// Validate payload length field matches actual response
	payloadLen := int(response[0])<<8 | int(response[1])
	if payloadLen == 0 || payloadLen+2 != len(response) {
		return false
	}
	return true
}

// isPrintableASCII checks that every byte in s is printable ASCII (0x20-0x7E).
// CR3 register strings (manufacturer, model) are always human-readable text.
func isPrintableASCII(s string) bool {
	if s == "" {
		return false
	}
	for _, b := range []byte(s) {
		if b < 0x20 || b > 0x7E {
			return false
		}
	}
	return true
}

// generateCPE generates CPE string from model name
// Format: cpe:2.3:h:red_lion:{normalized_model}:*:*:*:*:*:*:*:*
func generateCPE(model string) string {
	if model == "" {
		return ""
	}

	// Normalize model name for CPE (lowercase, replace spaces with underscores)
	normalized := strings.ToLower(model)
	normalized = strings.ReplaceAll(normalized, " ", "_")

	// Remove non-alphanumeric characters except underscores and hyphens
	reg := regexp.MustCompile(`[^a-z0-9_-]`)
	normalized = reg.ReplaceAllString(normalized, "")

	if normalized == "" {
		return ""
	}

	return fmt.Sprintf("cpe:2.3:h:red_lion:%s:*:*:*:*:*:*:*:*", normalized)
}

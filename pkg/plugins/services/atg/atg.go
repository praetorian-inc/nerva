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

package atg

import (
	"bytes"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type ATGPlugin struct{}

const ATG = "atg"

// i20100Command is the TLS protocol I20100 inventory command.
// Format: SOH (0x01) + "I20100" + LF (0x0A)
var i20100Command = []byte{0x01, 'I', '2', '0', '1', '0', '0', 0x0A}

func init() {
	plugins.RegisterPlugin(&ATGPlugin{})
}

func (p *ATGPlugin) PortPriority(port uint16) bool {
	return port == 10001
}

func (p *ATGPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := pluginutils.SendRecv(conn, i20100Command, timeout)
	if err != nil {
		return nil, nil
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Validate ATG response: must start with SOH (0x01) or LF (0x0A)
	// OR contain the error code (9999FF1B) which confirms ATG device
	if response[0] != 0x01 && response[0] != 0x0A && !isATGErrorResponse(response) {
		return nil, nil
	}

	serviceData := parseATGResponse(response)
	serviceData.CPEs = []string{"cpe:2.3:h:veeder-root:tls:*:*:*:*:*:*:*:*"}

	return plugins.CreateServiceFrom(target, serviceData, false, "", plugins.TCP), nil
}

func (p *ATGPlugin) Name() string {
	return ATG
}

func (p *ATGPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *ATGPlugin) Priority() int {
	return 500
}

// parseATGResponse extracts metadata from a TLS I20100 inventory response.
// Responses contain station name and per-tank data (product, volume, etc.).
func parseATGResponse(data []byte) plugins.ServiceATG {
	result := plugins.ServiceATG{}
	text := string(data)

	// Extract station name from the first data line after the header
	// Format typically has station info on the line after the command echo
	lines := strings.Split(text, "\n")

	tankCount := 0
	products := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check for "IN-TANK INVENTORY" header to confirm valid inventory data
		// Station name often appears on the same line or nearby

		// Look for tank data lines - they typically contain "TANK" followed by a number
		// and product information
		if strings.Contains(line, "TANK") && !strings.Contains(line, "IN-TANK") {
			tankCount++
		}

		// Extract product names - common fuel types in ATG systems
		// Products appear in inventory data as text fields
		for _, product := range knownProducts(line) {
			products[product] = true
		}
	}

	// Try to extract station name from early lines
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "\x01") {
			continue
		}
		// Skip header/command echo lines
		if strings.Contains(line, "I20100") || strings.Contains(line, "IN-TANK") {
			continue
		}
		// First non-empty, non-header line is typically the station name/address
		if len(line) > 2 && !strings.Contains(line, "TANK") {
			result.StationName = line
			break
		}
	}

	if tankCount > 0 {
		result.TankCount = tankCount
	}

	if len(products) > 0 {
		result.Products = make([]string, 0, len(products))
		for p := range products {
			result.Products = append(result.Products, p)
		}
	}

	return result
}

// knownProducts checks if a line contains recognizable fuel/product names
// and returns any found.
func knownProducts(line string) []string {
	upper := strings.ToUpper(line)
	var found []string

	productNames := []string{
		"UNLEADED", "PREMIUM", "DIESEL", "SUPER",
		"REGULAR", "MIDGRADE", "E85", "KEROSENE",
		"DEF",
	}

	for _, name := range productNames {
		if strings.Contains(upper, name) {
			found = append(found, name)
		}
	}
	return found
}

// isATGErrorResponse checks if the response is an ATG error code.
// Error code 9999FF1B means "command not understood" but still confirms ATG presence.
func isATGErrorResponse(data []byte) bool {
	return bytes.Contains(data, []byte("9999FF1B"))
}

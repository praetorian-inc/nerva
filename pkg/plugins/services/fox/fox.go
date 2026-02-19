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

package fox

import (
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	FOX            = "fox"
	DefaultFoxPort = 1911
	FoxPriority    = 400 // ICS protocol tier (same as BACnet, Modbus)
)

// FOXPlugin implements Niagara Fox protocol fingerprinting
type FOXPlugin struct{}

func init() {
	plugins.RegisterPlugin(&FOXPlugin{})
}

// Name returns the plugin name
func (p *FOXPlugin) Name() string {
	return FOX
}

// Type returns the protocol transport type (TCP)
func (p *FOXPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the scan priority (400 = ICS protocol tier)
func (p *FOXPlugin) Priority() int {
	return FoxPriority
}

// PortPriority returns true if the port matches default Fox port (1911)
func (p *FOXPlugin) PortPriority(port uint16) bool {
	return port == DefaultFoxPort
}

// Run performs Fox protocol detection and metadata extraction
//
// Fox protocol hello handshake:
// Request:  "fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n}\n"
// Response: "fox a 0 -1 fox hello\n{\nkey=type:value\n...\n}\n"
//
// The response contains key-value pairs in format "key=type:value" where:
// - key: Property name (e.g., "hostName", "app.version")
// - type: Data type (s=string, i=integer)
// - value: Property value
func (p *FOXPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Build Fox hello request
	request := "fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n}\n"

	// Send request and receive response
	response, err := utils.SendRecv(conn, []byte(request), timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	responseStr := string(response)

	// Validate Fox hello response header
	if !strings.HasPrefix(responseStr, "fox a 0 -1 fox hello\n") {
		return nil, nil
	}

	// Validate response has complete body with { and }
	if !strings.Contains(responseStr, "{") || !strings.Contains(responseStr, "}") {
		return nil, nil
	}

	// Parse metadata from response
	metadata := parseFoxResponse(responseStr)

	// Create service with Fox metadata
	return plugins.CreateServiceFrom(target, metadata, false, metadata.Version, plugins.TCP), nil
}

// parseFoxResponse extracts metadata from Fox hello response
//
// Response format:
// fox a 0 -1 fox hello
// {
// fox.version=s:1.0
// hostName=s:JACE-001
// hostAddress=s:192.168.1.100
// ...
// }
func parseFoxResponse(response string) plugins.ServiceFox {
	metadata := plugins.ServiceFox{}

	// Pattern to match key=type:value lines
	// Example: "fox.version=s:1.0" or "hostName=s:JACE-001"
	kvPattern := regexp.MustCompile(`([a-zA-Z.]+)=([si]):(.*)`)

	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "{" || line == "}" {
			continue
		}

		matches := kvPattern.FindStringSubmatch(line)
		if len(matches) != 4 {
			continue
		}

		key := matches[1]
		// typeChar := matches[2] // s=string, i=integer
		value := matches[3]

		// Map keys to metadata fields
		switch key {
		case "fox.version":
			metadata.Version = value
		case "hostName":
			metadata.HostName = value
		case "hostAddress":
			metadata.HostAddress = value
		case "app.name":
			metadata.AppName = value
		case "app.version":
			metadata.AppVersion = value
		case "vm.name":
			metadata.VMName = value
		case "vm.version":
			metadata.VMVersion = value
		case "os.name":
			metadata.OSName = value
		case "station.name":
			metadata.StationName = value
		case "brandId":
			metadata.BrandId = value
		}
	}

	// Generate CPE from BrandId, AppName, and AppVersion
	metadata.CPEs = generateCPE(metadata.BrandId, metadata.AppName, metadata.AppVersion)

	return metadata
}

// generateCPE creates CPE 2.3 strings for Niagara Fox applications.
// Returns nil if vendor is unknown or empty.
func generateCPE(brandId, appName, appVersion string) []string {
	vendorSlug := getVendorSlug(brandId)
	if vendorSlug == "*" || vendorSlug == "" {
		return nil // Unknown vendor, no CPE
	}

	// Normalize app name for CPE (lowercase, replace spaces/special chars with underscores)
	appSlug := "*"
	if appName != "" {
		appSlug = normalizeCPE(appName)
	}

	// Normalize app version
	versionSlug := "*"
	if appVersion != "" {
		versionSlug = normalizeCPE(appVersion)
	}

	// CPE 2.3 format for applications: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
	cpe := "cpe:2.3:a:" + vendorSlug + ":" + appSlug + ":" + versionSlug + ":*:*:*:*:*:*:*"
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

// getVendorSlug maps Fox BrandId to CPE vendor slug.
// Returns "*" for unknown vendors.
func getVendorSlug(brandId string) string {
	// Normalize brandId to lowercase for case-insensitive matching
	brandIdLower := strings.ToLower(strings.TrimSpace(brandId))

	// Map known Niagara Fox vendors to CPE vendor identifiers
	vendorMap := map[string]string{
		"tridium":   "tridium",
		"honeywell": "honeywell",
		"vykon":     "vykon",
		"distech":   "distech",
		"siemens":   "siemens",
		"schneider": "schneider_electric",
		"johnson":   "johnson_controls",
		"carrier":   "carrier",
		"niagara":   "tridium", // Niagara is Tridium's product
	}

	if vendor, exists := vendorMap[brandIdLower]; exists {
		return vendor
	}

	// Unknown vendor
	return "*"
}

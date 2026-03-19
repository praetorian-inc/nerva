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

package codesys

import (
	"net"
	"regexp"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	CODESYS = "codesys"

	// V2 Protocol constants
	V2ResponseSignature = 0xbb
	MinV2ResponseLength = 10 // Minimum valid V2 response size: Header (7 bytes) + minimal metadata
	OSNameOffset        = 65
	OSTypeOffset        = 97
	ProductTypeOffset   = 129
)

type CODESYSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&CODESYSPlugin{})
}

func (p *CODESYSPlugin) PortPriority(port uint16) bool {
	return port == 2455 || port == 1217 || port == 1200
}

// Run implements CODESYS protocol detection with multi-version fallback
func (p *CODESYSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Try V2 Little-Endian handshake first
	service, err := p.tryV2Protocol(conn, timeout, target, true)
	if service != nil || err != nil {
		return service, err
	}

	// Try V2 Big-Endian handshake
	service, err = p.tryV2Protocol(conn, timeout, target, false)
	if service != nil || err != nil {
		return service, err
	}

	// V3 protocol detection can be added here in future
	// Currently focusing on V2 which is more widely deployed

	return nil, nil
}

// tryV2Protocol attempts V2 protocol detection with specified endianness
func (p *CODESYSPlugin) tryV2Protocol(conn net.Conn, timeout time.Duration, target plugins.Target, littleEndian bool) (*plugins.Service, error) {
	var request []byte
	if littleEndian {
		// V2 Little-Endian request
		request = []byte{0xbb, 0xbb, 0x01, 0x00, 0x00, 0x00, 0x01}
	} else {
		// V2 Big-Endian request
		request = []byte{0xbb, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x01}
	}

	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, err
	}

	// Check minimum response length to prevent out-of-bounds read (CWE-125)
	if len(response) < MinV2ResponseLength {
		return nil, nil
	}

	// Validate response starts with 0xbb (V2 signature)
	if response[0] != V2ResponseSignature {
		return nil, nil
	}

	// Extract metadata from V2 response
	serviceData := plugins.ServiceCODESYS{}

	// Only extract metadata if response is long enough
	if len(response) > OSNameOffset {
		serviceData.OSName = extractNullTerminatedString(response, OSNameOffset)
	}

	if len(response) > OSTypeOffset {
		serviceData.OSType = extractNullTerminatedString(response, OSTypeOffset)
	}

	if len(response) > ProductTypeOffset {
		productType := extractNullTerminatedString(response, ProductTypeOffset)
		serviceData.Version = extractVersionFromProduct(productType)

		// Generate CPE if version extracted
		if serviceData.Version != "" {
			serviceData.CPEs = []string{
				"cpe:2.3:a:codesys:codesys:" + serviceData.Version + ":*:*:*:*:*:*:*",
			}
		}
	}

	return plugins.CreateServiceFrom(target, serviceData, false, "", plugins.TCP), nil
}

func (p *CODESYSPlugin) Name() string {
	return CODESYS
}

func (p *CODESYSPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *CODESYSPlugin) Priority() int {
	// ICS/SCADA protocols use Priority 400 (same as modbus, dnp3)
	// This ensures execution after HTTP/HTTPS (0/1) but before generic services
	return 400
}

// extractNullTerminatedString extracts a null-terminated string from byte array at given offset
func extractNullTerminatedString(data []byte, offset int) string {
	if offset >= len(data) {
		return ""
	}

	end := offset
	for end < len(data) && data[end] != 0 {
		end++
	}

	return string(data[offset:end])
}

// extractVersionFromProduct parses version from CODESYS product type string
// Example: "CODESYS V2.3.9.60" → "2.3.9.60"
// Example: "CODESYS V3.5.16.0" → "3.5.16.0"
func extractVersionFromProduct(productType string) string {
	if productType == "" {
		return ""
	}

	// Match version pattern: V followed by digits.digits or just digits.digits
	versionRegex := regexp.MustCompile(`V?(\d+\.\d+(?:\.\d+)*(?:\.\d+)?)`)
	matches := versionRegex.FindStringSubmatch(productType)

	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

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

package melsecq

import (
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	MELSECQ = "melsec-q"

	// 3E frame response magic byte
	MelsecQResponseMagic = 0xD7

	// Minimum response length (header + CPU model)
	MelsecQMinResponseLen = 43
)

type MelsecQPlugin struct{}

func init() {
	plugins.RegisterPlugin(&MelsecQPlugin{})
}

func (p *MelsecQPlugin) PortPriority(port uint16) bool {
	return port == 5006 || port == 5007
}

/*
MELSEC-Q (Mitsubishi PLCs) runs on TCP ports 5006 and 5007 using the 3E frame protocol.

Detection Strategy (based on Nmap melsecq-discover.nse):
1. Send 40-byte probe (3E frame, Read CPU Model command 0x0101)
2. Receive response
3. Validate response header: first byte must be 0xD7 (3E response magic)
4. Validate response is long enough (>= 43 bytes)
5. Extract CPU model string starting at byte offset 42 (null-terminated ASCII, max 16 chars)
6. Generate CPE for Mitsubishi

ICS/SCADA Safety:
- Read-only detection (command 0x0101 = Read CPU Model)
- No write operations to PLC memory
- Graceful error handling (connection issues must not crash)
*/
func (p *MelsecQPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Step 1: Send Read CPU Model probe
	probe := buildMelsecQProbe()
	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Step 2: Validate response
	if !isValidMelsecQResponse(response) {
		return nil, nil
	}

	// Step 3: Extract CPU model
	cpuModel := extractCPUModel(response)

	// Step 4: Build service metadata
	serviceData := plugins.ServiceMelsecQ{
		CPUModel: cpuModel,
	}

	// Step 5: Generate CPE
	if cpuModel != "" {
		serviceData.CPEs = []string{buildMelsecQCPE()}
	}

	return plugins.CreateServiceFrom(target, serviceData, false, "", plugins.TCP), nil
}

func (p *MelsecQPlugin) Name() string {
	return MELSECQ
}

func (p *MelsecQPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *MelsecQPlugin) Priority() int {
	return 400 // ICS protocol priority (same as modbus, s7comm)
}

// buildMelsecQProbe constructs the 40-byte Read CPU Model probe
// Based on Nmap melsecq-discover.nse
func buildMelsecQProbe() []byte {
	return []byte{
		0x57, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x07,
		0x00, 0x00, 0xff, 0xff, 0x03, 0x00, 0x00, 0xfe,
		0x03, 0x00, 0x00, 0x14, 0x00, 0x1c, 0x08, 0x0a,
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01,
	}
}

// isValidMelsecQResponse validates the response header and length
func isValidMelsecQResponse(response []byte) bool {
	// Check minimum length
	if len(response) < MelsecQMinResponseLen {
		return false
	}

	// Check magic byte (first byte must be 0xD7)
	if response[0] != MelsecQResponseMagic {
		return false
	}

	return true
}

// extractCPUModel extracts the null-terminated CPU model string at offset 42
func extractCPUModel(response []byte) string {
	// CPU model starts at byte 42
	if len(response) < MelsecQMinResponseLen {
		return ""
	}

	// Extract up to 16 characters or until null terminator
	start := 42
	end := start + 16
	if end > len(response) {
		end = len(response)
	}

	// Find null terminator
	cpuBytes := response[start:end]
	for i, b := range cpuBytes {
		if b == 0 {
			cpuBytes = cpuBytes[:i]
			break
		}
	}

	cpuModel := string(cpuBytes)
	return strings.TrimSpace(cpuModel)
}

// buildMelsecQCPE generates the CPE string for Mitsubishi MELSEC-Q
func buildMelsecQCPE() string {
	// CPE 2.3 format: cpe:2.3:h:vendor:product:version:...
	// Using wildcard for version since we can't extract firmware version from CPUINFO alone
	return "cpe:2.3:h:mitsubishielectric:melsec-q:*:*:*:*:*:*:*:*"
}

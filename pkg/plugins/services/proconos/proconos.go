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

package proconos

import (
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	PROCONOS = "proconos"

	// Protocol constants
	ResponseSignature        = 0xcc
	LadderLogicRuntimeOffset = 13
	PLCTypeOffset            = 45
	ProjectNameOffset        = 78
)

type ProConOSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&ProConOSPlugin{})
}

const descr = `
ProConOS is a PLC runtime engine by KW-Software (Phoenix Contact) for embedded and PC-based control applications.

This plugin detects exposed ProConOS runtime environments on TCP port 20547.

Detection Strategy:
1. Send ProConOS probe packet (10 bytes)
2. Validate response starts with 0xcc signature
3. Extract metadata from null-terminated strings at fixed offsets:
   - Offset 13: Ladder Logic Runtime version
   - Offset 45: PLC Type identifier
   - Offset 78: Project Name
   - Variable offsets: Boot Project and Project Source Code

ICS/SCADA Safety:
- Read-only detection probes (no write operations to PLC memory)
- Uses protocol handshake only (non-disruptive)
- Graceful error handling (connection issues must not crash)
- Timeout enforcement (avoid hanging on unresponsive devices)

Default port: 20547
`

func (p *ProConOSPlugin) PortPriority(port uint16) bool {
	return port == 20547
}

// Run implements ProConOS protocol detection
func (p *ProConOSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// ProConOS probe packet (10 bytes)
	request := []byte{0xcc, 0x01, 0x00, 0x0b, 0x40, 0x02, 0x00, 0x00, 0x47, 0xee}

	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, nil
	}

	// Validate response starts with 0xcc (ProConOS signature)
	if response[0] != ResponseSignature {
		return nil, nil
	}

	// Extract metadata from ProConOS response
	serviceData := plugins.ServiceProConOS{}

	// Extract Ladder Logic Runtime from offset 13
	if len(response) > LadderLogicRuntimeOffset {
		serviceData.LadderLogicRuntime = extractNullTerminatedString(response, LadderLogicRuntimeOffset)
	}

	// Extract PLC Type from offset 45
	if len(response) > PLCTypeOffset {
		serviceData.PLCType = extractNullTerminatedString(response, PLCTypeOffset)
	}

	// Extract Project Name from offset 78
	if len(response) > ProjectNameOffset {
		serviceData.ProjectName = extractNullTerminatedString(response, ProjectNameOffset)

		// Calculate Boot Project offset (after Project Name + null terminator)
		bootProjectOffset := ProjectNameOffset + len(serviceData.ProjectName) + 1
		if bootProjectOffset < len(response) {
			serviceData.BootProject = extractNullTerminatedString(response, bootProjectOffset)

			// Calculate Project Source Code offset (after Boot Project + null terminator)
			sourceCodeOffset := bootProjectOffset + len(serviceData.BootProject) + 1
			if sourceCodeOffset < len(response) {
				serviceData.ProjectSourceCode = extractNullTerminatedString(response, sourceCodeOffset)
			}
		}
	}

	return plugins.CreateServiceFrom(target, serviceData, false, "", plugins.TCP), nil
}

func (p *ProConOSPlugin) Name() string {
	return PROCONOS
}

func (p *ProConOSPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *ProConOSPlugin) Priority() int {
	// ICS/SCADA protocols use Priority 400 (same as modbus, dnp3, codesys)
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

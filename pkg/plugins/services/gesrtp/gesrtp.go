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

package gesrtp

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
	headerLen          = 56
	initResponseByte   = 0x01
	protocolIDByte     = 0x0f
	returnResponseByte = 0x03
	textLengthOffset   = 4
	svcCodeOffset      = 42

	// Controller type payload offsets (from start of payload, NOT from start of response)
	ctrlSvcEchoOffset   = 8
	ctrlDeviceIndOffset = 9
	ctrlPLCNameOffset   = 12
	ctrlPLCNameMaxLen   = 8
	ctrlPayloadLen      = 40

	svcSCADAEnable          = 0x4F
	svcReturnControllerType = 0x43
)

type GESRTPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&GESRTPPlugin{})
}

func (p *GESRTPPlugin) PortPriority(port uint16) bool {
	return port == 18245
}

func (p *GESRTPPlugin) Name() string {
	return plugins.ProtoGESRTP
}

func (p *GESRTPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *GESRTPPlugin) Priority() int {
	return 400 // ICS protocol priority
}

/*
GE SRTP (Service Request Transport Protocol) runs on TCP port 18245.
Protocol reverse-engineered from GE/Emerson PACSystems, Series 90, and RX3i PLCs.

Detection Strategy:
1. Send Init packet (56 bytes of zeros)
2. Receive Init Response - validates GE SRTP protocol presence
3. Send SCADA Enable packet (service code 0x4F)
4. Receive SCADA Enable Response - confirms SCADA session established
5. Send Return Controller Type packet (service code 0x43)
6. Receive Controller Type Response - extracts PLC name and device indicator

ICS/SCADA Safety:
- Read-only identification probes (no write operations to PLC memory)
- Uses established service codes (SCADA Enable, Return Controller Type)
- No memory read/write, no program upload/download, no CPU control commands
- Graceful error handling (connection issues must not crash)

References:
- https://github.com/TheMadHatt3r/ge-ethernet-SRTP
- https://dfrws.org/wp-content/uploads/2019/06/paper_leveraging_the_srtp_protocol_for_over-the-network_memory_acquisition_of_a_ge_fanuc_series_90-30.pdf
- CVE-2022-30263 (cleartext credential transmission)
*/
func (p *GESRTPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Step 1: Send Init packet (56 bytes of zeros)
	initPacket := make([]byte, headerLen)
	initResponse, err := utils.SendRecv(conn, initPacket, timeout)
	if err != nil {
		return nil, err
	}
	if len(initResponse) == 0 {
		return nil, nil
	}

	// Step 2: Validate Init Response
	if !validateInitResponse(initResponse) {
		return nil, nil
	}

	// Step 3: Send SCADA Enable packet
	scadaEnablePacket := buildSCADAEnablePacket()
	scadaResponse, err := utils.SendRecv(conn, scadaEnablePacket, timeout)
	if err != nil {
		return nil, err
	}
	if len(scadaResponse) == 0 || len(scadaResponse) < 1 {
		return nil, nil
	}

	// Step 4: Validate SCADA Enable Response
	if scadaResponse[0] != returnResponseByte {
		return nil, nil
	}

	// At this point, we have confirmed GE SRTP presence
	serviceData := plugins.ServiceGESRTP{}

	// Step 5: Send Return Controller Type packet (enrichment - graceful failure)
	ctrlTypePacket := buildReturnControllerTypePacket()
	ctrlResponse, err := utils.SendRecv(conn, ctrlTypePacket, timeout)
	if err != nil || len(ctrlResponse) == 0 {
		// Enrichment failed, return basic detection
		return plugins.CreateServiceFrom(target, serviceData, false, "", plugins.TCP), nil
	}

	// Step 6: Parse Controller Type Response
	serviceData = parseControllerTypeResponse(ctrlResponse, conn, timeout)

	// Generate CPE from PLC name
	if serviceData.PLCName != "" || serviceData.DeviceIndicator != 0 {
		serviceData.CPEs = generateCPE(serviceData.PLCName)
	}

	return plugins.CreateServiceFrom(target, serviceData, false, "", plugins.TCP), nil
}

// validateInitResponse checks if response is valid GE SRTP init acknowledgment
func validateInitResponse(response []byte) bool {
	// Must be exactly 56 bytes
	if len(response) != headerLen {
		return false
	}

	// First byte must be 0x01 (init acknowledgment)
	if response[0] != initResponseByte {
		return false
	}

	// Byte 8 must be 0x0f (protocol identifier)
	if response[8] != protocolIDByte {
		return false
	}

	return true
}

// buildSCADAEnablePacket constructs SCADA Enable request (service code 0x4F)
func buildSCADAEnablePacket() []byte {
	return []byte{
		0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc0,
		0x00, 0x00, 0x00, 0x00, 0x10, 0x0e, 0x00, 0x00,
		0x01, 0x01, svcSCADAEnable, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

// buildReturnControllerTypePacket constructs Return Controller Type request (service code 0x43)
func buildReturnControllerTypePacket() []byte {
	return []byte{
		0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xc0,
		0x00, 0x00, 0x00, 0x00, 0x10, 0x0e, 0x00, 0x00,
		0x01, 0x01, svcReturnControllerType, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

// parseControllerTypeResponse extracts PLC name and device indicator from response
func parseControllerTypeResponse(response []byte, conn net.Conn, timeout time.Duration) plugins.ServiceGESRTP {
	serviceData := plugins.ServiceGESRTP{}

	// Response can be:
	// - 56 bytes (header only) - no payload
	// - 96 bytes (header + 40-byte payload) - single read
	// - 56 bytes header, then 40 bytes payload - split reads

	// Minimum: header only
	if len(response) < headerLen {
		return serviceData
	}

	// Check if we have payload
	textLength := binary.LittleEndian.Uint16(response[textLengthOffset : textLengthOffset+2])

	// If textLength indicates payload but we only have header, read additional bytes
	if textLength > 0 && len(response) == headerLen {
		// Read additional payload
		payload := make([]byte, textLength)
		n, err := conn.Read(payload)
		if err != nil || n == 0 {
			return serviceData // Return empty if can't read payload
		}
		// Combine header and payload
		response = append(response, payload[:n]...)
	}

	// Now check if we have full response (header + payload)
	if len(response) < headerLen+ctrlSvcEchoOffset+1 {
		return serviceData
	}

	// Payload starts at offset 56 (after header)
	payload := response[headerLen:]

	// Verify service echo (payload offset 8)
	if len(payload) > ctrlSvcEchoOffset && payload[ctrlSvcEchoOffset] != svcReturnControllerType {
		return serviceData
	}

	// Extract device indicator (payload offset 9)
	if len(payload) > ctrlDeviceIndOffset {
		serviceData.DeviceIndicator = payload[ctrlDeviceIndOffset]
	}

	// Extract PLC name (payload offset 12, max 8 bytes, null-terminated)
	if len(payload) >= ctrlPLCNameOffset+ctrlPLCNameMaxLen {
		plcNameBytes := payload[ctrlPLCNameOffset : ctrlPLCNameOffset+ctrlPLCNameMaxLen]
		serviceData.PLCName = extractNullTerminatedString(plcNameBytes)
	}

	return serviceData
}

// extractNullTerminatedString extracts a null-terminated ASCII string from a byte slice
func extractNullTerminatedString(b []byte) string {
	// Find null terminator
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	// No null terminator, return full string
	return string(b)
}

// generateCPE generates CPE identifier for GE PLC
func generateCPE(plcName string) []string {
	// Since GE SRTP returns program names (not hardware models), use generic CPE
	baseCPE := "cpe:2.3:h:ge:pacsystems:*:*:*:*:*:*:*:*"

	// If PLC name contains recognizable hardware identifiers, generate more specific CPE
	plcNameUpper := strings.ToUpper(plcName)
	if strings.Contains(plcNameUpper, "RX3I") {
		// More specific CPE for RX3i
		specificCPE := "cpe:2.3:h:ge:pacsystems_rx3i:*:*:*:*:*:*:*:*"
		return []string{specificCPE}
	}

	// Sanitize PLC name for CPE if it has recognizable hardware info
	// Remove non-alphanumeric except underscores, hyphens, periods
	reg := regexp.MustCompile(`[^a-z0-9_.-]`)
	sanitized := reg.ReplaceAllString(strings.ToLower(plcName), "")

	if sanitized != "" {
		// Try to identify hardware family from name patterns
		switch {
		case strings.Contains(sanitized, "series") || strings.Contains(sanitized, "90"):
			return []string{"cpe:2.3:h:ge:series_90:*:*:*:*:*:*:*:*"}
		case strings.Contains(sanitized, "versa"):
			return []string{"cpe:2.3:h:ge:versamax:*:*:*:*:*:*:*:*"}
		}
	}

	return []string{baseCPE}
}

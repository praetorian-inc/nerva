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

package s7comm

import (
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	S7COMM = "s7comm"

	// TPKT Header constants
	TPKTVersion  = 0x03
	TPKTReserved = 0x00

	// COTP PDU types
	COTPTypeConnectionRequest = 0xE0
	COTPTypeConnectionConfirm = 0xD0

	// S7comm constants
	S7ProtocolID     = 0x32
	S7FunctionSetup  = 0xF0
	S7MessageTypeJob = 0x01
	S7MessageTypeAck = 0x03

	// TSAP addressing
	TSAPSourceClient     = 0x0100
	TSAPDestRack0Slot2   = 0x0102
	TSAPDestOPConnection = 0x0200
)

type S7COMMPlugin struct{}

func init() {
	plugins.RegisterPlugin(&S7COMMPlugin{})
}

func (p *S7COMMPlugin) PortPriority(port uint16) bool {
	return port == 102
}

func (p *S7COMMPlugin) Name() string {
	return S7COMM
}

func (p *S7COMMPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *S7COMMPlugin) Priority() int {
	return 400 // ICS protocol priority (same as modbus, dnp3)
}

/*
S7comm (Siemens S7 Communication Protocol) runs over COTP (ISO 8073) which runs
over TPKT (RFC 1006) on TCP port 102.

Detection Strategy:
1. Send COTP Connection Request (CR) with TSAP addressing
2. Receive COTP Connection Confirm (CC) - confirms S7comm presence
3. (Optional) Send S7 Communication Setup for further confirmation
4. (Optional) Send SZL queries for device metadata extraction

ICS/SCADA Safety:
- Read-only detection probes (no write operations to PLC memory)
- Uses COTP handshake and SZL read queries only (non-disruptive)
- Graceful error handling (connection issues must not crash)

Testing: Use Snap7 or real Siemens PLCs for validation
*/
func (p *S7COMMPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Step 1: Send COTP Connection Request
	cotpCR := buildCOTPConnectionRequest(TSAPDestRack0Slot2)
	response, err := utils.SendRecv(conn, cotpCR, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Step 2: Validate COTP Connection Confirm
	if !validateCOTPConfirm(response) {
		// Try alternate TSAP (OP connection)
		cotpCR = buildCOTPConnectionRequest(TSAPDestOPConnection)
		response, err = utils.SendRecv(conn, cotpCR, timeout)
		if err != nil {
			return nil, err
		}
		if len(response) == 0 || !validateCOTPConfirm(response) {
			return nil, nil
		}
	}

	// At this point, COTP CC confirms S7comm presence
	serviceData := plugins.ServiceS7comm{}

	// Step 3: Send S7 Communication Setup (optional, for enhanced detection)
	s7Setup := buildS7SetupRequest()
	response, err = utils.SendRecv(conn, s7Setup, timeout)
	if err != nil {
		// S7 Setup failed, return basic detection
		return plugins.CreateServiceFrom(target, serviceData, false, "", plugins.TCP), nil
	}

	// Validate S7 Setup response
	if !validateS7SetupResponse(response) {
		// S7 Setup failed, return basic detection
		return plugins.CreateServiceFrom(target, serviceData, false, "", plugins.TCP), nil
	}

	// Step 4: (Optional) SZL queries for metadata - graceful failure
	serviceData = extractSZLMetadata(conn, timeout, serviceData)

	// Generate CPE if we have enough information
	if serviceData.PLCType != "" {
		serviceData.CPEs = generateCPEs(serviceData)
	}

	return plugins.CreateServiceFrom(target, serviceData, false, serviceData.FirmwareVersion, plugins.TCP), nil
}

// buildCOTPConnectionRequest constructs COTP CR packet with TPKT header
// TPKT Header (4 bytes) + COTP CR PDU (18 bytes) = 22 bytes total
func buildCOTPConnectionRequest(destTSAP uint16) []byte {
	// COTP CR PDU (without TPKT header)
	cotpPDU := []byte{
		0x11,                      // Header length (17 bytes follow in header)
		COTPTypeConnectionRequest, // PDU type: CR (0xE0)
		0x00, 0x00,                // Destination reference (filled by responder)
		0x00, 0x01, // Source reference
		0x00, // Class/Option: Class 0

		// Parameter: Source TSAP (0x0100 = client)
		0xC1, // Parameter code: Source TSAP
		0x02, // Parameter length
		byte(TSAPSourceClient >> 8), byte(TSAPSourceClient & 0xFF),

		// Parameter: Destination TSAP
		0xC2, // Parameter code: Destination TSAP
		0x02, // Parameter length
		byte(destTSAP >> 8), byte(destTSAP & 0xFF),

		// Parameter: TPDU Size (optional, but recommended)
		0xC0, // Parameter code: TPDU Size
		0x01, // Parameter length
		0x0A, // Size: 1024 bytes (2^10)
	}

	// Calculate total packet length
	totalLen := 4 + len(cotpPDU) // TPKT header + COTP PDU

	// TPKT Header
	tpkt := []byte{
		TPKTVersion,           // Version: 3
		TPKTReserved,          // Reserved: 0
		byte(totalLen >> 8),   // Length high byte
		byte(totalLen & 0xFF), // Length low byte
	}

	return append(tpkt, cotpPDU...)
}

// validateCOTPConfirm checks if response is valid COTP CC
func validateCOTPConfirm(response []byte) bool {
	// Minimum: TPKT(4) + COTP header length(1) + PDU type(1) = 6 bytes
	if len(response) < 6 {
		return false
	}

	// Check TPKT header
	if response[0] != TPKTVersion || response[1] != TPKTReserved {
		return false
	}

	// Check COTP PDU type (byte 5 after TPKT header)
	// TPKT(4) + Header length(1) + PDU type at offset 5
	pduTypeOffset := 5

	if len(response) <= pduTypeOffset {
		return false
	}

	pduType := response[pduTypeOffset]

	// 0xD0 = Connection Confirm
	return pduType == COTPTypeConnectionConfirm
}

// buildS7SetupRequest constructs S7 Setup Communication request
func buildS7SetupRequest() []byte {
	// S7 Communication Setup parameters
	s7Params := []byte{
		S7FunctionSetup, // Function: Setup Communication (0xF0)
		0x00,            // Reserved
		0x00, 0x01,      // Max AmQ calling (1)
		0x00, 0x01, // Max AmQ called (1)
		0x01, 0xE0, // PDU size (480 bytes = 0x01E0)
	}

	// S7 Header (10 bytes)
	s7Header := []byte{
		S7ProtocolID,                                             // Protocol ID: 0x32
		S7MessageTypeJob,                                         // Message type: Job request (0x01)
		0x00, 0x00,                                               // Reserved
		0x00, 0x00,                                               // PDU reference
		byte(len(s7Params) >> 8), byte(len(s7Params) & 0xFF), // Parameter length
		0x00, 0x00, // Data length
	}

	// COTP Data PDU (DT)
	cotpData := []byte{
		0x02, // Header length
		0xF0, // PDU type: DT (Data)
		0x80, // TPDU number + EOT flag
	}

	// Combine COTP + S7
	payload := append(cotpData, s7Header...)
	payload = append(payload, s7Params...)

	// Calculate total length
	totalLen := 4 + len(payload)

	// TPKT Header
	tpkt := []byte{
		TPKTVersion,
		TPKTReserved,
		byte(totalLen >> 8),
		byte(totalLen & 0xFF),
	}

	return append(tpkt, payload...)
}

// validateS7SetupResponse checks if response is valid S7 Setup Ack
func validateS7SetupResponse(response []byte) bool {
	// Minimum: TPKT(4) + COTP DT(3) + S7 Header(10) = 17 bytes
	if len(response) < 17 {
		return false
	}

	// Check TPKT header
	if response[0] != TPKTVersion || response[1] != TPKTReserved {
		return false
	}

	// Find S7 header (after TPKT + COTP DT)
	// TPKT(4) + COTP DT header length varies, but typically at offset 7
	s7Offset := 7 // Common offset after TPKT(4) + COTP DT(3)

	if len(response) <= s7Offset+1 {
		return false
	}

	// Check S7 Protocol ID
	if response[s7Offset] != S7ProtocolID {
		return false
	}

	// Check message type: Ack-Data (0x03)
	return response[s7Offset+1] == S7MessageTypeAck
}

// extractSZLMetadata attempts SZL queries for device info
// This function always returns serviceData (never fails completely)
func extractSZLMetadata(conn net.Conn, timeout time.Duration, serviceData plugins.ServiceS7comm) plugins.ServiceS7comm {
	// SZL 0x001C: Module identification
	szlRequest := buildSZLRequest(0x001C, 0x0000)
	response, err := utils.SendRecv(conn, szlRequest, timeout)
	if err == nil && len(response) > 0 {
		serviceData = parseSZL001CResponse(response, serviceData)
	}

	// If we got order code, detect PLC type
	if serviceData.OrderCode != "" {
		serviceData.PLCType = detectPLCType(serviceData.OrderCode)
	}

	return serviceData
}

// buildSZLRequest constructs SZL read request
func buildSZLRequest(szlID uint16, szlIndex uint16) []byte {
	// S7 UserData header for SZL request
	// This is a simplified SZL request structure
	s7Params := []byte{
		0x00, 0x01, 0x12, // Parameter header
		0x04, 0x11, // Request type
		0x44, 0x01, // Function group, subfunction
		0x00,       // Sequence number
	}

	// SZL data
	szlData := []byte{
		0xFF,       // Return code
		0x09,       // Transport size
		0x00, 0x04, // Data length
		byte(szlID >> 8), byte(szlID & 0xFF), // SZL ID
		byte(szlIndex >> 8), byte(szlIndex & 0xFF), // SZL Index
	}

	// S7 Header
	paramLen := len(s7Params)
	dataLen := len(szlData)
	s7Header := []byte{
		S7ProtocolID,            // Protocol ID: 0x32
		0x07,                    // Message type: UserData
		0x00, 0x00,              // Reserved
		0x00, 0x01,              // PDU reference
		byte(paramLen >> 8), byte(paramLen & 0xFF),
		byte(dataLen >> 8), byte(dataLen & 0xFF),
	}

	// COTP Data PDU
	cotpData := []byte{0x02, 0xF0, 0x80}

	// Combine all parts
	payload := append(cotpData, s7Header...)
	payload = append(payload, s7Params...)
	payload = append(payload, szlData...)

	totalLen := 4 + len(payload)
	tpkt := []byte{TPKTVersion, TPKTReserved, byte(totalLen >> 8), byte(totalLen & 0xFF)}

	return append(tpkt, payload...)
}

// parseSZL001CResponse extracts module info from SZL 0x001C response
func parseSZL001CResponse(response []byte, serviceData plugins.ServiceS7comm) plugins.ServiceS7comm {
	// SZL responses contain null-terminated strings at specific offsets
	// This is simplified - real implementation needs proper SZL parsing

	// Look for order code pattern: 6ES7 XXX-XXXXX-XXXX
	orderCodeRegex := regexp.MustCompile(`6ES7\s?\d{3}-\d[A-Z0-9]{4,5}-\d[A-Z0-9]{3,4}`)
	responseStr := string(response)

	if matches := orderCodeRegex.FindString(responseStr); matches != "" {
		serviceData.OrderCode = matches
	}

	// Look for firmware version pattern: V4.4.0, v.2.6.6, 4.4.0, v4.4.0
	fwVersionRegex := regexp.MustCompile(`[Vv]?\.?\d+\.\d+\.\d+`)
	if matches := fwVersionRegex.FindString(responseStr); matches != "" {
		serviceData.FirmwareVersion = matches
	}

	// Look for module name
	if idx := strings.Index(responseStr, "CPU"); idx >= 0 {
		// Extract module name (simplified)
		end := idx + 20
		if end > len(responseStr) {
			end = len(responseStr)
		}
		moduleName := strings.TrimSpace(responseStr[idx:end])
		// Clean up non-printable characters
		serviceData.ModuleName = cleanString(moduleName)
	}

	return serviceData
}

// cleanString removes non-printable characters
func cleanString(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			result.WriteRune(r)
		} else if r == 0 {
			break // Null terminator
		}
	}
	return strings.TrimSpace(result.String())
}

// detectPLCType determines PLC model from order code
func detectPLCType(orderCode string) string {
	// Order code format: 6ES7 XXX-XXXXX-XXXX
	// XXX indicates model family
	orderCode = strings.ReplaceAll(orderCode, " ", "")

	switch {
	case strings.HasPrefix(orderCode, "6ES731"):
		return "S7-300"
	case strings.HasPrefix(orderCode, "6ES741"):
		return "S7-400"
	case strings.HasPrefix(orderCode, "6ES721"):
		return "S7-1200"
	case strings.HasPrefix(orderCode, "6ES715"):
		return "S7-1500"
	default:
		return "S7"
	}
}

// generateCPEs creates CPE identifiers for the detected PLC
func generateCPEs(serviceData plugins.ServiceS7comm) []string {
	cpes := []string{}

	if serviceData.PLCType == "" {
		return cpes
	}

	// Normalize PLC type for CPE
	plcModel := strings.ToLower(strings.ReplaceAll(serviceData.PLCType, "-", "_"))

	// Version for CPE (use firmware version or wildcard)
	version := "*"
	if serviceData.FirmwareVersion != "" {
		// Clean version string (remove 'V' prefix if present)
		version = strings.TrimPrefix(serviceData.FirmwareVersion, "V")
		version = strings.TrimPrefix(version, "v")
	}

	// CPE 2.3 format: cpe:2.3:h:vendor:product:version:...
	cpe := "cpe:2.3:h:siemens:simatic_" + plcModel + ":" + version + ":*:*:*:*:*:*:*"
	cpes = append(cpes, cpe)

	return cpes
}

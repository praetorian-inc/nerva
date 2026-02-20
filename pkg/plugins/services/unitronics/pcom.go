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

/*
Package unitronics implements service detection for Unitronics PCOM protocol.

Detection Strategy:
1. Send PCOM/TCP ASCII ID command to port 20256
2. Validate response structure and protocol mode
3. Extract device model, HW version, and OS version from response
4. Map model code to known PLC model names
5. Generate CPE from normalized model and OS version

PCOM/TCP Protocol:
- 6-byte TCP header (transaction ID, mode, length)
- ASCII mode (0x65) payload with STX/ETX framing
- ID command returns model code, HW version, and OS version

Version Detection:
- Model code (6 hex chars) identifies PLC model
- OS version (major.minor.build format)
- HW version (1 hex char)

CPE Generation:
- Vendor: unitronics
- Product: Normalized model name (lowercase, underscores)
- Version: OS version in major.minor.build format
*/
package unitronics

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

// Protocol constants
const (
	PCOM                = "pcom"
	DEFAULT_PORT        = 20256
	TCP_HEADER_LENGTH   = 6
	ASCII_MODE          = 0x65
	BINARY_MODE         = 0x66
	STX_ASCII           = 0x2F // '/'
	ETX_ASCII           = 0x0D // '\r'
	RESPONSE_INDICATOR  = 0x41 // 'A'
	MIN_RESPONSE_LENGTH = 13   // 6-byte header + 7-byte minimum ASCII payload ("/A00ID" prefix)
)

// PCOMPlugin implements the Plugin interface for PCOM fingerprinting
type PCOMPlugin struct{}

// Model code to PLC model name mapping
var modelCodes = map[string]string{
	"180701": "V130-33-T38",
	"190401": "V130-33-R2",
	"1A0401": "V130-33-TR34",
	"420701": "V350-35-T38",
	"420501": "V350-35-R2",
	"700A01": "V560-T25B",
	"530901": "V570-57-T20",
	"530A01": "V570-57-T40",
	"580401": "V1040-T20B",
	"620401": "V1210-T40",
	"800401": "V700-T20BJ",
	"210401": "SM35-J-T20",
	"250501": "SM43-J-R20",
	"2A0801": "SM70-J-T20",
	"050301": "M91-2-T1",
	"040201": "M91-19-T1",
}

func init() {
	plugins.RegisterPlugin(&PCOMPlugin{})
}

// PortPriority returns true if the port is the default PCOM port (20256)
func (p *PCOMPlugin) PortPriority(port uint16) bool {
	return port == DEFAULT_PORT
}

// Name returns the protocol name for PCOM
func (p *PCOMPlugin) Name() string {
	return PCOM
}

// Type returns the protocol type (TCP)
func (p *PCOMPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the execution priority (400 = ICS/SCADA priority)
func (p *PCOMPlugin) Priority() int {
	return 400
}

// Run executes the PCOM fingerprinting logic
func (p *PCOMPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Phase 1: Detection - send ASCII ID command and validate response
	request, err := buildPCOMIDRequest()
	if err != nil {
		return nil, err
	}

	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, &utils.ServerNotEnable{}
	}

	// Phase 2: Parse and validate response
	serviceData, err := parsePCOMIDResponse(response)
	if err != nil {
		return nil, err
	}

	// Phase 3: Enrichment - map model code to name
	if modelName, ok := modelCodes[serviceData.Model]; ok {
		serviceData.Model = modelName
	}

	// Generate CPE
	if serviceData.Model != "" && serviceData.OSVersion != "" {
		cpe := generateCPE(serviceData.Model, serviceData.OSVersion)
		serviceData.CPEs = []string{cpe}
	}

	return plugins.CreateServiceFrom(target, serviceData, false, serviceData.OSVersion, plugins.TCP), nil
}

// buildPCOMIDRequest builds a PCOM/TCP ASCII ID command request
func buildPCOMIDRequest() ([]byte, error) {
	// Generate random 2-byte transaction ID
	transactionID := make([]byte, 2)
	_, err := rand.Read(transactionID)
	if err != nil {
		return nil, &utils.RandomizeError{Message: "Transaction ID"}
	}

	// ASCII ID command payload: /00IDED\r (8 bytes)
	// STX='/', Unit ID="00", Command="ID", Checksum="ED", ETX='\r'
	asciiPayload := []byte{
		STX_ASCII,      // '/'
		0x30, 0x30,     // Unit ID "00"
		0x49, 0x44,     // Command "ID"
		0x45, 0x44,     // Checksum "ED" (sum of 0x30+0x30+0x49+0x44 = 0xED)
		ETX_ASCII,      // '\r'
	}

	// Build 6-byte TCP header
	header := make([]byte, TCP_HEADER_LENGTH)
	copy(header[0:2], transactionID)
	header[2] = ASCII_MODE                                                // Protocol mode (0x65 = ASCII)
	header[3] = 0x00                                                      // Reserved
	binary.LittleEndian.PutUint16(header[4:6], uint16(len(asciiPayload))) // Data length

	// Concatenate header + payload
	return append(header, asciiPayload...), nil
}

// parsePCOMIDResponse parses a PCOM/TCP ASCII ID response
func parsePCOMIDResponse(response []byte) (plugins.ServicePCOM, error) {
	// Minimum response: 6-byte header + 7-byte ASCII prefix ("/A00ID")
	if len(response) < MIN_RESPONSE_LENGTH {
		return plugins.ServicePCOM{}, &utils.InvalidResponseErrorInfo{
			Service: PCOM,
			Info:    fmt.Sprintf("response too short: %d bytes (minimum %d)", len(response), MIN_RESPONSE_LENGTH),
		}
	}

	// Verify TCP header mode byte (ASCII mode)
	if response[2] != ASCII_MODE {
		return plugins.ServicePCOM{}, &utils.InvalidResponseErrorInfo{
			Service: PCOM,
			Info:    fmt.Sprintf("unexpected protocol mode: 0x%02x (expected 0x%02x)", response[2], ASCII_MODE),
		}
	}

	// Parse ASCII payload (starts at byte 6)
	asciiPayload := response[TCP_HEADER_LENGTH:]

	// Verify STX
	if len(asciiPayload) < 1 || asciiPayload[0] != STX_ASCII {
		return plugins.ServicePCOM{}, &utils.InvalidResponseErrorInfo{
			Service: PCOM,
			Info:    fmt.Sprintf("missing STX: 0x%02x (expected 0x%02x)", asciiPayload[0], STX_ASCII),
		}
	}

	// Verify response indicator 'A'
	if len(asciiPayload) < 2 || asciiPayload[1] != RESPONSE_INDICATOR {
		return plugins.ServicePCOM{}, &utils.InvalidResponseErrorInfo{
			Service: PCOM,
			Info:    fmt.Sprintf("missing response indicator: 0x%02x (expected 0x%02x)", asciiPayload[1], RESPONSE_INDICATOR),
		}
	}

	// Verify "ID" command echo at position [4-5]
	if len(asciiPayload) < 6 || asciiPayload[4] != 'I' || asciiPayload[5] != 'D' {
		return plugins.ServicePCOM{}, &utils.InvalidResponseErrorInfo{
			Service: PCOM,
			Info:    "missing ID command echo",
		}
	}

	// Full response format (after header):
	// /          [0]  STX
	// A          [1]  Response indicator
	// 00         [2-3] Unit ID echo
	// ID         [4-5] Command echo
	// XXXXXX     [6-11] Model code (6 hex chars)
	// X          [12] HW version (1 hex char)
	// XXX        [13-15] OS major version (3 chars)
	// XXX        [16-18] OS minor version (3 chars)
	// XX         [19-20] OS build (2 chars)
	// XX         [21-22] Response checksum
	// \r         [23] ETX

	// Minimum payload length for full parsing: 24 bytes (includes ETX)
	if len(asciiPayload) < 24 {
		return plugins.ServicePCOM{}, &utils.InvalidResponseErrorInfo{
			Service: PCOM,
			Info:    fmt.Sprintf("ASCII payload too short: %d bytes (minimum 24)", len(asciiPayload)),
		}
	}

	// Extract fields
	unitID := string(asciiPayload[2:4])
	modelCode := strings.ToUpper(string(asciiPayload[6:12]))
	hwVersion := string(asciiPayload[12:13])
	osMajor := string(asciiPayload[13:16])
	osMinor := string(asciiPayload[16:19])
	osBuild := string(asciiPayload[19:21])

	// Build OS version string
	osVersion := fmt.Sprintf("%s.%s.%s", osMajor, osMinor, osBuild)

	return plugins.ServicePCOM{
		Model:     modelCode,
		HWVersion: hwVersion,
		OSVersion: osVersion,
		UnitID:    unitID,
	}, nil
}

// generateCPE generates a CPE (Common Platform Enumeration) string for PCOM device
//
// CPE format: cpe:2.3:h:unitronics:{model}:{osVersion}:*:*:*:*:*:*:*
//
// Parameters:
//   - model: PLC model name (will be normalized)
//   - osVersion: OS version string (e.g., "003.001.00")
//
// Returns:
//   - string: CPE string
func generateCPE(model, osVersion string) string {
	// Normalize model name for CPE (lowercase, spaces→underscores, remove special chars)
	modelNorm := normalizeForCPE(model)

	// Use wildcard for unknown versions
	if osVersion == "" {
		osVersion = "*"
	}

	return fmt.Sprintf("cpe:2.3:h:unitronics:%s:%s:*:*:*:*:*:*:*", modelNorm, osVersion)
}

// normalizeForCPE normalizes a string for use in CPE
// - Converts to lowercase
// - Replaces spaces with underscores
// - Removes special characters except underscores and hyphens
func normalizeForCPE(s string) string {
	if s == "" {
		return ""
	}

	// Convert to lowercase
	s = strings.ToLower(s)

	// Replace spaces with underscores
	s = strings.ReplaceAll(s, " ", "_")

	// Remove common special characters (keep underscores and hyphens)
	s = strings.ReplaceAll(s, ".", "")
	s = strings.ReplaceAll(s, ",", "")
	s = strings.ReplaceAll(s, "'", "")

	// Remove trailing underscores
	s = strings.TrimRight(s, "_")

	return s
}

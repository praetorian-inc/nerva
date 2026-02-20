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

package sgsap

import (
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

/*
SGsAP (SGs Application Part) Protocol Fingerprinting over SCTP

SGsAP is a 3GPP protocol for the SGs interface between MME and VLR for Circuit-Switched Fallback (CSFB).
This enables LTE devices to fall back to 2G/3G circuit-switched networks for voice calls.

Protocol Specification:
  3GPP TS 29.118
  Transport: SCTP (IP protocol 132)
  Default Port: 29118
  Interface: SGs (MME to VLR for CS Fallback)

SGsAP Message Format:
  Unlike SIGTRAN protocols, SGsAP has a simpler format:
  - Byte 0: Message Type (0x00-0x1f)
  - Bytes 1+: Information Elements (TLV format)

Key Message Types:
  - 0x01: SGsAP-PAGING-REQUEST
  - 0x06: SGsAP-SERVICE-REQUEST
  - 0x09: SGsAP-LOCATION-UPDATE-REQUEST
  - 0x15: SGsAP-RESET-INDICATION
  - 0x1d: SGsAP-STATUS (used for error reporting)

Detection Strategy:
  Send SGsAP-STATUS message (0x1d) which is safe - it's used for error reporting.
  If we get any valid SGsAP response (message type 0x00-0x1f), it confirms SGsAP.

SGsAP-STATUS message format:
  - Byte 0: Message Type = 0x1d
  - Bytes 1+: SGs cause IE (mandatory)
    - IEI = 0x08 (SGs cause)
    - Length = 0x01
    - Value = 0x01 (IMSI detached for EPS services)
*/

const (
	SGSAP_SCTP             = "sgsap"
	SGSAP_PORT             = 29118
	SGSAP_STATUS_TYPE      = 0x1d // SGsAP-STATUS message
	SGSAP_MAX_MESSAGE_TYPE = 0x1f // Valid message types are 0x00-0x1f
	SGS_CAUSE_IEI          = 0x08 // SGs cause Information Element Identifier
)

type SGsAPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&SGsAPPlugin{})
}

// Run implements the main fingerprinting logic
func (p *SGsAPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Phase 1: Detection - send SGsAP-STATUS and receive response
	response, err := detectSGsAP(conn, timeout)
	if err != nil {
		return nil, err
	}

	// Phase 2: Enrichment - extract metadata from response
	messageType, sgsCause, err := enrichSGsAP(response)
	if err != nil {
		// Detection succeeded but enrichment failed - still return service
		metadata := plugins.ServiceSGsAP{
			MessageType: messageType,
		}
		return plugins.CreateServiceFrom(target, metadata, false, "", plugins.SCTP), nil
	}

	// Create service with metadata
	metadata := plugins.ServiceSGsAP{
		MessageType: messageType,
		SGsCause:    sgsCause,
	}

	return plugins.CreateServiceFrom(target, metadata, false, "", plugins.SCTP), nil
}

// PortPriority returns true if the port is 29118 (default SGsAP port)
func (p *SGsAPPlugin) PortPriority(port uint16) bool {
	return port == SGSAP_PORT
}

// Name returns the protocol name
func (p *SGsAPPlugin) Name() string {
	return SGSAP_SCTP
}

// Type returns the protocol type (SCTP)
func (p *SGsAPPlugin) Type() plugins.Protocol {
	return plugins.SCTP
}

// Priority returns the plugin execution priority
// SGsAP uses port 29118, run at same priority as other telecom protocols (60)
func (p *SGsAPPlugin) Priority() int {
	return 60
}

// detectSGsAP sends an SGsAP-STATUS message and validates the response
func detectSGsAP(conn net.Conn, timeout time.Duration) ([]byte, error) {
	// Build SGsAP-STATUS message
	statusMsg := buildSGsAPStatus()

	// Send SGsAP-STATUS
	response, err := utils.SendRecv(conn, statusMsg, timeout)
	if err != nil {
		return nil, err
	}

	// Validate response structure
	if err := validateSGsAPResponse(response); err != nil {
		return nil, err
	}

	return response, nil
}

// buildSGsAPStatus constructs an SGsAP-STATUS message
func buildSGsAPStatus() []byte {
	// SGsAP-STATUS message (4 bytes)
	msg := make([]byte, 4)

	// Byte 0: Message Type = 0x1d (SGsAP-STATUS)
	msg[0] = SGSAP_STATUS_TYPE

	// Bytes 1-3: SGs cause IE
	// IEI = 0x08 (SGs cause)
	msg[1] = SGS_CAUSE_IEI

	// Length = 0x01
	msg[2] = 0x01

	// Value = 0x01 (IMSI detached for EPS services)
	msg[3] = 0x01

	return msg
}

// validateSGsAPResponse validates the structure of an SGsAP response
func validateSGsAPResponse(response []byte) error {
	// Minimum response size: Message Type (1 byte)
	if len(response) < 1 {
		return &utils.InvalidResponseErrorInfo{
			Service: SGSAP_SCTP,
			Info:    fmt.Sprintf("response too short for valid SGsAP message: got %d bytes, need at least 1", len(response)),
		}
	}

	// Check message type (byte 0) - must be in range 0x00-0x1f
	messageType := response[0]
	if messageType > SGSAP_MAX_MESSAGE_TYPE {
		return &utils.InvalidResponseErrorInfo{
			Service: SGSAP_SCTP,
			Info:    fmt.Sprintf("invalid message type: 0x%02x, expected range 0x00-0x%02x", messageType, SGSAP_MAX_MESSAGE_TYPE),
		}
	}

	return nil
}

// enrichSGsAP extracts metadata from the response
// Returns: messageType, sgsCause, error
func enrichSGsAP(response []byte) (uint8, uint8, error) {
	if len(response) < 1 {
		return 0, 0, fmt.Errorf("response too short for enrichment")
	}

	// Extract message type from first byte
	messageType := response[0]

	// Default SGs cause to 0
	var sgsCause uint8

	// Parse optional IEs (TLV format) to extract SGs cause if present
	// IEs start at byte 1
	offset := 1
	for offset+2 <= len(response) {
		// IE Identifier (1 byte)
		iei := response[offset]

		// IE Length (1 byte)
		ieLength := response[offset+1]

		// Validate IE length
		if offset+2+int(ieLength) > len(response) {
			break
		}

		// If this is SGs cause IE, extract the value
		if iei == SGS_CAUSE_IEI && ieLength >= 1 {
			sgsCause = response[offset+2]
		}

		// Move to next IE
		offset += 2 + int(ieLength)
	}

	return messageType, sgsCause, nil
}

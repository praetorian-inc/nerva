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

package m2pa

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

/*
M2PA (MTP2 Peer Adaptation Layer) Protocol Fingerprinting over SCTP

M2PA provides MTP2 peer-to-peer signaling over SCTP/IP. Unlike M2UA (client-server
between SG and MGC), M2PA is a peer-to-peer protocol used for direct MTP2 signaling
links between Signalling Gateway Processes (SGPs). It replaces traditional TDM-based
MTP2 links with IP-based transport.

Protocol Specification:
  RFC 4165
  Transport: SCTP (IP protocol 132)
  Default Port: 3565
  SCTP PPID: 5 (IANA registered)

SIGTRAN Common Header (8 bytes):
  Byte 0: Version (always 0x01)
  Byte 1: Reserved (always 0x00)
  Byte 2: Message Class (0-14)
  Byte 3: Message Type (varies by class)
  Bytes 4-7: Message Length (big-endian, >= 8, multiple of 4)

M2PA-Specific Message Classes:
  - Class 0:  Management (MGMT) - Error, Notify (shared SIGTRAN)
  - Class 3:  ASPSM - ASP Up/Down, Heartbeat (shared SIGTRAN)
  - Class 11: M2PA Messages - User Data (Type 1), Link Status (Type 2)

M2PA-Unique Identifier: Message Class 11 - only M2PA uses this class.

Detection Strategy:
  1. Send Link Status message (Class 11, Type 2) - uniquely identifies M2PA
  2. Valid response: Link Status (Class 11, Type 2) or Error (Class 0, Type 0)
  3. Extract link state from response payload

Link Status Message Body (after 8-byte header):
  Bytes 0-3:  Unused (1) + BSN (3) - Backward Sequence Number
  Bytes 4-7:  Unused (1) + FSN (3) - Forward Sequence Number
  Bytes 8-11: Link Status (4 bytes)

Link Status Values:
  1 = Alignment
  2 = Proving Normal
  3 = Proving Emergency
  4 = Ready
  5 = Processor Outage
  6 = Processor Recovered
  7 = Busy
  8 = Busy Ended

Protocol Differentiation:
  M3UA: Port 2905, PPID 3, Class 1 (Transfer)
  M2UA: Port 2904, PPID 2, Class 6 (MAUP)
  M2PA: Port 3565, PPID 5, Class 11 (M2PA Messages)
*/

const (
	M2PA_SCTP          = "m2pa"
	M2PA_PORT          = 3565
	M2PA_VERSION       = 1
	M2PA_MSG_CLASS     = 0x0B // M2PA Messages (Class 11)
	M2PA_LINK_STATUS   = 0x02 // Link Status message type
	M2PA_USER_DATA     = 0x01 // User Data message type
	MGMT_CLASS         = 0x00 // Management messages
	ERROR_TYPE         = 0x00 // Error message
	HEADER_LENGTH      = 8
	LINK_STATUS_LENGTH = 20 // Header (8) + BSN (4) + FSN (4) + Link Status (4)
)

// Link state values from RFC 4165 Section 3.3.1
const (
	LinkStateAlignment        = 1
	LinkStateProvingNormal    = 2
	LinkStateProvingEmergency = 3
	LinkStateReady            = 4
	LinkStateProcessorOutage  = 5
	LinkStateProcessorRecov   = 6
	LinkStateBusy             = 7
	LinkStateBusyEnded        = 8
)

type M2PAPlugin struct{}

func init() {
	plugins.RegisterPlugin(&M2PAPlugin{})
}

// Run implements the main fingerprinting logic
func (p *M2PAPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Phase 1: Detection - send Link Status and validate response
	response, err := detectM2PA(conn, timeout)
	if err != nil {
		return nil, err
	}

	// Phase 2: Enrichment - extract metadata from response
	messageClass, messageType, linkState, errorCode, infoString, err := enrichM2PA(response)
	if err != nil {
		// Detection succeeded but enrichment failed - still return service
		metadata := ServiceM2PA{
			MessageClass: messageClass,
			MessageType:  messageType,
		}
		return plugins.CreateServiceFrom(target, metadata, false, "", plugins.SCTP), nil
	}

	// Create service with metadata
	metadata := ServiceM2PA{
		MessageClass:  messageClass,
		MessageType:   messageType,
		LinkState:     linkState,
		LinkStateName: linkStateName(linkState),
		ErrorCode:     errorCode,
		InfoString:    infoString,
	}

	return plugins.CreateServiceFrom(target, metadata, false, "", plugins.SCTP), nil
}

// PortPriority returns true if the port is 3565 (default M2PA port)
func (p *M2PAPlugin) PortPriority(port uint16) bool {
	return port == M2PA_PORT
}

// Name returns the protocol name
func (p *M2PAPlugin) Name() string {
	return M2PA_SCTP
}

// Type returns the protocol type (SCTP)
func (p *M2PAPlugin) Type() plugins.Protocol {
	return plugins.SCTP
}

// Priority returns the plugin execution priority
func (p *M2PAPlugin) Priority() int {
	return 60
}

// detectM2PA sends a Link Status message and validates the response
func detectM2PA(conn net.Conn, timeout time.Duration) ([]byte, error) {
	linkStatus := buildLinkStatus()

	response, err := utils.SendRecv(conn, linkStatus, timeout)
	if err != nil {
		return nil, err
	}

	if err := validateResponse(response); err != nil {
		return nil, err
	}

	return response, nil
}

// buildLinkStatus constructs an M2PA Link Status message (Class 11, Type 2)
func buildLinkStatus() []byte {
	msg := make([]byte, LINK_STATUS_LENGTH)

	// SIGTRAN Common Header
	msg[0] = M2PA_VERSION     // Version = 1
	msg[1] = 0x00             // Reserved = 0
	msg[2] = M2PA_MSG_CLASS   // Message Class = 11 (M2PA Messages)
	msg[3] = M2PA_LINK_STATUS // Message Type = 2 (Link Status)

	// Message Length = 20 (header + BSN + FSN + link status)
	binary.BigEndian.PutUint32(msg[4:8], LINK_STATUS_LENGTH)

	// BSN field: Unused (1 byte) + BSN (3 bytes) = 0
	// FSN field: Unused (1 byte) + FSN (3 bytes) = 0
	// (already zeroed by make)

	// Link Status = 1 (Alignment - initial state, safe probe)
	binary.BigEndian.PutUint32(msg[16:20], LinkStateAlignment)

	return msg
}

// validateResponse validates the structure of a response to our Link Status probe
func validateResponse(response []byte) error {
	if len(response) < HEADER_LENGTH {
		return &utils.InvalidResponseErrorInfo{
			Service: M2PA_SCTP,
			Info:    fmt.Sprintf("response too short for valid M2PA message: got %d bytes, need %d", len(response), HEADER_LENGTH),
		}
	}

	// Check version (byte 0)
	if response[0] != M2PA_VERSION {
		return &utils.InvalidResponseErrorInfo{
			Service: M2PA_SCTP,
			Info:    fmt.Sprintf("invalid version: %d, expected %d", response[0], M2PA_VERSION),
		}
	}

	// Check reserved byte (byte 1)
	if response[1] != 0x00 {
		return &utils.InvalidResponseErrorInfo{
			Service: M2PA_SCTP,
			Info:    fmt.Sprintf("invalid reserved byte: 0x%02x, expected 0x00", response[1]),
		}
	}

	// Check message class (byte 2) - should be M2PA (11) or MGMT (0)
	messageClass := response[2]
	if messageClass != M2PA_MSG_CLASS && messageClass != MGMT_CLASS {
		return &utils.InvalidResponseErrorInfo{
			Service: M2PA_SCTP,
			Info:    fmt.Sprintf("invalid message class: 0x%02x, expected 0x%02x (M2PA) or 0x%02x (MGMT)", messageClass, M2PA_MSG_CLASS, MGMT_CLASS),
		}
	}

	// Check message type (byte 3)
	messageType := response[3]
	if messageClass == M2PA_MSG_CLASS && messageType != M2PA_LINK_STATUS && messageType != M2PA_USER_DATA {
		return &utils.InvalidResponseErrorInfo{
			Service: M2PA_SCTP,
			Info:    fmt.Sprintf("invalid M2PA message type: 0x%02x, expected 0x%02x (Link Status) or 0x%02x (User Data)", messageType, M2PA_LINK_STATUS, M2PA_USER_DATA),
		}
	}
	if messageClass == MGMT_CLASS && messageType != ERROR_TYPE {
		return &utils.InvalidResponseErrorInfo{
			Service: M2PA_SCTP,
			Info:    fmt.Sprintf("invalid MGMT message type: 0x%02x, expected 0x%02x (Error)", messageType, ERROR_TYPE),
		}
	}

	// Check message length (bytes 4-7)
	// Use uint32 comparison to avoid integer overflow on 32-bit systems (CWE-190)
	msgLength := binary.BigEndian.Uint32(response[4:8])
	if msgLength > uint32(len(response)) {
		return &utils.InvalidResponseErrorInfo{
			Service: M2PA_SCTP,
			Info:    fmt.Sprintf("incomplete response: got %d bytes, expected %d", len(response), msgLength),
		}
	}

	if msgLength < HEADER_LENGTH {
		return &utils.InvalidResponseErrorInfo{
			Service: M2PA_SCTP,
			Info:    fmt.Sprintf("invalid message length: %d, must be >= %d", msgLength, HEADER_LENGTH),
		}
	}

	if msgLength%4 != 0 {
		return &utils.InvalidResponseErrorInfo{
			Service: M2PA_SCTP,
			Info:    fmt.Sprintf("invalid message length: %d, must be multiple of 4", msgLength),
		}
	}

	return nil
}

// enrichM2PA extracts metadata from the response
// Returns: messageClass, messageType, linkState, errorCode, infoString, error
func enrichM2PA(response []byte) (uint8, uint8, uint32, uint32, string, error) {
	if len(response) < HEADER_LENGTH {
		return 0, 0, 0, 0, "", fmt.Errorf("response too short for enrichment")
	}

	messageClass := response[2]
	messageType := response[3]
	msgLength := binary.BigEndian.Uint32(response[4:8])

	// M2PA Link Status response: extract link state from payload
	if messageClass == M2PA_MSG_CLASS && messageType == M2PA_LINK_STATUS {
		var linkState uint32
		// Link Status payload: BSN (4) + FSN (4) + Link Status (4) = 12 bytes after header
		if msgLength >= LINK_STATUS_LENGTH && len(response) >= LINK_STATUS_LENGTH {
			linkState = binary.BigEndian.Uint32(response[16:20])
		}
		return messageClass, messageType, linkState, 0, "", nil
	}

	// MGMT Error response: parse TLV parameters for error code and info string
	if messageClass == MGMT_CLASS {
		errorCode, infoString := parseTLVParams(response, msgLength)
		return messageClass, messageType, 0, errorCode, infoString, nil
	}

	// M2PA User Data response (unexpected but valid)
	return messageClass, messageType, 0, 0, "", nil
}

// parseTLVParams extracts error code and info string from TLV parameters
func parseTLVParams(response []byte, msgLength uint32) (uint32, string) {
	if msgLength == HEADER_LENGTH {
		return 0, ""
	}

	var errorCode uint32
	var infoString string

	offset := HEADER_LENGTH
	for offset+4 <= int(msgLength) {
		paramTag := binary.BigEndian.Uint16(response[offset : offset+2])
		paramLength := binary.BigEndian.Uint16(response[offset+2 : offset+4])

		if paramLength < 4 || offset+int(paramLength) > int(msgLength) {
			break
		}

		valueLength := int(paramLength) - 4
		if offset+4+valueLength > len(response) {
			break
		}

		value := response[offset+4 : offset+4+valueLength]

		switch paramTag {
		case 0x0004: // Info String
			infoString = string(value)
		case 0x000c: // Error Code
			if len(value) >= 4 {
				errorCode = binary.BigEndian.Uint32(value)
			}
		}

		// Parameters are padded to 4-byte boundary
		paddedLength := paramLength
		if paramLength%4 != 0 {
			paddedLength += 4 - (paramLength % 4)
		}
		offset += int(paddedLength)
	}

	return errorCode, infoString
}

// linkStateName returns a human-readable name for the link state value
func linkStateName(state uint32) string {
	switch state {
	case LinkStateAlignment:
		return "Alignment"
	case LinkStateProvingNormal:
		return "Proving Normal"
	case LinkStateProvingEmergency:
		return "Proving Emergency"
	case LinkStateReady:
		return "Ready"
	case LinkStateProcessorOutage:
		return "Processor Outage"
	case LinkStateProcessorRecov:
		return "Processor Recovered"
	case LinkStateBusy:
		return "Busy"
	case LinkStateBusyEnded:
		return "Busy Ended"
	default:
		return ""
	}
}

// ServiceM2PA contains metadata for M2PA services over SCTP transport
type ServiceM2PA struct {
	LinkState     uint32 `json:"linkState,omitempty"`
	LinkStateName string `json:"linkStateName,omitempty"`
	InfoString    string `json:"infoString,omitempty"`
	ErrorCode     uint32 `json:"errorCode,omitempty"`
	MessageClass  uint8  `json:"messageClass,omitempty"`
	MessageType   uint8  `json:"messageType,omitempty"`
}

// Type implements the Metadata interface
func (s ServiceM2PA) Type() string {
	return M2PA_SCTP
}

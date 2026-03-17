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

package m2ua

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

/*
M2UA (MTP2 User Adaptation Layer) Protocol Fingerprinting over SCTP

M2UA is part of the SIGTRAN protocol suite for transporting MTP2 user signaling
over IP using SCTP. It enables SS7 links to be transported over IP networks.

Protocol Specification:
  RFC 3331
  Transport: SCTP (IP protocol 132)
  Default Port: 2904
  SCTP PPID: 2

SIGTRAN Common Header (8 bytes):
  Byte 0: Version (always 0x01)
  Byte 1: Reserved (always 0x00)
  Byte 2: Message Class (0-14)
  Byte 3: Message Type (varies by class)
  Bytes 4-7: Message Length (big-endian, >= 8, multiple of 4)

M2UA-Specific Message Classes:
  - Class 0: Management (MGMT) - Error, Notify
  - Class 3: ASPSM - ASP Up/Down, Heartbeat (all SIGTRAN)
  - Class 4: ASPTM - ASP Active/Inactive (all SIGTRAN)
  - Class 6: MAUP - MTP2 User Adaptation - unique to M2UA

Detection Strategy:
  1. Send ASP Up message (SIGTRAN Common Header, 8 bytes)
  2. Valid responses:
     - ASP Up Ack: Class 0x03, Type 0x04
     - Error: Class 0x00, Type 0x00
     - MAUP: Class 0x06 (M2UA-unique, any type)

Active Probing (ASP Up):
  Version:       0x01
  Reserved:      0x00
  Message Class: 0x03 (ASPSM)
  Message Type:  0x01 (ASP Up)
  Length:        0x00000008
*/

const (
	M2UA_SCTP     = "m2ua"
	M2UA_PORT     = 2904
	M2UA_VERSION  = 1
	ASPSM_CLASS   = 0x03 // ASP State Maintenance
	ASP_UP_TYPE   = 0x01 // ASP Up message
	ASP_UP_ACK    = 0x04 // ASP Up Ack message
	MGMT_CLASS    = 0x00 // Management messages
	ERROR_TYPE    = 0x00 // Error message
	MAUP_CLASS    = 0x06 // MTP2 User Adaptation - M2UA-unique
	HEADER_LENGTH = 8
)

type M2UAPlugin struct{}

func init() {
	plugins.RegisterPlugin(&M2UAPlugin{})
}

// Run implements the main fingerprinting logic
func (p *M2UAPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Phase 1: Detection - send ASP Up and receive ASP Up Ack, Error, or MAUP
	response, err := detectM2UA(conn, timeout)
	if err != nil {
		return nil, err
	}

	// Phase 2: Enrichment - extract metadata from response
	messageClass, messageType, errorCode, infoString, err := enrichM2UA(response)
	if err != nil {
		// Detection succeeded but enrichment failed - still return service
		metadata := plugins.ServiceM2UA{
			MessageClass: messageClass,
			MessageType:  messageType,
		}
		return plugins.CreateServiceFrom(target, metadata, false, "", plugins.SCTP), nil
	}

	// Create service with metadata
	metadata := plugins.ServiceM2UA{
		MessageClass: messageClass,
		MessageType:  messageType,
		ErrorCode:    errorCode,
		InfoString:   infoString,
	}

	return plugins.CreateServiceFrom(target, metadata, false, "", plugins.SCTP), nil
}

// PortPriority returns true if the port is 2904 (default M2UA port)
func (p *M2UAPlugin) PortPriority(port uint16) bool {
	return port == M2UA_PORT
}

// Name returns the protocol name
func (p *M2UAPlugin) Name() string {
	return M2UA_SCTP
}

// Type returns the protocol type (SCTP)
func (p *M2UAPlugin) Type() plugins.Protocol {
	return plugins.SCTP
}

// Priority returns the plugin execution priority
// M2UA uses port 2904, run at same priority as M3UA and Diameter SCTP (60)
func (p *M2UAPlugin) Priority() int {
	return 60
}

// detectM2UA sends an ASP Up message and validates the response
func detectM2UA(conn net.Conn, timeout time.Duration) ([]byte, error) {
	// Build ASP Up message
	aspUp := buildASPUp()

	// Send ASP Up
	response, err := utils.SendRecv(conn, aspUp, timeout)
	if err != nil {
		return nil, err
	}

	// Validate response structure
	if err := validateResponse(response); err != nil {
		return nil, err
	}

	return response, nil
}

// buildASPUp constructs an ASP Up message
func buildASPUp() []byte {
	// SIGTRAN Common Header (8 bytes)
	header := make([]byte, HEADER_LENGTH)

	// Version = 1
	header[0] = M2UA_VERSION

	// Reserved = 0
	header[1] = 0x00

	// Message Class = 3 (ASPSM)
	header[2] = ASPSM_CLASS

	// Message Type = 1 (ASP Up)
	header[3] = ASP_UP_TYPE

	// Message Length = 8 (header only, no parameters)
	binary.BigEndian.PutUint32(header[4:8], HEADER_LENGTH)

	return header
}

// validateResponse validates the structure of an ASP Up Ack, Error, or MAUP response.
// M2UA accepts MAUP class (0x06) responses which are unique to M2UA.
func validateResponse(response []byte) error {
	// Minimum response size: Header (8 bytes)
	if len(response) < HEADER_LENGTH {
		return &utils.InvalidResponseErrorInfo{
			Service: M2UA_SCTP,
			Info:    fmt.Sprintf("response too short for valid M2UA message: got %d bytes, need %d", len(response), HEADER_LENGTH),
		}
	}

	// Check version (byte 0)
	if response[0] != M2UA_VERSION {
		return &utils.InvalidResponseErrorInfo{
			Service: M2UA_SCTP,
			Info:    fmt.Sprintf("invalid version: %d, expected %d", response[0], M2UA_VERSION),
		}
	}

	// Check reserved byte (byte 1)
	if response[1] != 0x00 {
		return &utils.InvalidResponseErrorInfo{
			Service: M2UA_SCTP,
			Info:    fmt.Sprintf("invalid reserved byte: 0x%02x, expected 0x00", response[1]),
		}
	}

	// Check message class (byte 2) - should be ASPSM (3), MGMT (0), or MAUP (6)
	// MAUP class (0x06) is unique to M2UA and definitively identifies this protocol
	messageClass := response[2]
	if messageClass != ASPSM_CLASS && messageClass != MGMT_CLASS && messageClass != MAUP_CLASS {
		return &utils.InvalidResponseErrorInfo{
			Service: M2UA_SCTP,
			Info:    fmt.Sprintf("invalid message class: 0x%02x, expected 0x%02x (ASPSM), 0x%02x (MGMT), or 0x%02x (MAUP)", messageClass, ASPSM_CLASS, MGMT_CLASS, MAUP_CLASS),
		}
	}

	// Check message type (byte 3) for ASPSM and MGMT classes
	messageType := response[3]
	if messageClass == ASPSM_CLASS && messageType != ASP_UP_ACK {
		return &utils.InvalidResponseErrorInfo{
			Service: M2UA_SCTP,
			Info:    fmt.Sprintf("invalid ASPSM message type: 0x%02x, expected 0x%02x (ASP Up Ack)", messageType, ASP_UP_ACK),
		}
	}
	if messageClass == MGMT_CLASS && messageType != ERROR_TYPE {
		return &utils.InvalidResponseErrorInfo{
			Service: M2UA_SCTP,
			Info:    fmt.Sprintf("invalid MGMT message type: 0x%02x, expected 0x%02x (Error)", messageType, ERROR_TYPE),
		}
	}
	// MAUP class accepts any message type - no type check needed

	// Check message length (bytes 4-7)
	// Use uint32 comparison to avoid integer overflow on 32-bit systems (CWE-190)
	msgLength := binary.BigEndian.Uint32(response[4:8])
	if msgLength > uint32(len(response)) {
		return &utils.InvalidResponseErrorInfo{
			Service: M2UA_SCTP,
			Info:    fmt.Sprintf("incomplete response: got %d bytes, expected %d", len(response), msgLength),
		}
	}

	// Validate length is >= header size and multiple of 4
	if msgLength < HEADER_LENGTH {
		return &utils.InvalidResponseErrorInfo{
			Service: M2UA_SCTP,
			Info:    fmt.Sprintf("invalid message length: %d, must be >= %d", msgLength, HEADER_LENGTH),
		}
	}

	if msgLength%4 != 0 {
		return &utils.InvalidResponseErrorInfo{
			Service: M2UA_SCTP,
			Info:    fmt.Sprintf("invalid message length: %d, must be multiple of 4", msgLength),
		}
	}

	return nil
}

// enrichM2UA extracts metadata from the response
// Returns: messageClass, messageType, errorCode, infoString, error
func enrichM2UA(response []byte) (uint8, uint8, uint32, string, error) {
	if len(response) < HEADER_LENGTH {
		return 0, 0, 0, "", fmt.Errorf("response too short for enrichment")
	}

	// Extract message class and type from header
	messageClass := response[2]
	messageType := response[3]

	// If this is just a header-only message with no parameters, return basic metadata
	msgLength := binary.BigEndian.Uint32(response[4:8])
	if msgLength == HEADER_LENGTH {
		return messageClass, messageType, 0, "", nil
	}

	// Parse optional parameters (TLV format)
	// Extract Info String (Tag 0x0004) and Error Code (Tag 0x000c) if present

	var errorCode uint32
	var infoString string

	// Parse parameters starting after header
	offset := HEADER_LENGTH
	for offset+4 <= int(msgLength) {
		// Parameter Tag (2 bytes)
		paramTag := binary.BigEndian.Uint16(response[offset : offset+2])

		// Parameter Length (2 bytes) - includes tag and length fields
		paramLength := binary.BigEndian.Uint16(response[offset+2 : offset+4])

		// Validate parameter length
		if paramLength < 4 || offset+int(paramLength) > int(msgLength) {
			break
		}

		// Extract parameter value
		valueLength := int(paramLength) - 4
		if offset+4+valueLength > len(response) {
			break
		}

		value := response[offset+4 : offset+4+valueLength]

		// Process specific parameter types
		switch paramTag {
		case 0x0004: // Info String
			infoString = string(value)

		case 0x000c: // Error Code
			if len(value) >= 4 {
				errorCode = binary.BigEndian.Uint32(value)
			}
		}

		// Move to next parameter (parameters are padded to 4-byte boundary)
		paddedLength := paramLength
		if paramLength%4 != 0 {
			paddedLength += 4 - (paramLength % 4)
		}
		offset += int(paddedLength)
	}

	return messageClass, messageType, errorCode, infoString, nil
}

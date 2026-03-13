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

package iua

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

/*
IUA (ISDN User Adaptation Layer) Protocol Fingerprinting over SCTP

IUA is part of the SIGTRAN protocol suite for transporting ISDN signaling over IP using SCTP.
This is a CRITICAL protocol for telecom security reconnaissance.

Protocol Specification:
  RFC 4233 (obsoletes RFC 3057)
  Transport: SCTP (IP protocol 132)
  Default Port: 9900
  SCTP PPID: 1 (first SIGTRAN PPID assigned)

SIGTRAN Common Header (8 bytes):
  Byte 0: Version (always 0x01)
  Byte 1: Reserved (always 0x00)
  Byte 2: Message Class (0-14)
  Byte 3: Message Type (varies by class)
  Bytes 4-7: Message Length (big-endian, >= 8, multiple of 4)

IUA-Specific Message Classes:
  - Class 0: Management (MGMT) - Error, Notify
  - Class 3: ASPSM - ASP Up/Down, Heartbeat (all SIGTRAN)
  - Class 4: ASPTM - ASP Active/Inactive (all SIGTRAN)
  - Class 5: QPTM - Q.921/Q.931 Boundary Primitives Transport Messages (IUA-SPECIFIC)

Detection Strategy:
  1. Primary: Check SCTP PPID = 1 (definitive)
  2. Fallback: Port 9900 when PPID = 0 (misconfiguration)
  3. Validation: Header bytes 0-1 = 0x01 0x00

Active Probing (ASP Up):
  Version:       0x01
  Reserved:      0x00
  Message Class: 0x03 (ASPSM)
  Message Type:  0x01 (ASP Up)
  Length:        0x00000008

Expected Response:
  ASP Up Ack (Class 3, Type 4), Error (Class 0, Type 0), or QPTM (Class 5)
*/

const (
	IUA_SCTP      = "iua"
	IUA_PORT      = 9900
	IUA_VERSION   = 1
	ASPSM_CLASS   = 0x03 // ASP State Maintenance
	ASP_UP_TYPE   = 0x01 // ASP Up message
	ASP_UP_ACK    = 0x04 // ASP Up Ack message
	MGMT_CLASS    = 0x00 // Management messages
	ERROR_TYPE    = 0x00 // Error message
	QPTM_CLASS    = 0x05 // Q.921/Q.931 Boundary Primitives Transport (IUA-specific)
	HEADER_LENGTH = 8
)

type IUAPlugin struct{}

func init() {
	plugins.RegisterPlugin(&IUAPlugin{})
}

// Run implements the main fingerprinting logic
func (p *IUAPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Phase 1: Detection - send ASP Up and receive ASP Up Ack or Error
	response, err := detectIUA(conn, timeout)
	if err != nil {
		return nil, err
	}

	// Phase 2: Enrichment - extract metadata from response
	messageClass, messageType, errorCode, infoString, err := enrichIUA(response)
	if err != nil {
		// Detection succeeded but enrichment failed - still return service
		metadata := ServiceIUA{
			MessageClass: messageClass,
			MessageType:  messageType,
		}
		return plugins.CreateServiceFrom(target, metadata, false, "", plugins.SCTP), nil
	}

	// Create service with metadata
	metadata := ServiceIUA{
		MessageClass: messageClass,
		MessageType:  messageType,
		ErrorCode:    errorCode,
		InfoString:   infoString,
	}

	return plugins.CreateServiceFrom(target, metadata, false, "", plugins.SCTP), nil
}

// PortPriority returns true if the port is 9900 (default IUA port)
func (p *IUAPlugin) PortPriority(port uint16) bool {
	return port == IUA_PORT
}

// Name returns the protocol name
func (p *IUAPlugin) Name() string {
	return IUA_SCTP
}

// Type returns the protocol type (SCTP)
func (p *IUAPlugin) Type() plugins.Protocol {
	return plugins.SCTP
}

// Priority returns the plugin execution priority
// IUA uses port 9900, run at same priority as Diameter and M3UA (60)
func (p *IUAPlugin) Priority() int {
	return 60
}

// detectIUA sends an ASP Up message and validates the response
func detectIUA(conn net.Conn, timeout time.Duration) ([]byte, error) {
	// Build ASP Up message
	aspUp := buildASPUp()

	// Send ASP Up
	response, err := utils.SendRecv(conn, aspUp, timeout)
	if err != nil {
		return nil, err
	}

	// Validate response structure
	if err := validateASPUpAck(response); err != nil {
		return nil, err
	}

	return response, nil
}

// buildASPUp constructs an ASP Up message
func buildASPUp() []byte {
	// SIGTRAN Common Header (8 bytes)
	header := make([]byte, HEADER_LENGTH)

	// Version = 1
	header[0] = IUA_VERSION

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

// validateASPUpAck validates the structure of an ASP Up Ack, Error, or QPTM response
func validateASPUpAck(response []byte) error {
	// Minimum response size: Header (8 bytes)
	if len(response) < HEADER_LENGTH {
		return &utils.InvalidResponseErrorInfo{
			Service: IUA_SCTP,
			Info:    fmt.Sprintf("response too short for valid IUA message: got %d bytes, need %d", len(response), HEADER_LENGTH),
		}
	}

	// Check version (byte 0)
	if response[0] != IUA_VERSION {
		return &utils.InvalidResponseErrorInfo{
			Service: IUA_SCTP,
			Info:    fmt.Sprintf("invalid version: %d, expected %d", response[0], IUA_VERSION),
		}
	}

	// Check reserved byte (byte 1)
	if response[1] != 0x00 {
		return &utils.InvalidResponseErrorInfo{
			Service: IUA_SCTP,
			Info:    fmt.Sprintf("invalid reserved byte: 0x%02x, expected 0x00", response[1]),
		}
	}

	// Check message class (byte 2) - should be ASPSM (3), MGMT (0), or QPTM (5)
	messageClass := response[2]
	if messageClass != ASPSM_CLASS && messageClass != MGMT_CLASS && messageClass != QPTM_CLASS {
		return &utils.InvalidResponseErrorInfo{
			Service: IUA_SCTP,
			Info:    fmt.Sprintf("invalid message class: 0x%02x, expected 0x%02x (ASPSM), 0x%02x (MGMT), or 0x%02x (QPTM)", messageClass, ASPSM_CLASS, MGMT_CLASS, QPTM_CLASS),
		}
	}

	// Check message type (byte 3)
	messageType := response[3]
	if messageClass == ASPSM_CLASS && messageType != ASP_UP_ACK {
		return &utils.InvalidResponseErrorInfo{
			Service: IUA_SCTP,
			Info:    fmt.Sprintf("invalid ASPSM message type: 0x%02x, expected 0x%02x (ASP Up Ack)", messageType, ASP_UP_ACK),
		}
	}
	if messageClass == MGMT_CLASS && messageType != ERROR_TYPE {
		return &utils.InvalidResponseErrorInfo{
			Service: IUA_SCTP,
			Info:    fmt.Sprintf("invalid MGMT message type: 0x%02x, expected 0x%02x (Error)", messageType, ERROR_TYPE),
		}
	}
	// QPTM class (5) can have various message types - we accept any for detection

	// Check message length (bytes 4-7)
	// Use uint32 comparison to avoid integer overflow on 32-bit systems (CWE-190)
	msgLength := binary.BigEndian.Uint32(response[4:8])
	if msgLength > uint32(len(response)) {
		return &utils.InvalidResponseErrorInfo{
			Service: IUA_SCTP,
			Info:    fmt.Sprintf("incomplete response: got %d bytes, expected %d", len(response), msgLength),
		}
	}

	// Validate length is >= header size and multiple of 4
	if msgLength < HEADER_LENGTH {
		return &utils.InvalidResponseErrorInfo{
			Service: IUA_SCTP,
			Info:    fmt.Sprintf("invalid message length: %d, must be >= %d", msgLength, HEADER_LENGTH),
		}
	}

	if msgLength%4 != 0 {
		return &utils.InvalidResponseErrorInfo{
			Service: IUA_SCTP,
			Info:    fmt.Sprintf("invalid message length: %d, must be multiple of 4", msgLength),
		}
	}

	return nil
}

// enrichIUA extracts metadata from the response
// Returns: messageClass, messageType, errorCode, infoString, error
func enrichIUA(response []byte) (uint8, uint8, uint32, string, error) {
	if len(response) < HEADER_LENGTH {
		return 0, 0, 0, "", fmt.Errorf("response too short for enrichment")
	}

	// Extract message class and type from header
	messageClass := response[2]
	messageType := response[3]

	// If this is just an ASP Up Ack with no parameters, return basic metadata
	msgLength := binary.BigEndian.Uint32(response[4:8])
	if msgLength == HEADER_LENGTH {
		return messageClass, messageType, 0, "", nil
	}

	// Parse optional parameters (TLV format)
	// For now, we extract Info String (Tag 0x0004) and Error Code (Tag 0x000c) if present
	// This is a simplified implementation - full implementation would parse all parameter types

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

// ServiceIUA contains metadata for IUA services over SCTP transport
type ServiceIUA struct {
	InfoString   string `json:"info_string,omitempty"`
	ErrorCode    uint32 `json:"error_code,omitempty"`
	MessageClass uint8  `json:"message_class,omitempty"`
	MessageType  uint8  `json:"message_type,omitempty"`
}

// Type implements the Metadata interface
func (s ServiceIUA) Type() string {
	return IUA_SCTP
}

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

package hartip

import (
	"crypto/rand"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	HARTIPVersion          = 0x01
	HARTIPMsgTypeRequest   = 0x00
	HARTIPMsgTypeResponse  = 0x01
	HARTIPMsgTypePublish   = 0x02
	HARTIPMsgTypeError     = 0x03
	HARTIPMsgTypeNAK       = 0x0F
	HARTIPMsgIDSessionInit = 0x00
	HARTIPHeaderLength     = 8
	HARTIPMinLength        = 8 // Minimum valid response length
)

type HARTIPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&HARTIPPlugin{})
}

const HARTIP = "hartip"

func (p *HARTIPPlugin) PortPriority(port uint16) bool {
	return port == 5094
}

// Run
/*
   HART-IP (Highway Addressable Remote Transducer over IP) is a protocol
   used for communication with HART-enabled field devices in industrial
   process control environments.

   HART-IP runs over TCP on port 5094 by default. All HART-IP messages
   follow a consistent header format:
   - Version (1 byte): Protocol version (0x01)
   - Message Type (1 byte): Request/Response/Publish/Error/NAK
   - Message ID (1 byte): Session Initiate/Close/KeepAlive/PassThrough
   - Status (1 byte): Status code
   - Transaction ID (2 bytes): Client-generated identifier
   - Length (2 bytes): Total packet length

   This implementation uses Session Initiate (Message ID 0x00) which is
   a safe, read-only handshake that:
   - Only initiates a session
   - Does NOT modify any data
   - Does NOT trigger control operations
   - Safe for ICS/SCADA environments

   Session Initiate body contains:
   - Master Type (1 byte): Always 0x01
   - Inactivity Close Time (4 bytes): Timeout in milliseconds

   Detection validates:
   - HART-IP version byte (0x01)
   - Transaction ID echo
   - Valid message type (Response/Error/NAK all indicate HART-IP)
*/
func (p *HARTIPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	probe := buildSessionInitiateProbe()

	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Validate HART-IP response
	if !isValidHARTIPResponse(response, probe) {
		return nil, nil
	}

	// Parse response metadata
	version, messageType, status, statusDesc, transactionID := parseHARTIPResponse(response)

	// Create service metadata
	service := plugins.ServiceHARTIP{
		Version:       version,
		MessageType:   messageType,
		Status:        status,
		StatusDesc:    statusDesc,
		TransactionID: transactionID,
	}

	return plugins.CreateServiceFrom(target, service, false, "", plugins.TCP), nil
}

func (p *HARTIPPlugin) Name() string {
	return HARTIP
}

func (p *HARTIPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *HARTIPPlugin) Priority() int {
	return 400 // Same priority as other ICS protocols (Modbus, DNP3)
}

// buildSessionInitiateProbe creates a HART-IP Session Initiate request
func buildSessionInitiateProbe() []byte {
	// Generate random transaction ID (2 bytes)
	txID := make([]byte, 2)
	_, err := rand.Read(txID)
	if err != nil {
		// Fallback to a fixed transaction ID if randomization fails
		txID = []byte{0x00, 0x01}
	}

	// Build Session Initiate packet
	// Header (8 bytes) + Body (5 bytes) = 13 bytes total
	probe := []byte{
		HARTIPVersion,          // Byte 0: Version (0x01)
		HARTIPMsgTypeRequest,   // Byte 1: Message Type (0x00 = Request)
		HARTIPMsgIDSessionInit, // Byte 2: Message ID (0x00 = Session Initiate)
		0x00,                   // Byte 3: Status (0x00)
		txID[0], txID[1],       // Bytes 4-5: Transaction ID (random)
		0x00, 0x0D,             // Bytes 6-7: Length (13 bytes total)
		0x01,                   // Byte 8: Master Type (0x01)
		0x00, 0x00, 0xEA, 0x60, // Bytes 9-12: Inactivity Close Time (60000 ms = 60 seconds)
	}

	return probe
}

// isValidHARTIPResponse validates the HART-IP response structure
func isValidHARTIPResponse(response []byte, probe []byte) bool {
	// Check minimum length
	if len(response) < HARTIPMinLength {
		return false
	}

	// Check version byte
	if response[0] != HARTIPVersion {
		return false
	}

	// Check transaction ID matches probe
	if len(probe) >= 6 {
		if response[4] != probe[4] || response[5] != probe[5] {
			return false
		}
	}

	// Check message type is valid (Response, Publish, Error, or NAK all indicate HART-IP)
	msgType := response[1]
	if msgType != HARTIPMsgTypeResponse && msgType != HARTIPMsgTypePublish &&
		msgType != HARTIPMsgTypeError && msgType != HARTIPMsgTypeNAK {
		return false
	}

	return true
}

// parseHARTIPResponse extracts metadata from a HART-IP response
func parseHARTIPResponse(response []byte) (version uint8, messageType uint8, status uint8, statusDesc string, transactionID uint16) {
	version = response[0]
	messageType = response[1]
	status = response[3]
	transactionID = uint16(response[4])<<8 | uint16(response[5])

	// Determine status description based on message type
	switch messageType {
	case HARTIPMsgTypeResponse:
		if status == 0x00 {
			statusDesc = "Success"
		} else {
			statusDesc = "Error"
		}
	case HARTIPMsgTypeError:
		statusDesc = "Error"
	case HARTIPMsgTypeNAK:
		statusDesc = "NAK"
	case HARTIPMsgTypePublish:
		statusDesc = "Publish"
	default:
		statusDesc = "Unknown"
	}

	return
}

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

package x2ap

import (
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

/*
X2AP (E-UTRAN X2 Application Protocol) Protocol Fingerprinting over SCTP

X2AP is a critical 4G LTE protocol for inter-eNodeB signaling and handover management.
This is a CRITICAL protocol for telecom security reconnaissance.

Protocol Specification:
  3GPP TS 36.423
  Transport: SCTP (IP protocol 132)
  Default Port: 36422
  SCTP PPID: 27
  Interface: X2 (eNodeB to eNodeB)
  Purpose: Inter-eNodeB handover and mobility management

X2AP PDU Structure (APER-encoded ASN.1):
  - Initiating Message (choice tag 0x00)
  - Successful Outcome (choice tag 0x20)
  - Unsuccessful Outcome (choice tag 0x40)
  - Procedure Code (byte 1)
  - Criticality (byte 2)
  - Value (byte 3+)

X2AP Key Procedure Codes:
  - 0: Handover Preparation
  - 6: X2 Setup
  - 7: Reset

Detection Strategy:
  1. Primary: Check SCTP PPID = 27 (definitive)
  2. Fallback: Port 36422 when PPID = 0 (misconfiguration)
  3. Validation: Valid APER choice tag (0x00, 0x20, or 0x40)

Active Probing (X2 Setup Request):
  Minimal APER encoding:
    Choice tag:    0x00 (InitiatingMessage)
    Procedure Code: 0x06 (id-x2Setup)
    Criticality:   0x00 (reject)
    Value:         0x00 (minimal encoding)

Expected Response:
  Successful Outcome (0x20, procedure 6) or Unsuccessful Outcome (0x40, procedure 6)
*/

const (
	X2AP_SCTP               = "x2ap"
	X2AP_PORT               = 36422
	X2AP_SCTP_PPID          = 27
	INITIATING_MESSAGE      = 0x00
	SUCCESSFUL_OUTCOME      = 0x20
	UNSUCCESSFUL_OUTCOME    = 0x40
	X2_SETUP_PROCEDURE_CODE = 0x06
	CRITICALITY_REJECT      = 0x00
	MIN_MESSAGE_LENGTH      = 4
)

type X2APPlugin struct{}

func init() {
	plugins.RegisterPlugin(&X2APPlugin{})
}

// Run implements the main fingerprinting logic
func (p *X2APPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Phase 1: Detection - send X2 Setup Request and receive response
	response, err := detectX2AP(conn, timeout)
	if err != nil {
		return nil, err
	}

	// Phase 2: Enrichment - extract metadata from response
	procedureCode, criticality, messageType, err := enrichX2AP(response)
	if err != nil {
		// Detection succeeded but enrichment failed - still return service
		metadata := plugins.ServiceX2AP{
			ProcedureCode: procedureCode,
			Criticality:   criticality,
			MessageType:   messageType,
		}
		return plugins.CreateServiceFrom(target, metadata, false, "", plugins.SCTP), nil
	}

	// Create service with metadata
	metadata := plugins.ServiceX2AP{
		ProcedureCode: procedureCode,
		Criticality:   criticality,
		MessageType:   messageType,
	}

	return plugins.CreateServiceFrom(target, metadata, false, "", plugins.SCTP), nil
}

// PortPriority returns true if the port is 36422 (default X2AP port)
func (p *X2APPlugin) PortPriority(port uint16) bool {
	return port == X2AP_PORT
}

// Name returns the protocol name
func (p *X2APPlugin) Name() string {
	return X2AP_SCTP
}

// Type returns the protocol type (SCTP)
func (p *X2APPlugin) Type() plugins.Protocol {
	return plugins.SCTP
}

// Priority returns the plugin execution priority
// X2AP uses port 36422, run at same priority as other telecom protocols (60)
func (p *X2APPlugin) Priority() int {
	return 60
}

// detectX2AP sends an X2 Setup Request and validates the response
func detectX2AP(conn net.Conn, timeout time.Duration) ([]byte, error) {
	// Build X2 Setup Request
	x2SetupRequest := buildX2SetupRequest()

	// Send X2 Setup Request
	response, err := utils.SendRecv(conn, x2SetupRequest, timeout)
	if err != nil {
		return nil, err
	}

	// Validate response structure
	if err := validateX2SetupResponse(response); err != nil {
		return nil, err
	}

	return response, nil
}

// buildX2SetupRequest constructs a minimal X2 Setup Request message
func buildX2SetupRequest() []byte {
	// Minimal X2AP message (APER encoded)
	// Byte 0: Choice tag for InitiatingMessage
	// Byte 1: Procedure Code (6 = X2Setup)
	// Byte 2: Criticality (0 = reject)
	// Byte 3: Value length (minimal encoding)
	message := make([]byte, 4)

	message[0] = INITIATING_MESSAGE      // InitiatingMessage choice
	message[1] = X2_SETUP_PROCEDURE_CODE // Procedure code: id-x2Setup (6)
	message[2] = CRITICALITY_REJECT      // Criticality: reject
	message[3] = 0x00                    // Value length (minimal)

	return message
}

// validateX2SetupResponse validates the structure of an X2 Setup Response or error response
func validateX2SetupResponse(response []byte) error {
	// Minimum response size: 4 bytes (choice tag + procedure code + criticality + value)
	if len(response) < MIN_MESSAGE_LENGTH {
		return &utils.InvalidResponseErrorInfo{
			Service: X2AP_SCTP,
			Info:    fmt.Sprintf("response too short for valid X2AP message: got %d bytes, need %d", len(response), MIN_MESSAGE_LENGTH),
		}
	}

	// Check choice tag (byte 0) - should be Initiating (0x00), Successful (0x20), or Unsuccessful (0x40)
	choiceTag := response[0]
	if choiceTag != INITIATING_MESSAGE && choiceTag != SUCCESSFUL_OUTCOME && choiceTag != UNSUCCESSFUL_OUTCOME {
		return &utils.InvalidResponseErrorInfo{
			Service: X2AP_SCTP,
			Info:    fmt.Sprintf("invalid choice tag: 0x%02x, expected 0x%02x (Initiating), 0x%02x (Successful), or 0x%02x (Unsuccessful)", choiceTag, INITIATING_MESSAGE, SUCCESSFUL_OUTCOME, UNSUCCESSFUL_OUTCOME),
		}
	}

	// Check procedure code (byte 1) - for X2Setup response, should be 6
	procedureCode := response[1]
	if procedureCode != X2_SETUP_PROCEDURE_CODE {
		return &utils.InvalidResponseErrorInfo{
			Service: X2AP_SCTP,
			Info:    fmt.Sprintf("invalid procedure code: 0x%02x, expected 0x%02x (X2Setup)", procedureCode, X2_SETUP_PROCEDURE_CODE),
		}
	}

	return nil
}

// enrichX2AP extracts metadata from the response
// Returns: procedureCode, criticality, messageType, error
func enrichX2AP(response []byte) (uint8, uint8, uint8, error) {
	if len(response) < MIN_MESSAGE_LENGTH {
		return 0, 0, 0, fmt.Errorf("response too short for enrichment")
	}

	// Extract fields from message
	choiceTag := response[0]
	procedureCode := response[1]
	criticality := response[2]

	// Map choice tag to message type
	var messageType uint8
	switch choiceTag {
	case INITIATING_MESSAGE:
		messageType = 0 // Initiating
	case SUCCESSFUL_OUTCOME:
		messageType = 1 // Successful
	case UNSUCCESSFUL_OUTCOME:
		messageType = 2 // Unsuccessful
	default:
		messageType = 0xFF // Unknown
	}

	return procedureCode, criticality, messageType, nil
}


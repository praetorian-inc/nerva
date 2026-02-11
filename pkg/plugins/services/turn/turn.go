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
Package turn implements TURN (Traversal Using Relays around NAT) server detection.

Detection Strategy:
TURN detection sends an Allocate request (message type 0x0003) without credentials,
expecting a 401 Unauthorized error response containing REALM and NONCE attributes.
This distinguishes TURN servers from STUN-only servers, which do not understand
Allocate requests and will respond differently or not at all.

TURN extends STUN to provide relay services for NAT traversal when direct
peer-to-peer connections fail. TURN servers require authentication via
long-term credentials (username/realm/password).

Reference: RFC 8656 - Traversal Using Relays around NAT (TURN)
*/
package turn

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const TURN = "turn"

type Plugin struct{}

var MessageHeaderLength = 20
var AllocateErrorResponse = "0113" // Allocate Error Response
var MagicCookie = "2112a442"
var ATTRIBUTES = map[uint32]string{
	0x0001: "MappedAddress",
	0x0006: "Username",
	0x0008: "MessageIntegrity",
	0x0009: "ErrorCode",
	0x000a: "UnknownAttributes",
	0x0014: "Realm",
	0x0015: "Nonce",
	0x0019: "RequestedTransport",
	0x0020: "XORMappedAddress",
	0x8022: "Software",
	0x8023: "AlternateServer",
	0x8028: "Fingerprint",
}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	/**
	 * https://datatracker.ietf.org/doc/html/rfc8656
	 *
	 * Sends TURN Allocate request with REQUESTED-TRANSPORT attribute
	 * Expects 401 Unauthorized response with REALM and NONCE attributes
	 * This distinguishes TURN from STUN-only servers
	 */

	InitialConnectionPackage := []byte{
		0x00, 0x03, // Message Type (class: Request, method: Allocate)
		0x00, 0x08, // Message Length (8 bytes for REQUESTED-TRANSPORT attribute)
		0x21, 0x12, 0xA4, 0x42, // Magic Cookie
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Transaction ID

		// Attribute: REQUESTED-TRANSPORT (0x0019)
		0x00, 0x19, // attribute type
		0x00, 0x04, // attribute length (4 bytes)
		0x11, 0x00, 0x00, 0x00, // Protocol: UDP (17), reserved bytes
	}

	_, err := rand.Read(InitialConnectionPackage[8:20]) // generate random transaction ID
	if err != nil {
		return nil, &utils.RandomizeError{Message: "transaction ID"}
	}
	TransactionID := hex.EncodeToString(InitialConnectionPackage[8:20])

	response, err := utils.SendRecv(conn, InitialConnectionPackage, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// check response
	if len(response) < MessageHeaderLength {
		return nil, nil
	}
	rmsgType, rmagicCookie, rtransID := hex.EncodeToString(response[:2]),
		hex.EncodeToString(response[4:8]),
		hex.EncodeToString(response[8:20])

	// Expect Allocate Error Response (0x0113)
	if rmsgType != AllocateErrorResponse {
		return nil, nil
	}
	if rmagicCookie != MagicCookie {
		return nil, nil
	}
	if rtransID != TransactionID {
		return nil, nil
	}

	// parse attributes to extract REALM, NONCE, SOFTWARE, and ERROR-CODE
	turnInfo, isTURN := parseResponse(response)
	if !isTURN {
		return nil, nil
	}

	payload := plugins.ServiceTURN{
		Software: turnInfo.Software,
		Realm:    turnInfo.Realm,
		Nonce:    turnInfo.Nonce,
	}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
}

// parseResponse extracts TURN-specific attributes and validates it's a TURN server
func parseResponse(response []byte) (*plugins.ServiceTURN, bool) {
	turnInfo := &plugins.ServiceTURN{}
	idx := MessageHeaderLength
	length := len(response)
	foundErrorCode := false
	isTURNError := false

	for idx < length {
		// parse attribute type, length
		if idx+4 > length {
			return nil, false
		}
		attrType := (uint32(response[idx]) << 8) + uint32(response[idx+1])
		attrLen := (int(response[idx+2]) << 8) + int(response[idx+3])
		idx += 4

		if attrLen == 0 {
			continue
		}

		// parse attribute value
		if idx+attrLen > length {
			return nil, false
		}
		attrValue := response[idx : idx+attrLen]

		// Extract TURN-specific attributes
		switch attrType {
		case 0x8022: // SOFTWARE
			turnInfo.Software = string(attrValue)
		case 0x0014: // REALM
			turnInfo.Realm = string(attrValue)
		case 0x0015: // NONCE
			turnInfo.Nonce = string(attrValue)
		case 0x0009: // ERROR-CODE
			foundErrorCode = true
			// ERROR-CODE structure: 2 reserved bytes, 1 class byte, 1 code byte, reason phrase
			if attrLen >= 4 {
				class := attrValue[2]
				code := attrValue[3]
				errorCode := (uint16(class&0x07) * 100) + uint16(code)
				// TURN-specific error codes: 401 (Unauthorized) or 437 (Allocation Mismatch)
				if errorCode == 401 || errorCode == 437 {
					isTURNError = true
				}
			}
		}

		idx += attrLen
	}

	// Must have error code 401 or 437 to be a TURN server
	if !foundErrorCode || !isTURNError {
		return nil, false
	}

	return turnInfo, true
}

func (p *Plugin) PortPriority(i uint16) bool {
	return i == 3478 || i == 5349
}

func (p *Plugin) Name() string {
	return TURN
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 1999 // Higher priority than STUN (2000) to run first
}

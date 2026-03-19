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

package coap

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const CoAP = "coap"

type CoAPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&CoAPPlugin{})
}

func (p *CoAPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Generate random 2-byte Message ID
	msgID := make([]byte, 2)
	if _, err := rand.Read(msgID); err != nil {
		return nil, &utils.RandomizeError{Message: "coap message id"}
	}

	// Construct CoAP GET /.well-known/core probe packet (21 bytes total)
	// Byte 0: 0x40 = Ver=1, Type=CON, TKL=0
	// Byte 1: 0x01 = Code GET (0.01)
	// Bytes 2-3: random MsgID
	// Byte 4: 0xBB = Option delta=11 (Uri-Path), length=11
	// Bytes 5-15: ".well-known"
	// Byte 16: 0x04 = Option delta=0, length=4
	// Bytes 17-20: "core"
	probe := []byte{
		0x40, 0x01, msgID[0], msgID[1],
		0xBB, '.', 'w', 'e', 'l', 'l', '-', 'k', 'n', 'o', 'w', 'n',
		0x04, 'c', 'o', 'r', 'e',
	}

	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}
	if len(response) < 4 {
		return nil, nil
	}

	// Validate CoAP version: bits 7-6 of byte 0 must be 1
	if (response[0] >> 6) != 1 {
		return nil, nil
	}

	// Validate message type: bits 5-4 of byte 0
	// 1 = NON (Non-confirmable), 2 = ACK (Acknowledgement)
	typ := (response[0] >> 4) & 0x03
	if typ != 1 && typ != 2 {
		return nil, nil
	}

	// Validate code class: bits 7-5 of byte 1 must be 2, 4, or 5
	codeClass := response[1] >> 5
	if codeClass != 2 && codeClass != 4 && codeClass != 5 {
		return nil, nil
	}

	// For ACK responses, validate message ID matches
	if typ == 2 {
		respMsgID := binary.BigEndian.Uint16(response[2:4])
		sentMsgID := binary.BigEndian.Uint16(msgID)
		if respMsgID != sentMsgID {
			return nil, nil
		}
	}

	resources, version := extractPayload(response)

	payload := plugins.ServiceCoAP{Resources: resources}
	return plugins.CreateServiceFrom(target, payload, false, version, plugins.UDP), nil
}

// extractPayload walks the CoAP response to extract the payload string and
// any version information. Returns empty strings on any parse error (graceful
// degradation — we already know it's CoAP at this point).
func extractPayload(response []byte) (resources string, version string) {
	if len(response) < 4 {
		return "", ""
	}

	tkl := int(response[0] & 0x0F) // token length from bits 3-0 of byte 0
	idx := 4 + tkl                  // skip fixed header + token

	// Walk options using CoAP delta encoding
	for idx < len(response) {
		b := response[idx]
		idx++

		if b == 0xFF {
			// Payload marker — everything after is the payload
			break
		}

		deltaNibble := int(b >> 4)
		lengthNibble := int(b & 0x0F)

		// Extended delta
		switch deltaNibble {
		case 13:
			if idx >= len(response) {
				return "", ""
			}
			idx++ // consume 1 extra byte
		case 14:
			if idx+1 >= len(response) {
				return "", ""
			}
			idx += 2 // consume 2 extra bytes
		case 15:
			// Reserved; treat as error
			return "", ""
		}

		// Extended length
		optLen := lengthNibble
		switch lengthNibble {
		case 13:
			if idx >= len(response) {
				return "", ""
			}
			optLen = int(response[idx]) + 13
			idx++
		case 14:
			if idx+1 >= len(response) {
				return "", ""
			}
			optLen = int(binary.BigEndian.Uint16(response[idx:idx+2])) + 269
			idx += 2
		case 15:
			// Reserved; treat as error
			return "", ""
		}

		// Skip option value bytes
		if idx+optLen > len(response) {
			return "", ""
		}
		idx += optLen
	}

	// idx now points to the start of the payload (after 0xFF marker)
	if idx >= len(response) {
		return "", ""
	}

	payloadStr := string(response[idx:])

	// Check for Eclipse Californium server identification ("Cf ")
	if cfIdx := strings.Index(payloadStr, "Cf "); cfIdx != -1 {
		rest := payloadStr[cfIdx+3:]
		// Version string ends at first whitespace or non-printable character
		end := strings.IndexAny(rest, " \t\r\n")
		if end == -1 {
			version = rest
		} else {
			version = rest[:end]
		}
	}

	return payloadStr, version
}

func (p *CoAPPlugin) PortPriority(i uint16) bool { return i == 5683 }
func (p *CoAPPlugin) Name() string               { return CoAP }
func (p *CoAPPlugin) Type() plugins.Protocol     { return plugins.UDP }
func (p *CoAPPlugin) Priority() int              { return 2000 }

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

package wireguard

import (
	"bytes"
	"crypto/rand"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	WIREGUARD = "wireguard"

	// WireGuard message types
	MsgTypeInitiation = 0x01
	MsgTypeResponse   = 0x02
	MsgTypeCookie     = 0x03

	// Message sizes
	InitiationSize = 148
	ResponseSize   = 92
	CookieSize     = 64

	// Default port
	DefaultPort = 51820
)

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// generateSenderIndex creates a random 4-byte sender index using crypto/rand
func generateSenderIndex() ([]byte, error) {
	senderIndex := make([]byte, 4)
	if _, err := rand.Read(senderIndex); err != nil {
		return nil, &utils.RandomizeError{Message: "sender_index"}
	}
	return senderIndex, nil
}

// buildHandshakeInitiation creates a 148-byte WireGuard handshake initiation packet
func buildHandshakeInitiation(senderIndex []byte) ([]byte, error) {
	packet := make([]byte, InitiationSize)

	// Byte 0: Message type
	packet[0] = MsgTypeInitiation
	// Bytes 1-3: Reserved (zeros)
	// Bytes 4-7: Sender index (little-endian)
	copy(packet[4:8], senderIndex)

	// Fill remaining fields with random data (crypto/rand)
	// Bytes 8-39: unencrypted_ephemeral (32 bytes)
	// Bytes 40-87: encrypted_static (48 bytes)
	// Bytes 88-115: encrypted_timestamp (28 bytes)
	// Bytes 116-131: mac1 (16 bytes)
	if _, err := rand.Read(packet[8:132]); err != nil {
		return nil, &utils.RandomizeError{Message: "handshake_fields"}
	}
	// Bytes 132-147: mac2 (16 bytes) - all zeros (no cookie)

	return packet, nil
}

// isWireGuardResponse validates a WireGuard handshake response
// NOTE: This detection method cannot determine if AllowedIPs is properly configured
// on the server. WireGuard will respond to handshake initiations regardless of whether
// the sender IP is in the allowed list. AllowedIPs restrictions are only enforced for
// actual data packets after the handshake completes.
func isWireGuardResponse(response []byte, expectedSenderIndex []byte) (bool, string) {
	if len(response) < 4 {
		return false, ""
	}

	msgType := response[0]

	// Check for Cookie Reply (type 0x03) - confirms WireGuard
	if msgType == MsgTypeCookie && len(response) >= CookieSize {
		return true, "cookie"
	}

	// Check for Handshake Response (type 0x02)
	if msgType == MsgTypeResponse && len(response) >= ResponseSize {
		// Verify receiver_index (bytes 8-11) matches our sender_index
		if bytes.Equal(response[8:12], expectedSenderIndex) {
			return true, "response"
		}
		// Even without index match, message type indicates WireGuard
		return true, "response_unverified"
	}

	return false, ""
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Generate random sender index
	senderIndex, err := generateSenderIndex()
	if err != nil {
		return nil, err
	}

	// Build WireGuard handshake initiation packet
	initPacket, err := buildHandshakeInitiation(senderIndex)
	if err != nil {
		return nil, err
	}

	// PROBE 1: Send WireGuard handshake initiation
	response, err := utils.SendRecv(conn, initPacket, timeout)
	if err != nil {
		return nil, err
	}

	// Check if we got a WireGuard response
	if len(response) > 0 {
		isWG, method := isWireGuardResponse(response, senderIndex)
		if isWG {
			confidence := "high"
			if method == "response_unverified" {
				confidence = "medium"
			}
			return plugins.CreateServiceFrom(target, plugins.ServiceWireGuard{
				DetectionMethod: method,
				Confidence:      confidence,
			}, false, "", plugins.UDP), nil
		}
		// Got a non-WireGuard response - not WireGuard
		return nil, nil
	}

	// PROBE 2: Differential detection - send garbage probe
	garbagePacket := make([]byte, InitiationSize)
	// First byte is NOT a valid WireGuard message type (0x00)
	garbagePacket[0] = 0x00
	if _, err := rand.Read(garbagePacket[1:]); err != nil {
		return nil, &utils.RandomizeError{Message: "garbage_packet"}
	}

	// Small delay between probes
	time.Sleep(100 * time.Millisecond)

	garbageResponse, err := utils.SendRecv(conn, garbagePacket, timeout)
	if err != nil {
		return nil, err
	}

	// Analyze differential behavior
	// WireGuard: silent to both (but WG-format handled, garbage dropped earlier)
	// Closed port: ICMP unreachable to both
	// Other UDP service: likely different responses

	if len(garbageResponse) == 0 {
		// Both probes got no response
		// If on default WireGuard port, use heuristic
		if target.Address.Port() == DefaultPort {
			return plugins.CreateServiceFrom(target, plugins.ServiceWireGuard{
				DetectionMethod: "heuristic",
				Confidence:      "low",
			}, false, "", plugins.UDP), nil
		}
		// Not enough evidence on non-standard port
		return nil, nil
	}

	// Garbage probe got a response but WG probe didn't
	// This suggests different handling - possible WireGuard
	return plugins.CreateServiceFrom(target, plugins.ServiceWireGuard{
		DetectionMethod: "differential",
		Confidence:      "medium",
	}, false, "", plugins.UDP), nil
}

func (p *Plugin) PortPriority(port uint16) bool {
	return port == DefaultPort
}

func (p *Plugin) Name() string {
	return WIREGUARD
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 710 // Between OpenVPN (708) and NTP (800)
}

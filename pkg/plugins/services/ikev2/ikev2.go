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

// Package ikev2 implements IKEv2 (RFC 7296) fingerprinting for network services.
//
// IKEv2 is the successor to IKEv1 (IPsec/ISAKMP) and provides VPN functionality.
// This plugin sends an IKE_SA_INIT request and analyzes the response to detect
// IKEv2 servers. It is designed to distinguish IKEv2 from IKEv1 by checking the
// version byte (0x20 for IKEv2 vs 0x10 for IKEv1).
//
// Detection Strategy:
//   - Constructs an IKE_SA_INIT message with a random initiator SPI
//   - Uses IKEv2-specific values: Version=0x20, ExchangeType=0x22, NextPayload=0x22
//   - Includes modern crypto proposals (AES-CBC, SHA256, DH14)
//   - Validates the response has correct version byte (0x20)
//   - Verifies initiator SPI matches to confirm it's a legitimate response
//   - Extracts Responder SPI and Message ID for fingerprinting
package ikev2

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const IKEV2 = "IKEv2"

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (f *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	initiator := make([]byte, 8)
	_, err := rand.Read(initiator)
	if err != nil {
		return nil, &utils.RandomizeError{Message: "initiator SPI"}
	}

	// IKEv2 IKE_SA_INIT request
	// Key differences from IKEv1:
	// - Version byte at offset 17 = 0x20 (not 0x10)
	// - Exchange Type at offset 18 = 0x22 (IKE_SA_INIT, not 0x02)
	// - NextPayload at offset 16 = 0x22 (SA payload, not 0x01)
	// - Includes modern crypto: AES-CBC, SHA256, DH14
	InitialConnectionPackage := append(initiator, []byte{ //nolint:gocritic
		// 8 bytes Initiator SPI (already appended above)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Responder SPI (empty in request)
		0x22, // NextPayload: SA (33)
		0x20, // Version: IKEv2 (2.0) - THIS IS KEY DIFFERENCE FROM IKEv1
		0x22, // Exchange Type: IKE_SA_INIT (34) - different from IKEv1's 0x02
		0x08, // Flags: Initiator
		0x00, 0x00, 0x00, 0x00, // Message ID: 0
		0x00, 0x00, 0x01, 0x50, // Message Length: 336 bytes

		// SA Payload
		0x21,       // Next Payload: KE (Key Exchange, 33)
		0x00,       // Reserved
		0x00, 0x84, // Payload Length: 132 bytes

		// Proposal 1: IKE
		0x00,       // Last Substructure: 0 (more proposals follow)
		0x00,       // Reserved
		0x00, 0x80, // Proposal Length: 128 bytes
		0x01,       // Proposal Num: 1
		0x01,       // Protocol ID: IKE (1)
		0x00,       // SPI Size: 0
		0x04,       // Number of Transforms: 4

		// Transform 1: Encryption Algorithm - AES-CBC (modern crypto, not 3DES)
		0x03,       // Last Transform: 3 (more transforms follow)
		0x00,       // Reserved
		0x00, 0x0C, // Transform Length: 12 bytes
		0x01,       // Transform Type: Encryption Algorithm (1)
		0x00,       // Reserved
		0x00, 0x0C, // Transform ID: AES-CBC (12)
		0x80, 0x0E, // Attribute Type: Key Length (14) with AF bit set
		0x01, 0x00, // Key Length: 256 bits

		// Transform 2: Integrity Algorithm - HMAC-SHA2-256 (modern hash)
		0x03,       // Last Transform: 3
		0x00,       // Reserved
		0x00, 0x08, // Transform Length: 8 bytes
		0x03,       // Transform Type: Integrity Algorithm (3)
		0x00,       // Reserved
		0x00, 0x0C, // Transform ID: AUTH_HMAC_SHA2_256_128 (12)

		// Transform 3: PRF Algorithm - PRF-HMAC-SHA2-256
		0x03,       // Last Transform: 3
		0x00,       // Reserved
		0x00, 0x08, // Transform Length: 8 bytes
		0x02,       // Transform Type: PRF Algorithm (2)
		0x00,       // Reserved
		0x00, 0x05, // Transform ID: PRF_HMAC_SHA2_256 (5)

		// Transform 4: Diffie-Hellman Group - DH14 (2048-bit MODP)
		0x00,       // Last Transform: 0 (last transform)
		0x00,       // Reserved
		0x00, 0x08, // Transform Length: 8 bytes
		0x04,       // Transform Type: Diffie-Hellman Group (4)
		0x00,       // Reserved
		0x00, 0x0E, // Transform ID: 2048-bit MODP Group (14)

		// Proposal 2: Similar to Proposal 1 with different parameters (for compatibility)
		0x00,       // Last Substructure: 0 (last proposal)
		0x00,       // Reserved
		0x00, 0x4C, // Proposal Length: 76 bytes
		0x02,       // Proposal Num: 2
		0x01,       // Protocol ID: IKE
		0x00,       // SPI Size: 0
		0x03,       // Number of Transforms: 3

		// Transform 1: AES-CBC 128-bit
		0x03,       // Last Transform: 3
		0x00,       // Reserved
		0x00, 0x0C, // Transform Length: 12 bytes
		0x01,       // Transform Type: Encryption
		0x00,       // Reserved
		0x00, 0x0C, // Transform ID: AES-CBC
		0x80, 0x0E, // Key Length Attribute
		0x00, 0x80, // 128 bits

		// Transform 2: SHA1 (for compatibility)
		0x03,       // Last Transform: 3
		0x00,       // Reserved
		0x00, 0x08, // Transform Length: 8 bytes
		0x03,       // Transform Type: Integrity
		0x00,       // Reserved
		0x00, 0x02, // Transform ID: AUTH_HMAC_SHA1_96

		// Transform 3: DH14
		0x00,       // Last Transform: 0
		0x00,       // Reserved
		0x00, 0x08, // Transform Length: 8 bytes
		0x04,       // Transform Type: DH Group
		0x00,       // Reserved
		0x00, 0x0E, // Transform ID: Group 14

		// KE Payload (minimal for probing)
		0x00,       // Next Payload: None (0)
		0x00,       // Reserved
		0x00, 0x88, // Payload Length: 136 bytes
		0x00, 0x0E, // DH Group: 14 (2048-bit MODP)
		0x00, 0x00, // Reserved

		// Key Exchange Data (128 bytes of zeros - minimal for probing)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}...)

	response, err := utils.SendRecv(conn, InitialConnectionPackage, timeout)
	if err != nil {
		return nil, err
	}

	// Check for minimum response length (IKE header is 28 bytes)
	if len(response) < 28 {
		return nil, nil
	}

	// Verify this is an IKEv2 response (version byte at offset 17 should be 0x20)
	// This is the key check to distinguish IKEv2 from IKEv1 (which would be 0x10)
	if response[17] != 0x20 {
		return nil, nil
	}

	// Verify the initiator SPI matches (bytes 0-7)
	// This confirms the response is for our request and not random data
	if !bytes.Equal(initiator, response[0:8]) {
		return nil, nil
	}

	// Extract IKEv2-specific data
	responderSPI := hex.EncodeToString(response[8:16])
	messageID := hex.EncodeToString(response[20:24])

	payload := plugins.ServiceIKEv2{
		ResponderSPI: responderSPI,
		MessageID:    messageID,
	}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
}

func (f *Plugin) PortPriority(i uint16) bool {
	// IKEv2 typically runs on UDP port 500 (ISAKMP) or 4500 (NAT-T)
	return i == 500 || i == 4500
}

func (f *Plugin) Name() string {
	return IKEV2
}

func (f *Plugin) Priority() int {
	// Priority 197 - slightly lower than ipsec's 198
	// This ensures IKEv1/IPSEC plugin runs first, and IKEv2 can differentiate itself
	return 197
}

func (f *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

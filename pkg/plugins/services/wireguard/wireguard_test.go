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
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// Unit tests for helper functions

func TestGenerateSenderIndex(t *testing.T) {
	index, err := generateSenderIndex()
	if err != nil {
		t.Errorf("generateSenderIndex() failed: %v", err)
	}
	if len(index) != 4 {
		t.Errorf("Expected 4-byte sender index, got %d bytes", len(index))
	}

	// Generate multiple times to ensure randomness (not all zeros)
	index2, _ := generateSenderIndex()
	if string(index) == string(index2) {
		t.Logf("Warning: Two consecutive sender indexes are identical (statistically unlikely but possible)")
	}
}

func TestBuildHandshakeInitiation(t *testing.T) {
	senderIndex := []byte{0x01, 0x02, 0x03, 0x04}
	packet, err := buildHandshakeInitiation(senderIndex)
	if err != nil {
		t.Errorf("buildHandshakeInitiation() failed: %v", err)
	}

	// Verify packet structure
	if len(packet) != InitiationSize {
		t.Errorf("Expected packet size %d, got %d", InitiationSize, len(packet))
	}

	// Check message type (byte 0)
	if packet[0] != MsgTypeInitiation {
		t.Errorf("Expected message type 0x%02x, got 0x%02x", MsgTypeInitiation, packet[0])
	}

	// Check reserved bytes (1-3) are zeros
	if packet[1] != 0 || packet[2] != 0 || packet[3] != 0 {
		t.Errorf("Expected reserved bytes to be zero, got [%02x %02x %02x]", packet[1], packet[2], packet[3])
	}

	// Check sender index is correctly placed (bytes 4-7)
	if packet[4] != 0x01 || packet[5] != 0x02 || packet[6] != 0x03 || packet[7] != 0x04 {
		t.Errorf("Expected sender index [01 02 03 04], got [%02x %02x %02x %02x]", packet[4], packet[5], packet[6], packet[7])
	}

	// Check mac2 (bytes 132-147) are zeros (no cookie)
	allZeros := true
	for i := 132; i < 148; i++ {
		if packet[i] != 0 {
			allZeros = false
			break
		}
	}
	if !allZeros {
		t.Errorf("Expected mac2 field (bytes 132-147) to be all zeros")
	}
}

func TestIsWireGuardResponse(t *testing.T) {
	tests := []struct {
		name                string
		response            []byte
		expectedSenderIndex []byte
		expectMatch         bool
		expectedMethod      string
	}{
		{
			name:                "Cookie reply",
			response:            append([]byte{MsgTypeCookie}, make([]byte, CookieSize-1)...),
			expectedSenderIndex: []byte{0x01, 0x02, 0x03, 0x04},
			expectMatch:         true,
			expectedMethod:      "cookie",
		},
		{
			name: "Handshake response with matching index",
			response: append(
				[]byte{MsgTypeResponse, 0x00, 0x00, 0x00, 0x05, 0x06, 0x07, 0x08}, // first 8 bytes
				append([]byte{0x01, 0x02, 0x03, 0x04}, make([]byte, ResponseSize-12)...)..., // receiver_index at bytes 8-11 + padding
			),
			expectedSenderIndex: []byte{0x01, 0x02, 0x03, 0x04},
			expectMatch:         true,
			expectedMethod:      "response",
		},
		{
			name: "Handshake response without matching index",
			response: append(
				[]byte{MsgTypeResponse, 0x00, 0x00, 0x00, 0x05, 0x06, 0x07, 0x08}, // first 8 bytes
				append([]byte{0xFF, 0xFF, 0xFF, 0xFF}, make([]byte, ResponseSize-12)...)..., // wrong receiver_index + padding
			),
			expectedSenderIndex: []byte{0x01, 0x02, 0x03, 0x04},
			expectMatch:         true,
			expectedMethod:      "response_unverified",
		},
		{
			name:                "Too short response",
			response:            []byte{0x01, 0x02},
			expectedSenderIndex: []byte{0x01, 0x02, 0x03, 0x04},
			expectMatch:         false,
			expectedMethod:      "",
		},
		{
			name:                "Invalid message type",
			response:            append([]byte{0xFF}, make([]byte, 91)...),
			expectedSenderIndex: []byte{0x01, 0x02, 0x03, 0x04},
			expectMatch:         false,
			expectedMethod:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isWG, method := isWireGuardResponse(tt.response, tt.expectedSenderIndex)
			if isWG != tt.expectMatch {
				t.Errorf("isWireGuardResponse() match = %v, want %v", isWG, tt.expectMatch)
			}
			if method != tt.expectedMethod {
				t.Errorf("isWireGuardResponse() method = %v, want %v", method, tt.expectedMethod)
			}
		})
	}
}

func TestPluginMetadata(t *testing.T) {
	p := &Plugin{}

	if p.Name() != WIREGUARD {
		t.Errorf("Expected plugin name %s, got %s", WIREGUARD, p.Name())
	}

	if p.Type() != plugins.UDP {
		t.Errorf("Expected UDP protocol type (%d), got %d", plugins.UDP, p.Type())
	}

	if p.Priority() != 710 {
		t.Errorf("Expected priority 710, got %d", p.Priority())
	}

	if !p.PortPriority(DefaultPort) {
		t.Errorf("Expected PortPriority to return true for default port %d", DefaultPort)
	}

	if p.PortPriority(1234) {
		t.Errorf("Expected PortPriority to return false for non-default port 1234")
	}
}

// Docker integration test (commented out as it requires a running WireGuard server)
func TestWireGuard(t *testing.T) {
	// Docker integration test commented out - requires privileged container
	testcases := []test.Testcase{
		// 	{
		// 		Description: "wireguard",
		// 		Port:        51820,
		// 		Protocol:    plugins.UDP,
		// 		Expected: func(res *plugins.PluginResults) bool {
		// 			return res != nil && res.Protocol == "wireguard"
		// 		},
		// 		RunConfig: dockertest.RunOptions{
		// 			Repository: "linuxserver/wireguard",
		// 			Tag:        "latest",
		// 			Privileged: true,
		// 			Env: []string{
		// 				"PUID=1000",
		// 				"PGID=1000",
		// 				"TZ=America/New_York",
		// 				"SERVERURL=auto",
		// 				"PEERS=1",
		// 			},
		// 		},
		// 	},
	}

	var p *Plugin

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

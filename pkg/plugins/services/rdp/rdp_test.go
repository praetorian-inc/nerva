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

package rdp

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

func TestRDP(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "rdp",
			Port:        3389,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "scottyhardy/docker-remote-desktop",
			},
		},
	}

	p := &RDPPlugin{}

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

// mockConn is a mock net.Conn for testing
type mockConn struct {
	readData  []byte
	writeData []byte
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	n = copy(b, m.readData)
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// createNTLMChallengeResponse creates a basic NTLM challenge response with the given parameters
func createNTLMChallengeResponse(targetNameLen, targetNameOffset, targetInfoLen, targetInfoOffset uint32) []byte {
	buf := &bytes.Buffer{}

	// ASN.1 wrapper prefix (simplified)
	prefix := []byte{0x30, 0x82, 0x00, 0x00} // Will be adjusted
	buf.Write(prefix)

	// NTLM Signature
	buf.Write([]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00})

	// Message Type (0x00000002)
	binary.Write(buf, binary.LittleEndian, uint32(0x00000002))

	// TargetNameLen (2 bytes)
	binary.Write(buf, binary.LittleEndian, uint16(targetNameLen))
	// TargetNameMaxLen (2 bytes)
	binary.Write(buf, binary.LittleEndian, uint16(targetNameLen))
	// TargetNameBufferOffset (4 bytes)
	binary.Write(buf, binary.LittleEndian, uint32(targetNameOffset))

	// NegotiateFlags (4 bytes)
	binary.Write(buf, binary.LittleEndian, uint32(0xE2828215))

	// ServerChallenge (8 bytes)
	binary.Write(buf, binary.LittleEndian, uint64(0x0102030405060708))

	// Reserved (8 bytes)
	binary.Write(buf, binary.LittleEndian, uint64(0))

	// TargetInfoLen (2 bytes)
	binary.Write(buf, binary.LittleEndian, uint16(targetInfoLen))
	// TargetInfoMaxLen (2 bytes)
	binary.Write(buf, binary.LittleEndian, uint16(targetInfoLen))
	// TargetInfoBufferOffset (4 bytes)
	binary.Write(buf, binary.LittleEndian, uint32(targetInfoOffset))

	// Version (8 bytes) - must end with 0x00, 0x00, 0x00, 0x0F
	binary.Write(buf, binary.LittleEndian, uint32(0x0A000A06)) // 10.0.10.6
	binary.Write(buf, binary.LittleEndian, uint32(0x0F000000))

	return buf.Bytes()
}

func TestDetectRDPAuth_TargetNameOverflow(t *testing.T) {
	tests := []struct {
		name              string
		targetNameLen     uint32
		targetNameOffset  uint32
		shouldError       bool
		errorContains     string
	}{
		{
			name:              "valid target name",
			targetNameLen:     10,
			targetNameOffset:  56, // After fixed header
			shouldError:       false,
		},
		{
			name:              "target name offset exceeds response length",
			targetNameLen:     10,
			targetNameOffset:  1000, // Way beyond response
			shouldError:       true,
			errorContains:     "invalid target name bounds",
		},
		{
			name:              "target name end exceeds response length",
			targetNameLen:     1000, // Length would exceed response
			targetNameOffset:  56,
			shouldError:       true,
			errorContains:     "invalid target name bounds",
		},
		{
			name:              "integer overflow scenario",
			targetNameLen:     0xFFFFFFFF, // Max uint32
			targetNameOffset:  10,
			shouldError:       true,
			errorContains:     "invalid target name bounds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := createNTLMChallengeResponse(tt.targetNameLen, tt.targetNameOffset, 0, 0)

			// Pad response to have some data
			for len(response) < 100 {
				response = append(response, 0x00)
			}

			conn := &mockConn{readData: response}
			_, _, err := DetectRDPAuth(conn, time.Second)

			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errorContains)
				} else if tt.errorContains != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errorContains)) {
					t.Errorf("expected error containing %q, got %q", tt.errorContains, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestDetectRDPAuth_AVPairOverflow(t *testing.T) {
	tests := []struct {
		name             string
		setupAVPair      func() []byte
		shouldError      bool
		errorContains    string
	}{
		{
			name: "valid AV_PAIR",
			setupAVPair: func() []byte {
				buf := &bytes.Buffer{}
				// Valid AV_PAIR: AvID=1 (NetBIOSComputerName), AvLen=8
				binary.Write(buf, binary.LittleEndian, uint16(1))    // AvID
				binary.Write(buf, binary.LittleEndian, uint16(8))    // AvLen
				buf.Write([]byte("T\x00E\x00S\x00T\x00"))           // Value (UTF-16LE)
				// Terminator
				binary.Write(buf, binary.LittleEndian, uint16(0))    // AvID=0
				binary.Write(buf, binary.LittleEndian, uint16(0))    // AvLen=0
				return buf.Bytes()
			},
			shouldError: false,
		},
		{
			name: "AV_PAIR length exceeds response",
			setupAVPair: func() []byte {
				buf := &bytes.Buffer{}
				// Malicious AV_PAIR: AvLen=1000 (way beyond response)
				binary.Write(buf, binary.LittleEndian, uint16(1))     // AvID
				binary.Write(buf, binary.LittleEndian, uint16(1000))  // AvLen (too large)
				return buf.Bytes()
			},
			shouldError:   true,
			errorContains: "invalid AV_PAIR bounds",
		},
		{
			name: "AV_PAIR with overflow causing negative index",
			setupAVPair: func() []byte {
				buf := &bytes.Buffer{}
				// Overflow scenario: huge AvLen
				binary.Write(buf, binary.LittleEndian, uint16(1))           // AvID
				binary.Write(buf, binary.LittleEndian, uint16(0xFFFF))      // AvLen (max uint16)
				return buf.Bytes()
			},
			shouldError:   true,
			errorContains: "invalid AV_PAIR bounds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			avPairData := tt.setupAVPair()
			avPairLen := uint32(len(avPairData))
			avPairOffset := uint32(56) // After fixed header

			response := createNTLMChallengeResponse(0, 0, avPairLen, avPairOffset)

			// Append AV_PAIR data at the expected offset
			for len(response) < int(avPairOffset) {
				response = append(response, 0x00)
			}
			response = append(response, avPairData...)

			// Pad response
			for len(response) < 200 {
				response = append(response, 0x00)
			}

			conn := &mockConn{readData: response}
			_, _, err := DetectRDPAuth(conn, time.Second)

			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errorContains)
				} else if tt.errorContains != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errorContains)) {
					t.Errorf("expected error containing %q, got %q", tt.errorContains, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

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
	"net/netip"
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
	_ = binary.Write(buf, binary.LittleEndian, uint32(0x00000002))

	// TargetNameLen (2 bytes)
	_ = binary.Write(buf, binary.LittleEndian, uint16(targetNameLen))
	// TargetNameMaxLen (2 bytes)
	_ = binary.Write(buf, binary.LittleEndian, uint16(targetNameLen))
	// TargetNameBufferOffset (4 bytes)
	_ = binary.Write(buf, binary.LittleEndian, targetNameOffset)

	// NegotiateFlags (4 bytes)
	_ = binary.Write(buf, binary.LittleEndian, uint32(0xE2828215))

	// ServerChallenge (8 bytes)
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x0102030405060708))

	// Reserved (8 bytes)
	_ = binary.Write(buf, binary.LittleEndian, uint64(0))

	// TargetInfoLen (2 bytes)
	_ = binary.Write(buf, binary.LittleEndian, uint16(targetInfoLen))
	// TargetInfoMaxLen (2 bytes)
	_ = binary.Write(buf, binary.LittleEndian, uint16(targetInfoLen))
	// TargetInfoBufferOffset (4 bytes)
	_ = binary.Write(buf, binary.LittleEndian, targetInfoOffset)

	// Version (8 bytes) - must end with 0x00, 0x00, 0x00, 0x0F
	_ = binary.Write(buf, binary.LittleEndian, uint32(0x0A000A06)) // 10.0.10.6
	_ = binary.Write(buf, binary.LittleEndian, uint32(0x0F000000))

	return buf.Bytes()
}

func TestDetectRDPAuth_TargetNameOverflow(t *testing.T) {
	tests := []struct {
		name             string
		targetNameLen    uint32
		targetNameOffset uint32
		shouldError      bool
		errorContains    string
	}{
		{
			name:             "valid target name",
			targetNameLen:    10,
			targetNameOffset: 56, // After fixed header
			shouldError:      false,
		},
		{
			name:             "target name offset exceeds response length",
			targetNameLen:    10,
			targetNameOffset: 1000, // Way beyond response
			shouldError:      true,
			errorContains:    "invalid target name bounds",
		},
		{
			name:             "target name end exceeds response length",
			targetNameLen:    1000, // Length would exceed response
			targetNameOffset: 56,
			shouldError:      true,
			errorContains:    "invalid target name bounds",
		},
		{
			name:             "integer overflow scenario",
			targetNameLen:    0xFFFFFFFF, // Max uint32
			targetNameOffset: 10,
			shouldError:      true,
			errorContains:    "invalid target name bounds",
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
		name          string
		setupAVPair   func() []byte
		shouldError   bool
		errorContains string
	}{
		{
			name: "valid AV_PAIR",
			setupAVPair: func() []byte {
				buf := &bytes.Buffer{}
				// Valid AV_PAIR: AvID=1 (NetBIOSComputerName), AvLen=8
				_ = binary.Write(buf, binary.LittleEndian, uint16(1)) // AvID
				_ = binary.Write(buf, binary.LittleEndian, uint16(8)) // AvLen
				buf.Write([]byte("T\x00E\x00S\x00T\x00"))             // Value (UTF-16LE)
				// Terminator
				_ = binary.Write(buf, binary.LittleEndian, uint16(0)) // AvID=0
				_ = binary.Write(buf, binary.LittleEndian, uint16(0)) // AvLen=0
				return buf.Bytes()
			},
			shouldError: false,
		},
		{
			name: "AV_PAIR length exceeds response",
			setupAVPair: func() []byte {
				buf := &bytes.Buffer{}
				// Malicious AV_PAIR: AvLen=1000 (way beyond response)
				_ = binary.Write(buf, binary.LittleEndian, uint16(1))    // AvID
				_ = binary.Write(buf, binary.LittleEndian, uint16(1000)) // AvLen (too large)
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
				_ = binary.Write(buf, binary.LittleEndian, uint16(1))      // AvID
				_ = binary.Write(buf, binary.LittleEndian, uint16(0xFFFF)) // AvLen (max uint16)
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

func TestCheckEOLOS(t *testing.T) {
	tests := []struct {
		fingerprint      string
		expectedNil      bool
		expectedSeverity plugins.Severity
	}{
		{"Windows 2000", false, plugins.SeverityCritical},
		{"Windows Server 2003", false, plugins.SeverityCritical},
		{"Windows Server 2008", false, plugins.SeverityHigh},
		{"Windows 7 or Server 2008 R2", false, plugins.SeverityHigh},
		{"Windows Server 2008 R2 DC", false, plugins.SeverityHigh},
		{"Windows 8 or Server 2012", false, plugins.SeverityMedium},
		{"Windows 10", true, ""},
		{"Windows Server 2016 or 2019", true, ""},
		{"", true, ""},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.fingerprint, func(t *testing.T) {
			finding := checkEOLOS(tt.fingerprint)
			if tt.expectedNil {
				if finding != nil {
					t.Errorf("checkEOLOS(%q) = %+v, want nil", tt.fingerprint, finding)
				}
				return
			}
			if finding == nil {
				t.Fatalf("checkEOLOS(%q) = nil, want non-nil finding", tt.fingerprint)
			}
			if finding.ID != "rdp-eol-os" {
				t.Errorf("finding.ID = %q, want %q", finding.ID, "rdp-eol-os")
			}
			if finding.Severity != tt.expectedSeverity {
				t.Errorf("finding.Severity = %q, want %q", finding.Severity, tt.expectedSeverity)
			}
		})
	}
}

func TestCheckEOLOSVersion(t *testing.T) {
	tests := []struct {
		osVersion        string
		expectedNil      bool
		expectedSeverity plugins.Severity
	}{
		{"5.0.2195", false, plugins.SeverityCritical},
		{"5.2.3790", false, plugins.SeverityCritical},
		{"6.0.6001", false, plugins.SeverityHigh},
		{"6.1.7601", false, plugins.SeverityHigh},
		{"6.2.9200", false, plugins.SeverityMedium},
		{"6.3.9600", false, plugins.SeverityMedium},
		{"10.0.19041", true, ""},
		{"", true, ""},
		{"invalid", true, ""},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.osVersion, func(t *testing.T) {
			finding := checkEOLOSVersion(tt.osVersion)
			if tt.expectedNil {
				if finding != nil {
					t.Errorf("checkEOLOSVersion(%q) = %+v, want nil", tt.osVersion, finding)
				}
				return
			}
			if finding == nil {
				t.Fatalf("checkEOLOSVersion(%q) = nil, want non-nil finding", tt.osVersion)
			}
			if finding.ID != "rdp-eol-os" {
				t.Errorf("finding.ID = %q, want %q", finding.ID, "rdp-eol-os")
			}
			if finding.Severity != tt.expectedSeverity {
				t.Errorf("finding.Severity = %q, want %q", finding.Severity, tt.expectedSeverity)
			}
		})
	}
}

// createNTLMChallengeResponseWithVersion creates an NTLM challenge with a specific OS version.
// The version fields are: MajorVersion (1 byte), MinorVersion (1 byte), BuildNumber (2 bytes LE),
// followed by ProductType (1 byte), Reserved (3 bytes = 0x00 0x00 0x00), NTLMRevision (1 byte = 0x0F).
// DetectRDPAuth checks that Version[4:] == [0, 0, 0, 0xF].
func createNTLMChallengeResponseWithVersion(major, minor, build uint16) []byte {
	buf := &bytes.Buffer{}

	// ASN.1 wrapper prefix (simplified)
	prefix := []byte{0x30, 0x82, 0x00, 0x00}
	buf.Write(prefix)

	// NTLM Signature
	buf.Write([]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00})

	// Message Type (0x00000002)
	_ = binary.Write(buf, binary.LittleEndian, uint32(0x00000002))

	// TargetNameLen, TargetNameMaxLen, TargetNameBufferOffset
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(buf, binary.LittleEndian, uint32(0))

	// NegotiateFlags
	_ = binary.Write(buf, binary.LittleEndian, uint32(0xE2828215))

	// ServerChallenge
	_ = binary.Write(buf, binary.LittleEndian, uint64(0x0102030405060708))

	// Reserved (must be 0 for the validity check)
	_ = binary.Write(buf, binary.LittleEndian, uint64(0))

	// TargetInfoLen, TargetInfoMaxLen, TargetInfoBufferOffset
	// Point to right after the 56-byte fixed header (offset from NTLM start = 56,
	// but our buffer has a 4-byte ASN.1 prefix before NTLM, so NTLM starts at offset 4).
	// DetectRDPAuth strips bytes before NTLMSSP, so offsets are relative to NTLM start.
	targetInfoOffset := uint32(56) // offset from NTLM start
	_ = binary.Write(buf, binary.LittleEndian, uint16(4)) // terminator AV_PAIR = 4 bytes
	_ = binary.Write(buf, binary.LittleEndian, uint16(4))
	_ = binary.Write(buf, binary.LittleEndian, targetInfoOffset)

	// Version (8 bytes):
	// [0] MajorVersion, [1] MinorVersion, [2-3] BuildNumber LE, [4] ProductType, [5-6] Reserved=0, [7] NTLMRevision=0x0F
	_ = binary.Write(buf, binary.LittleEndian, uint8(major))
	_ = binary.Write(buf, binary.LittleEndian, uint8(minor))
	_ = binary.Write(buf, binary.LittleEndian, build) // uint16 LE
	buf.Write([]byte{0x00, 0x00, 0x00, 0x0F})         // ProductType=0, Reserved=0,0, NTLMRevision=0x0F

	// TargetInfo payload: AV_PAIR terminator (AvID=0, AvLen=0)
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))

	return buf.Bytes()
}

func TestRDPPlugin_EOL(t *testing.T) {
	// Windows Server 2003 signature — passes the generic checkRDP and guesses EOL OS.
	// The generic signature matches the first 11 bytes; Server 2003 is 18 bytes total.
	win2003Response := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
		0x03, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}
	conn := &mockConn{readData: win2003Response}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:3389"),
		Misconfigs: true,
	}
	p := &RDPPlugin{}
	service, err := p.Run(conn, time.Second, target)
	if err != nil {
		t.Fatalf("RDPPlugin.Run() unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("RDPPlugin.Run() returned nil service")
	}
	if len(service.SecurityFindings) == 0 {
		t.Fatal("RDPPlugin.Run() expected SecurityFindings, got none")
	}
	if service.SecurityFindings[0].ID != "rdp-eol-os" {
		t.Errorf("SecurityFindings[0].ID = %q, want %q", service.SecurityFindings[0].ID, "rdp-eol-os")
	}
	if service.SecurityFindings[0].Severity != plugins.SeverityCritical {
		t.Errorf("SecurityFindings[0].Severity = %q, want critical", service.SecurityFindings[0].Severity)
	}
}

func TestTLSPlugin_EOL(t *testing.T) {
	// Build NTLM challenge with version 6.1 (Windows 7 / Server 2008 R2)
	response := createNTLMChallengeResponseWithVersion(6, 1, 7601)
	conn := &mockConn{readData: response}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:3389"),
		Misconfigs: true,
	}
	p := &TLSPlugin{}
	service, err := p.Run(conn, time.Second, target)
	if err != nil {
		t.Fatalf("TLSPlugin.Run() unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("TLSPlugin.Run() returned nil service")
	}
	if len(service.SecurityFindings) == 0 {
		t.Fatal("TLSPlugin.Run() expected SecurityFindings, got none")
	}
	if service.SecurityFindings[0].ID != "rdp-eol-os" {
		t.Errorf("SecurityFindings[0].ID = %q, want %q", service.SecurityFindings[0].ID, "rdp-eol-os")
	}
	if service.SecurityFindings[0].Severity != plugins.SeverityHigh {
		t.Errorf("SecurityFindings[0].Severity = %q, want high", service.SecurityFindings[0].Severity)
	}
}

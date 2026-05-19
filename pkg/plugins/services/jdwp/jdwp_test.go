// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jdwp

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// tested locally against a Java process with JDWP enabled
func TestJDWP(_ *testing.T) {
}

// mockJDWPConn implements net.Conn for testing sequential request/response pairs.
// Each Write advances the response index so the following Read returns the
// corresponding pre-built response.
type mockJDWPConn struct {
	responses [][]byte
	callIndex int
}

func (m *mockJDWPConn) Read(b []byte) (int, error) {
	if m.callIndex >= len(m.responses) {
		return 0, nil
	}
	n := copy(b, m.responses[m.callIndex])
	m.callIndex++
	return n, nil
}

func (m *mockJDWPConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (m *mockJDWPConn) Close() error                       { return nil }
func (m *mockJDWPConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockJDWPConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mockJDWPConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockJDWPConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockJDWPConn) SetWriteDeadline(t time.Time) error { return nil }

// buildVersionResponse constructs a valid JDWP version reply packet.
func buildVersionResponse(description, vmVersion, vmName string, major, minor int32) []byte {
	buf := new(bytes.Buffer)

	descBytes := []byte(description)
	vmVersionBytes := []byte(vmVersion)
	vmNameBytes := []byte(vmName)

	// Payload: uint32 descLen + desc + int32 major + int32 minor +
	//          uint32 vmVersionLen + vmVersion + uint32 vmNameLen + vmName
	payloadSize := 4 + len(descBytes) +
		4 + 4 +
		4 + len(vmVersionBytes) +
		4 + len(vmNameBytes)

	// JDWPPacket header: Length(4) + ID(4) + Flags(1) + CommandSet(1) + Command(1) = 11 bytes
	totalLen := uint32(11 + payloadSize)

	// Header
	_ = binary.Write(buf, binary.BigEndian, totalLen)    // Length
	_ = binary.Write(buf, binary.BigEndian, uint32(0x01)) // ID
	buf.WriteByte(0x80)                                   // Flags (reply)
	buf.WriteByte(0x00)                                   // CommandSet (unused in reply)
	buf.WriteByte(0x00)                                   // Command (unused in reply)

	// String: description
	_ = binary.Write(buf, binary.BigEndian, uint32(len(descBytes)))
	buf.Write(descBytes)

	// int32: jdwpMajor
	_ = binary.Write(buf, binary.BigEndian, major)

	// int32: jdwpMinor
	_ = binary.Write(buf, binary.BigEndian, minor)

	// String: vmVersion
	_ = binary.Write(buf, binary.BigEndian, uint32(len(vmVersionBytes)))
	buf.Write(vmVersionBytes)

	// String: vmName
	_ = binary.Write(buf, binary.BigEndian, uint32(len(vmNameBytes)))
	buf.Write(vmNameBytes)

	return buf.Bytes()
}

// jdwpHandshake is the 14-byte literal echoed by a JDWP server.
var jdwpHandshake = []byte{
	0x4a, 0x44, 0x57, 0x50, 0x2d, 0x48, 0x61, 0x6e, 0x64, 0x73, 0x68, 0x61, 0x6b, 0x65,
}

// TestJDWPExposedFinding verifies that a valid handshake + version response with
// Misconfigs=true produces exactly one Critical "jdwp-exposed" finding whose
// evidence mentions the VM name and version.
func TestJDWPExposedFinding(t *testing.T) {
	versionResp := buildVersionResponse("Java Debug Wire Protocol", "11.0.2", "OpenJDK 64-Bit", 1, 8)

	mockConn := &mockJDWPConn{
		responses: [][]byte{
			jdwpHandshake,
			versionResp,
		},
	}

	plugin := &JDWPPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:5005"),
		Host:       "127.0.0.1",
		Misconfigs: true,
	}

	service, err := plugin.Run(mockConn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}
	if len(service.SecurityFindings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(service.SecurityFindings))
	}
	if service.SecurityFindings[0].ID != "jdwp-exposed" {
		t.Errorf("expected finding ID %q, got %q", "jdwp-exposed", service.SecurityFindings[0].ID)
	}
	if service.SecurityFindings[0].Severity != plugins.SeverityCritical {
		t.Errorf("expected severity %q, got %q", plugins.SeverityCritical, service.SecurityFindings[0].Severity)
	}
	evidence := service.SecurityFindings[0].Evidence
	if !bytes.Contains([]byte(evidence), []byte("JDWP handshake succeeded")) {
		t.Errorf("expected evidence to contain %q, got %q", "JDWP handshake succeeded", evidence)
	}
}

// TestJDWPNoFindingWhenMisconfigsDisabled verifies that a valid handshake + version
// response with Misconfigs=false produces no security findings.
func TestJDWPNoFindingWhenMisconfigsDisabled(t *testing.T) {
	versionResp := buildVersionResponse("Java Debug Wire Protocol", "11.0.2", "OpenJDK 64-Bit", 1, 8)

	mockConn := &mockJDWPConn{
		responses: [][]byte{
			jdwpHandshake,
			versionResp,
		},
	}

	plugin := &JDWPPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:5005"),
		Host:       "127.0.0.1",
		Misconfigs: false,
	}

	service, err := plugin.Run(mockConn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}
	if len(service.SecurityFindings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(service.SecurityFindings))
	}
}

// TestJDWPExposedFindingNoVersion verifies that a valid handshake followed by a
// short/empty version response still produces a "jdwp-exposed" finding when
// Misconfigs=true. The evidence should be the bare handshake message with no VM info.
func TestJDWPExposedFindingNoVersion(t *testing.T) {
	// Return fewer than 11 bytes for the version response so DetectJDWPVersion
	// returns (nil, nil), causing Run to use the no-version code path.
	shortVersionResp := []byte{0x00, 0x01, 0x02}

	mockConn := &mockJDWPConn{
		responses: [][]byte{
			jdwpHandshake,
			shortVersionResp,
		},
	}

	plugin := &JDWPPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:5005"),
		Host:       "127.0.0.1",
		Misconfigs: true,
	}

	service, err := plugin.Run(mockConn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}
	if len(service.SecurityFindings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(service.SecurityFindings))
	}
	if service.SecurityFindings[0].ID != "jdwp-exposed" {
		t.Errorf("expected finding ID %q, got %q", "jdwp-exposed", service.SecurityFindings[0].ID)
	}
	if service.SecurityFindings[0].Evidence != "JDWP handshake succeeded" {
		t.Errorf("expected evidence %q, got %q", "JDWP handshake succeeded", service.SecurityFindings[0].Evidence)
	}
}

// TestJDWPNonMatchingHandshake verifies that when the server returns bytes that
// are not the JDWP handshake, Run returns a nil service (not detected).
func TestJDWPNonMatchingHandshake(t *testing.T) {
	mockConn := &mockJDWPConn{
		responses: [][]byte{
			[]byte("HTTP/1.1 200 OK"),
		},
	}

	plugin := &JDWPPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:5005"),
		Host:       "127.0.0.1",
		Misconfigs: false,
	}

	service, err := plugin.Run(mockConn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service != nil {
		t.Errorf("Run() returned non-nil service, want nil (non-matching response should not be detected)")
	}
}

// TestJDWPEmptyResponse verifies that when the server returns an empty response,
// Run returns a nil service (not detected).
func TestJDWPEmptyResponse(t *testing.T) {
	mockConn := &mockJDWPConn{
		responses: [][]byte{{}},
	}

	plugin := &JDWPPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:5005"),
		Host:       "127.0.0.1",
		Misconfigs: false,
	}

	service, err := plugin.Run(mockConn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service != nil {
		t.Errorf("Run() returned non-nil service, want nil (empty response should not be detected)")
	}
}

// TestJDWPPortPriority verifies that PortPriority returns true for common JDWP
// ports and false for non-JDWP ports.
func TestJDWPPortPriority(t *testing.T) {
	plugin := &JDWPPlugin{}

	jdwpPorts := []uint16{5005, 8000, 8787, 9001}
	for _, port := range jdwpPorts {
		if !plugin.PortPriority(port) {
			t.Errorf("PortPriority(%d) = false, want true", port)
		}
	}

	nonJDWPPorts := []uint16{80, 443, 22}
	for _, port := range nonJDWPPorts {
		if plugin.PortPriority(port) {
			t.Errorf("PortPriority(%d) = true, want false", port)
		}
	}
}

// TestJdwpExposedFindingHelper unit-tests the jdwpExposedFinding helper directly.
func TestJdwpExposedFindingHelper(t *testing.T) {
	evidence := "test evidence"
	finding := jdwpExposedFinding(evidence)

	if finding.ID != "jdwp-exposed" {
		t.Errorf("expected ID %q, got %q", "jdwp-exposed", finding.ID)
	}
	if finding.Severity != plugins.SeverityCritical {
		t.Errorf("expected severity %q, got %q", plugins.SeverityCritical, finding.Severity)
	}
	if finding.Description == "" {
		t.Error("expected non-empty description")
	}
	if finding.Evidence != evidence {
		t.Errorf("expected evidence %q, got %q", evidence, finding.Evidence)
	}
}

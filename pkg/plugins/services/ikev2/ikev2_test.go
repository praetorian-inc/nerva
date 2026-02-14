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

package ikev2

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// TestIKEv2ValidResponse tests that a valid IKEv2 response is correctly parsed
func TestIKEv2ValidResponse(t *testing.T) {
	p := &Plugin{}

	// Create a mock connection that returns a valid IKEv2 response
	initiatorSPI := make([]byte, 8)
	copy(initiatorSPI, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})

	// Valid IKEv2 response structure:
	// Bytes 0-7: Initiator SPI (must match request)
	// Bytes 8-15: Responder SPI
	// Byte 16: NextPayload (0x22 = SA)
	// Byte 17: Version (0x20 for IKEv2)
	// Byte 18: Exchange Type (0x22 = IKE_SA_INIT)
	// Byte 19: Flags (0x20 = Response)
	// Bytes 20-23: Message ID
	// Bytes 24-27: Length
	validResponse := append(initiatorSPI, []byte{
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, // Responder SPI
		0x22,       // NextPayload
		0x20,       // Version (IKEv2)
		0x22,       // Exchange Type (IKE_SA_INIT)
		0x20,       // Flags (Response)
		0x00, 0x00, 0x00, 0x01, // Message ID
		0x00, 0x00, 0x00, 0x1C, // Length (28 bytes minimum)
	}...)

	conn := &mockConn{
		response:     validResponse,
		autoMatchSPI: true,
	}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:500"),
		Host:    "localhost",
	}

	service, err := p.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if service == nil {
		t.Fatal("Expected non-nil service")
	}

	// Verify the service contains the expected data
	var ikev2Service plugins.ServiceIKEv2
	if err := json.Unmarshal(service.Raw, &ikev2Service); err != nil {
		t.Fatalf("Failed to unmarshal service: %v", err)
	}

	expectedResponderSPI := hex.EncodeToString(validResponse[8:16])
	if ikev2Service.ResponderSPI != expectedResponderSPI {
		t.Errorf("Expected ResponderSPI %s, got %s", expectedResponderSPI, ikev2Service.ResponderSPI)
	}

	expectedMessageID := hex.EncodeToString(validResponse[20:24])
	if ikev2Service.MessageID != expectedMessageID {
		t.Errorf("Expected MessageID %s, got %s", expectedMessageID, ikev2Service.MessageID)
	}
}

// TestIKEv2RejectsIKEv1 tests that IKEv1 responses are rejected
func TestIKEv2RejectsIKEv1(t *testing.T) {
	p := &Plugin{}

	initiatorSPI := make([]byte, 8)
	copy(initiatorSPI, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})

	// IKEv1 response (version byte = 0x10)
	ikev1Response := append(initiatorSPI, []byte{
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, // Responder SPI
		0x01, // NextPayload
		0x10, // Version (IKEv1) - THIS IS THE KEY DIFFERENCE
		0x02, // Exchange Type
		0x00, // Flags
		0x00, 0x00, 0x00, 0x01, // Message ID
		0x00, 0x00, 0x00, 0x1C, // Length
	}...)

	conn := &mockConn{
		response:     ikev1Response,
		autoMatchSPI: true,
	}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:500"),
		Host:    "localhost",
	}

	service, err := p.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if service != nil {
		t.Error("Expected nil service for IKEv1 response, got non-nil")
	}
}

// TestIKEv2EmptyResponse tests that empty responses return nil
func TestIKEv2EmptyResponse(t *testing.T) {
	p := &Plugin{}

	conn := &mockConn{
		response: []byte{},
	}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:500"),
		Host:    "localhost",
	}

	service, err := p.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if service != nil {
		t.Error("Expected nil service for empty response, got non-nil")
	}
}

// TestIKEv2TruncatedResponse tests that truncated responses (<28 bytes) return nil
func TestIKEv2TruncatedResponse(t *testing.T) {
	p := &Plugin{}

	// Response with only 20 bytes (less than minimum 28)
	truncatedResponse := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
		0x22, 0x20, 0x22, 0x20,
	}

	conn := &mockConn{
		response: truncatedResponse,
	}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:500"),
		Host:    "localhost",
	}

	service, err := p.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if service != nil {
		t.Error("Expected nil service for truncated response, got non-nil")
	}
}

// TestIKEv2SPIMismatch tests that responses with mismatched initiator SPI return nil
func TestIKEv2SPIMismatch(t *testing.T) {
	p := &Plugin{}

	// Response with different initiator SPI (will not match the generated one in the request)
	mismatchedResponse := append([]byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8}, []byte{
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, // Responder SPI
		0x22,       // NextPayload
		0x20,       // Version
		0x22,       // Exchange Type
		0x20,       // Flags
		0x00, 0x00, 0x00, 0x01, // Message ID
		0x00, 0x00, 0x00, 0x1C, // Length
	}...)

	conn := &mockConn{
		response:     mismatchedResponse,
		autoMatchSPI: false, // Don't auto-match SPI for this test
	}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:500"),
		Host:    "localhost",
	}

	service, err := p.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if service != nil {
		t.Error("Expected nil service for SPI mismatch, got non-nil")
	}
}

// TestPluginMethods tests the plugin interface methods
func TestPluginMethods(t *testing.T) {
	p := &Plugin{}

	// Test PortPriority
	if !p.PortPriority(500) {
		t.Error("Expected PortPriority(500) to return true")
	}
	if !p.PortPriority(4500) {
		t.Error("Expected PortPriority(4500) to return true")
	}
	if p.PortPriority(5000) {
		t.Error("Expected PortPriority(5000) to return false")
	}

	// Test Name
	if p.Name() != "IKEv2" {
		t.Errorf("Expected Name() to return 'IKEv2', got '%s'", p.Name())
	}

	// Test Priority (should be 197, lower than ipsec's 198)
	if p.Priority() != 197 {
		t.Errorf("Expected Priority() to return 197, got %d", p.Priority())
	}

	// Test Type
	if p.Type() != plugins.UDP {
		t.Errorf("Expected Type() to return UDP, got %v", p.Type())
	}
}

// TestIKEv2Docker tests against a real IKEv2 server using Docker
func TestIKEv2Docker(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "ikev2",
			Port:        500,
			Protocol:    plugins.UDP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "hwdsl2/ipsec-vpn-server",
				Mounts: []string{
					"ikev2-vpn-data:/etc/ipsec.d",
					"/lib/modules:/lib/modules:ro",
				},
				Privileged: true,
			},
		},
	}

	var p *Plugin

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("test failed: %v", err)
			}
		})
	}
}

// mockConn implements net.Conn for testing
type mockConn struct {
	initiatorSPI     []byte
	response         []byte
	readCalled       bool
	writeData        []byte
	autoMatchSPI     bool // if true, automatically match SPI from request
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readCalled {
		return 0, nil
	}
	m.readCalled = true

	// If autoMatchSPI is enabled and we have both request and response data
	if m.autoMatchSPI && len(m.writeData) >= 8 && len(m.response) >= 8 {
		// Update response with the actual initiator SPI from the request
		responseWithSPI := make([]byte, len(m.response))
		copy(responseWithSPI, m.response)
		copy(responseWithSPI[0:8], m.writeData[0:8])
		copy(b, responseWithSPI)
		return len(responseWithSPI), nil
	}

	// Otherwise, return response as-is
	copy(b, m.response)
	return len(m.response), nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	// Store the written data for SPI matching
	m.writeData = make([]byte, len(b))
	copy(m.writeData, b)
	return len(b), nil
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 500}
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

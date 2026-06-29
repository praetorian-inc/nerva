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

package ipmi

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// mockIPMIConn is a mock net.Conn that returns a fixed responseData from Read.
// It streams bytes continuously across calls, which matches the behavior seen by
// the original isIPMI io.ReadFull and the new detectIPMI conn.Read.
type mockIPMIConn struct {
	responseData []byte
	readIndex    int
}

func (m *mockIPMIConn) Read(b []byte) (n int, err error) {
	if m.readIndex >= len(m.responseData) {
		return 0, io.EOF
	}
	n = copy(b, m.responseData[m.readIndex:])
	m.readIndex += n
	return n, nil
}

func (m *mockIPMIConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockIPMIConn) Close() error {
	return nil
}

func (m *mockIPMIConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (m *mockIPMIConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{}
}

func (m *mockIPMIConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockIPMIConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockIPMIConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// mockUDPConn simulates UDP datagram behavior: each Read call returns one
// complete datagram from the responses slice.
type mockUDPConn struct {
	responses [][]byte
	readIdx   int
}

func (m *mockUDPConn) Read(b []byte) (n int, err error) {
	if m.readIdx >= len(m.responses) {
		return 0, io.EOF
	}
	resp := m.responses[m.readIdx]
	m.readIdx++
	n = copy(b, resp)
	return n, nil
}

func (m *mockUDPConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockUDPConn) Close() error {
	return nil
}

func (m *mockUDPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (m *mockUDPConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{}
}

func (m *mockUDPConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockUDPConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockUDPConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// buildAuthCapabilitiesResponse constructs a 29-byte Get Channel Auth
// Capabilities response with the given auth type bitmap, auth status byte,
// and extended capabilities byte. Offsets follow the IPMI 2.0 spec (Table 22-15).
//
//	[0-3]  RMCP header: 06 00 FF 07
//	[4]    Auth type: 00
//	[5-8]  Session ID: 00 00 00 00
//	[9-12] Session seq: 00 00 00 00
//	[13]   Message length
//	[14-16] IPMB header (target addr, netfn/lun, checksum)
//	[17-19] IPMB (source addr, rqseq/lun, command 0x38)
//	[20]   Completion code (0x00 = success)
//	[21]   Channel number
//	[22]   Auth type support bitmap
//	[23]   Auth status
//	[24]   Extended capabilities (bit 1 = IPMIv2 supported)
//	[25-28] OEM ID, OEM Aux, Checksum
func buildAuthCapabilitiesResponse(authTypes, authStatus, extCap byte) []byte {
	resp := make([]byte, 29)
	// RMCP header
	resp[0] = 0x06
	resp[1] = 0x00
	resp[2] = 0xFF
	resp[3] = 0x07
	// Auth type 0x00, session ID and seq all zero (bytes 4-12)
	// Message length at [13] — left as zero (not validated by parser)
	// IPMB header bytes 14-16, IPMB source 17-19 — left as zero
	// Completion code
	resp[20] = 0x00
	// Channel number
	resp[21] = 0x00
	// Auth type support bitmap
	resp[22] = authTypes
	// Auth status
	resp[23] = authStatus
	// Extended capabilities
	resp[24] = extCap
	// OEM ID, OEM Aux, Checksum (bytes 25-28) — left as zero
	return resp
}

// buildCipherZeroResponse constructs an RMCP+ Open Session Response with the
// given status code at byte offset 17.
//
//	[0-3]  RMCP header: 06 00 FF 07
//	[4]    Auth type: 06 (RMCP+)
//	[5]    Payload type: 11 (Open Session Response)
//	[6-9]  Session ID
//	[10-13] Session sequence
//	[14-15] Payload length
//	[16]   Message tag
//	[17]   Status code
func buildCipherZeroResponse(statusCode byte) []byte {
	resp := make([]byte, 18)
	resp[0] = 0x06
	resp[1] = 0x00
	resp[2] = 0xFF
	resp[3] = 0x07
	resp[4] = 0x06 // Auth type: RMCP+
	resp[5] = 0x11 // Payload type: Open Session Response
	// Session ID, sequence, payload length at [6-15] — left as zero
	// Message tag at [16] — left as zero
	resp[17] = statusCode
	return resp
}

func TestIPMI(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "ipmi",
			Port:        623,
			Protocol:    plugins.UDP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository:   "vaporio/ipmi-simulator",
				ExposedPorts: []string{"623/udp"},
			},
		},
	}

	p := &IPMIPlugin{}

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

// TestIPMIExposedFinding verifies that a security finding is produced when
// Misconfigs=true and the IPMI response matches ipmiExpectedResponse.
// The 13-byte mock response is too short for parseAuthCapabilities (needs 24),
// so caps is nil and probeCipherZero gets EOF → false. Result: 1 finding.
func TestIPMIExposedFinding(t *testing.T) {
	mockConn := &mockIPMIConn{
		responseData: []byte{0x06, 0x00, 0xFF, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}

	plugin := &IPMIPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:623"),
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
	if service.SecurityFindings[0].ID != "ipmi-exposed" {
		t.Errorf("expected finding ID 'ipmi-exposed', got %q", service.SecurityFindings[0].ID)
	}
	if service.SecurityFindings[0].Severity != plugins.SeverityHigh {
		t.Errorf("expected severity high, got %s", service.SecurityFindings[0].Severity)
	}
	if service.AnonymousAccess {
		t.Error("expected AnonymousAccess to be false; short response cannot trigger anonymous login")
	}
}

// TestIPMINoFindingWhenMisconfigsDisabled verifies that no security findings are
// produced when Misconfigs=false, even when detection succeeds.
func TestIPMINoFindingWhenMisconfigsDisabled(t *testing.T) {
	mockConn := &mockIPMIConn{
		responseData: []byte{0x06, 0x00, 0xFF, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}

	plugin := &IPMIPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:623"),
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

// TestIpmiExposedFindingHelper verifies the ipmiExposedFinding helper returns
// the expected ID, severity, description, and evidence fields.
func TestIpmiExposedFindingHelper(t *testing.T) {
	f := ipmiExposedFinding()

	if f.ID != "ipmi-exposed" {
		t.Errorf("expected ID 'ipmi-exposed', got %q", f.ID)
	}
	if f.Severity != plugins.SeverityHigh {
		t.Errorf("expected severity high, got %s", f.Severity)
	}
	if f.Description == "" {
		t.Error("expected non-empty Description")
	}
	if f.Evidence == "" {
		t.Error("expected non-empty Evidence")
	}
}

// resolveAddrPort converts a host:port string (which may contain "localhost")
// to a numeric netip.AddrPort suitable for plugins.Target.
func resolveAddrPort(t *testing.T, hostPort string) netip.AddrPort {
	t.Helper()
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", hostPort, err)
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ap, err := netip.ParseAddrPort(fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		t.Fatalf("ParseAddrPort: %v", err)
	}
	return ap
}

// TestIPMIIntegrationMisconfigs starts a real vaporio/ipmi-simulator container
// and verifies that Run() with Misconfigs=true produces at least one "ipmi-exposed"
// High finding. The simulator may also trigger anonymous-login or cipher-zero findings.
func TestIPMIIntegrationMisconfigs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker integration test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to Docker: %v", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "vaporio/ipmi-simulator",
		Tag:          "latest", // vaporio/ipmi-simulator has no versioned tags
		ExposedPorts: []string{"623/udp"},
	})
	if err != nil {
		t.Fatalf("Could not start IPMI simulator container: %v", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	addr := resource.GetHostPort("623/udp")
	t.Logf("IPMI simulator container running at %s", addr)

	retryErr := pool.Retry(func() error {
		time.Sleep(3 * time.Second)
		conn, dialErr := net.DialTimeout("udp", addr, 3*time.Second)
		if dialErr != nil {
			return dialErr
		}
		defer conn.Close()

		// Send actual IPMI probe to verify the simulator is responding
		if _, writeErr := conn.Write(ipmiInitialPacket[:]); writeErr != nil {
			return writeErr
		}
		if deadlineErr := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); deadlineErr != nil {
			return deadlineErr
		}
		buf := make([]byte, 128)
		if _, readErr := conn.Read(buf); readErr != nil {
			return readErr
		}
		return nil
	})
	if retryErr != nil {
		t.Fatalf("IPMI simulator never became reachable: %v", retryErr)
	}

	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to open UDP connection to IPMI simulator: %v", err)
	}
	defer conn.Close()

	target := plugins.Target{
		Address:    resolveAddrPort(t, addr),
		Host:       resolveAddrPort(t, addr).Addr().String(),
		Misconfigs: true,
	}

	plugin := &IPMIPlugin{}
	service, err := plugin.Run(conn, 2*time.Second, target)
	if err != nil {
		t.Fatalf("Plugin Run returned error: %v", err)
	}
	if service == nil {
		t.Fatal("Plugin Run returned nil service (IPMI not detected)")
	}

	t.Logf("Detected service: protocol=%s tls=%v", service.Protocol, service.TLS)

	if len(service.SecurityFindings) < 1 {
		t.Fatalf("Expected at least 1 SecurityFinding, got %d", len(service.SecurityFindings))
	}

	foundExposed := false
	for _, f := range service.SecurityFindings {
		if f.ID == "ipmi-exposed" {
			foundExposed = true
			if f.Severity != plugins.SeverityHigh {
				t.Errorf("Expected ipmi-exposed severity High, got %s", f.Severity)
			}
		}
		t.Logf("SecurityFinding: id=%s severity=%s", f.ID, f.Severity)
	}
	if !foundExposed {
		t.Error("Expected finding 'ipmi-exposed' to be present among findings")
	}
}

// TestIPMIResponseMismatch verifies that a response whose first byte does not
// match ipmiExpectedResponse causes Run() to return nil (not detected).
func TestIPMIResponseMismatch(t *testing.T) {
	// First byte is 0x07 instead of the expected 0x06.
	mockConn := &mockIPMIConn{
		responseData: []byte{0x07, 0x00, 0xFF, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}

	plugin := &IPMIPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:623"),
		Host:       "127.0.0.1",
		Misconfigs: true,
	}

	service, err := plugin.Run(mockConn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service != nil {
		t.Errorf("Run() returned non-nil service for mismatched response, want nil")
	}
}

// TestIPMIPartialResponse verifies that a response shorter than the 13-byte
// expected response causes Run() to return nil.
func TestIPMIPartialResponse(t *testing.T) {
	// Only 5 bytes — shorter than the 13-byte ipmiExpectedResponse.
	mockConn := &mockIPMIConn{
		responseData: []byte{0x06, 0x00, 0xFF, 0x07, 0x00},
	}

	plugin := &IPMIPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:623"),
		Host:       "127.0.0.1",
		Misconfigs: true,
	}

	service, err := plugin.Run(mockConn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service != nil {
		t.Errorf("Run() returned non-nil service for partial response, want nil")
	}
}

// TestIPMIServiceMetadata verifies that when an IPMI service is detected the
// returned Service carries the correct protocol name and TLS=false.
func TestIPMIServiceMetadata(t *testing.T) {
	mockConn := &mockIPMIConn{
		responseData: []byte{0x06, 0x00, 0xFF, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}

	plugin := &IPMIPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:623"),
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
	if service.Protocol != IPMI {
		t.Errorf("Expected protocol %q, got %q", IPMI, service.Protocol)
	}
	if service.TLS {
		t.Error("Expected TLS=false for IPMI service, got true")
	}
}

// TestIPMICipherZeroAndAnonymousLogin verifies that when both anonymous login
// (authStatus bit 0 set) and cipher zero are accepted, Run() with
// Misconfigs=true produces 3 findings and sets AnonymousAccess=true.
func TestIPMICipherZeroAndAnonymousLogin(t *testing.T) {
	// authStatus=0x01: bit 0 (anonymous login); extCap=0x02: bit 1 (IPMIv2)
	authResp := buildAuthCapabilitiesResponse(0x14, 0x01, 0x02)
	cipherResp := buildCipherZeroResponse(0x00)

	mockConn := &mockUDPConn{
		responses: [][]byte{authResp, cipherResp},
	}

	plugin := &IPMIPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:623"),
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
	if len(service.SecurityFindings) != 3 {
		t.Fatalf("expected 3 findings (exposed + anonymous + cipher-zero), got %d", len(service.SecurityFindings))
	}

	ids := make(map[string]bool)
	for _, f := range service.SecurityFindings {
		ids[f.ID] = true
	}
	for _, want := range []string{"ipmi-exposed", "ipmi-anonymous-login", "ipmi-cipher-zero"} {
		if !ids[want] {
			t.Errorf("expected finding %q not present", want)
		}
	}

	if !service.AnonymousAccess {
		t.Error("expected AnonymousAccess=true when anonymous login detected")
	}
}

// TestIPMICipherZeroOnly verifies that when cipher zero is accepted but
// anonymous login is not set, Run() produces 2 findings (exposed + cipher-zero).
func TestIPMICipherZeroOnly(t *testing.T) {
	// authStatus=0x00: no anonymous login; extCap=0x02: bit 1 (IPMIv2)
	authResp := buildAuthCapabilitiesResponse(0x14, 0x00, 0x02)
	cipherResp := buildCipherZeroResponse(0x00)

	mockConn := &mockUDPConn{
		responses: [][]byte{authResp, cipherResp},
	}

	plugin := &IPMIPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:623"),
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
	if len(service.SecurityFindings) != 2 {
		t.Fatalf("expected 2 findings (exposed + cipher-zero), got %d", len(service.SecurityFindings))
	}

	ids := make(map[string]bool)
	for _, f := range service.SecurityFindings {
		ids[f.ID] = true
	}
	if !ids["ipmi-exposed"] {
		t.Error("expected finding 'ipmi-exposed' not present")
	}
	if !ids["ipmi-cipher-zero"] {
		t.Error("expected finding 'ipmi-cipher-zero' not present")
	}
	if service.AnonymousAccess {
		t.Error("expected AnonymousAccess=false when anonymous login not set")
	}
}

// TestIPMICipherZeroRejected verifies that when the BMC rejects cipher zero
// (status != 0x00), Run() produces only 1 finding (exposed).
func TestIPMICipherZeroRejected(t *testing.T) {
	authResp := buildAuthCapabilitiesResponse(0x14, 0x00, 0x02)
	cipherResp := buildCipherZeroResponse(0x01) // non-zero status = rejected

	mockConn := &mockUDPConn{
		responses: [][]byte{authResp, cipherResp},
	}

	plugin := &IPMIPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:623"),
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
		t.Fatalf("expected 1 finding (exposed only), got %d", len(service.SecurityFindings))
	}
	if service.SecurityFindings[0].ID != "ipmi-exposed" {
		t.Errorf("expected 'ipmi-exposed', got %q", service.SecurityFindings[0].ID)
	}
}

// TestIPMIAnonymousLoginOnly verifies that when anonymous login is set but
// no cipher zero response is returned (EOF), Run() produces 2 findings and
// sets AnonymousAccess=true.
func TestIPMIAnonymousLoginOnly(t *testing.T) {
	// authStatus=0x01: bit 0 (anonymous login); extCap=0x00: no IPMIv2
	authResp := buildAuthCapabilitiesResponse(0x14, 0x01, 0x00)

	mockConn := &mockUDPConn{
		responses: [][]byte{authResp}, // no second response → probeCipherZero gets EOF
	}

	plugin := &IPMIPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:623"),
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
	if len(service.SecurityFindings) != 2 {
		t.Fatalf("expected 2 findings (exposed + anonymous), got %d", len(service.SecurityFindings))
	}

	ids := make(map[string]bool)
	for _, f := range service.SecurityFindings {
		ids[f.ID] = true
	}
	if !ids["ipmi-exposed"] {
		t.Error("expected finding 'ipmi-exposed' not present")
	}
	if !ids["ipmi-anonymous-login"] {
		t.Error("expected finding 'ipmi-anonymous-login' not present")
	}

	if !service.AnonymousAccess {
		t.Error("expected AnonymousAccess=true when anonymous login detected")
	}
}

// TestParseAuthCapabilities verifies parseAuthCapabilities across various
// response lengths and auth field values.
func TestParseAuthCapabilities(t *testing.T) {
	tests := []struct {
		name            string
		response        []byte
		wantNil         bool
		wantAuthTypes   byte
		wantAuthStatus  byte
		wantExtCap      byte
	}{
		{
			name:     "too short — returns nil",
			response: make([]byte, 24), // one byte short of minimum (25)
			wantNil:  true,
		},
		{
			name: "completion code non-zero — returns nil",
			response: func() []byte {
				r := make([]byte, 29)
				r[20] = 0xD4 // non-zero completion code
				return r
			}(),
			wantNil: true,
		},
		{
			name:           "MD5 only — no anonymous, no IPMIv2",
			response:       buildAuthCapabilitiesResponse(0x04, 0x00, 0x00),
			wantNil:        false,
			wantAuthTypes:  0x04,
			wantAuthStatus: 0x00,
			wantExtCap:     0x00,
		},
		{
			name:           "anonymous login bit set (bit 0)",
			response:       buildAuthCapabilitiesResponse(0x00, 0x01, 0x00),
			wantNil:        false,
			wantAuthTypes:  0x00,
			wantAuthStatus: 0x01,
			wantExtCap:     0x00,
		},
		{
			name:           "IPMIv2 extended capability bit set (extCap bit 1)",
			response:       buildAuthCapabilitiesResponse(0x00, 0x00, 0x02),
			wantNil:        false,
			wantAuthTypes:  0x00,
			wantAuthStatus: 0x00,
			wantExtCap:     0x02,
		},
		{
			name:           "both anonymous login and IPMIv2",
			response:       buildAuthCapabilitiesResponse(0x14, 0x01, 0x02),
			wantNil:        false,
			wantAuthTypes:  0x14,
			wantAuthStatus: 0x01,
			wantExtCap:     0x02,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			caps := parseAuthCapabilities(tc.response)
			if tc.wantNil {
				if caps != nil {
					t.Errorf("expected nil, got %+v", caps)
				}
				return
			}
			if caps == nil {
				t.Fatal("expected non-nil caps, got nil")
			}
			if caps.AuthTypeSupport != tc.wantAuthTypes {
				t.Errorf("AuthTypeSupport: want 0x%02X, got 0x%02X", tc.wantAuthTypes, caps.AuthTypeSupport)
			}
			if caps.AuthStatus != tc.wantAuthStatus {
				t.Errorf("AuthStatus: want 0x%02X, got 0x%02X", tc.wantAuthStatus, caps.AuthStatus)
			}
			if caps.ExtCapabilities != tc.wantExtCap {
				t.Errorf("ExtCapabilities: want 0x%02X, got 0x%02X", tc.wantExtCap, caps.ExtCapabilities)
			}
		})
	}
}

// TestIPMICipherZeroFullResponse verifies that probeCipherZero correctly handles a
// realistic 52-byte Open Session Response that includes algorithm payloads, and that
// Run() still produces the ipmi-cipher-zero finding when Misconfigs=true.
func TestIPMICipherZeroFullResponse(t *testing.T) {
	authResp := buildAuthCapabilitiesResponse(0x14, 0x00, 0x02)

	// Full 52-byte Open Session Response with algorithm payloads.
	fullCipherResp := []byte{
		0x06, 0x00, 0xFF, 0x07, // RMCP header
		0x06,                   // Auth type = RMCP+
		0x11,                   // Payload type = Open Session Response
		0x00, 0x00, 0x00, 0x00, // Session ID
		0x00, 0x00, 0x00, 0x00, // Session sequence
		0x24, 0x00,             // Payload length = 36 (little-endian)
		0x00,                   // Message tag
		0x00,                   // Status code = accepted
		0x04,                   // Max privilege level
		0x00,                   // Reserved
		0xA0, 0xA1, 0xA2, 0xA3, // Remote console session ID (echoed)
		0x01, 0x02, 0x03, 0x04, // Managed system session ID
		// Auth algorithm payload
		0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
		// Integrity algorithm payload
		0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
		// Confidentiality algorithm payload
		0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
	}

	mockConn := &mockUDPConn{
		responses: [][]byte{authResp, fullCipherResp},
	}

	plugin := &IPMIPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:623"),
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

	ids := make(map[string]bool)
	for _, f := range service.SecurityFindings {
		ids[f.ID] = true
	}
	if !ids["ipmi-cipher-zero"] {
		t.Errorf("expected finding 'ipmi-cipher-zero' not present in findings: %v", service.SecurityFindings)
	}
	if !ids["ipmi-exposed"] {
		t.Errorf("expected finding 'ipmi-exposed' not present in findings: %v", service.SecurityFindings)
	}
}

// TestIPMIMetadataEnrichment verifies that ServiceIPMI fields are correctly
// populated and round-trip through the service's Raw JSON metadata.
func TestIPMIMetadataEnrichment(t *testing.T) {
	// authStatus=0x01: bit 0 (anonymous login); extCap=0x02: bit 1 (IPMIv2)
	// authTypes=0x14: MD5 (bit2) + straight_key (bit4)
	authResp := buildAuthCapabilitiesResponse(0x14, 0x01, 0x02)
	cipherResp := buildCipherZeroResponse(0x00) // cipher zero accepted

	mockConn := &mockUDPConn{
		responses: [][]byte{authResp, cipherResp},
	}

	plugin := &IPMIPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:623"),
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

	var meta plugins.ServiceIPMI
	if err := json.Unmarshal(service.Raw, &meta); err != nil {
		t.Fatalf("failed to unmarshal service.Raw into ServiceIPMI: %v", err)
	}

	if !meta.AnonymousLogin {
		t.Error("expected AnonymousLogin=true in metadata")
	}
	if !meta.IPMIv2 {
		t.Error("expected IPMIv2=true in metadata")
	}
	if !meta.CipherZero {
		t.Error("expected CipherZero=true in metadata")
	}

	authTypeSet := make(map[string]bool)
	for _, at := range meta.AuthTypes {
		authTypeSet[at] = true
	}
	if !authTypeSet["md5"] {
		t.Error("expected 'md5' in AuthTypes")
	}
	if !authTypeSet["straight_key"] {
		t.Error("expected 'straight_key' in AuthTypes")
	}

	if !service.AnonymousAccess {
		t.Error("expected service.AnonymousAccess=true")
	}
}

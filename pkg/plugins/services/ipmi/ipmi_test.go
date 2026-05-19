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
		t.Error("expected AnonymousAccess to be false; IPMI plugin does not set AnonymousAccess")
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
// and verifies that Run() with Misconfigs=true produces exactly one "ipmi-exposed"
// High finding.
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
		Tag:          "latest",
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
		buf := make([]byte, len(ipmiExpectedResponse))
		if _, readErr := io.ReadFull(conn, buf); readErr != nil {
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

	if len(service.SecurityFindings) != 1 {
		t.Fatalf("Expected exactly 1 SecurityFinding, got %d", len(service.SecurityFindings))
	}
	finding := service.SecurityFindings[0]
	if finding.ID != "ipmi-exposed" {
		t.Errorf("Expected finding ID %q, got %q", "ipmi-exposed", finding.ID)
	}
	if finding.Severity != plugins.SeverityHigh {
		t.Errorf("Expected severity High, got %s", finding.Severity)
	}
	t.Logf("SecurityFinding: id=%s severity=%s", finding.ID, finding.Severity)
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
// expected response causes Run() to return nil (io.ReadFull cannot be satisfied).
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

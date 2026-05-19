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
		return 0, nil
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

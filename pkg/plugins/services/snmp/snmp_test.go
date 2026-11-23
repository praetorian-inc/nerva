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

package snmp

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

func TestSNMP(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "snmp",
			Port:        161,
			Protocol:    plugins.UDP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository:   "polinux/snmpd",
				ExposedPorts: []string{"161/udp"},
			},
		},
	}

	p := &SNMPPlugin{}

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

// TestSNMPSecurityFindings verifies that security findings are set when Misconfigs is true.
func TestSNMPSecurityFindings(t *testing.T) {
	// Build a mock SNMP response containing "public" and the RequestID bytes,
	// with enough bytes after "public"+33 for a version string.
	requestID := []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	// Craft response: padding + "public" + 33 bytes of padding + sysDescr + requestID bytes
	sysDescr := "Linux test 5.4.0"
	padding := make([]byte, 10)
	afterPublic := make([]byte, 33)
	response := append(padding, []byte("public")...)
	response = append(response, afterPublic...)
	response = append(response, []byte(sysDescr)...)
	response = append(response, requestID...)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock UDP server: %v", err)
	}
	defer pc.Close()

	serverAddr := pc.LocalAddr().String()

	go func() {
		buf := make([]byte, 4096)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n == 0 {
			return
		}
		_, _ = pc.WriteTo(response, addr)
	}()

	conn, err := net.DialTimeout("udp", serverAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%s", serverAddr[len("127.0.0.1:"):])
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &SNMPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}
	if len(service.SecurityFindings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(service.SecurityFindings))
	}
	if service.SecurityFindings[0].ID != "snmp-default-community" {
		t.Errorf("expected finding ID 'snmp-default-community', got %q", service.SecurityFindings[0].ID)
	}
	if service.SecurityFindings[0].Severity != plugins.SeverityHigh {
		t.Errorf("expected severity high, got %s", service.SecurityFindings[0].Severity)
	}
}

// TestSNMPSecurityFindingsDisabled verifies that no security findings are set when Misconfigs is false.
func TestSNMPSecurityFindingsDisabled(t *testing.T) {
	requestID := []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	sysDescr := "Linux test 5.4.0"
	padding := make([]byte, 10)
	afterPublic := make([]byte, 33)
	response := append(padding, []byte("public")...)
	response = append(response, afterPublic...)
	response = append(response, []byte(sysDescr)...)
	response = append(response, requestID...)

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock UDP server: %v", err)
	}
	defer pc.Close()

	serverAddr := pc.LocalAddr().String()

	go func() {
		buf := make([]byte, 4096)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n == 0 {
			return
		}
		_, _ = pc.WriteTo(response, addr)
	}()

	conn, err := net.DialTimeout("udp", serverAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%s", serverAddr[len("127.0.0.1:"):])
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: false,
	}

	plugin := &SNMPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}
	if len(service.SecurityFindings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(service.SecurityFindings))
	}
}

func TestCheckSNMPEOL(t *testing.T) {
	tests := []struct {
		sysDescr string
		wantID   string
	}{
		{"VMware ESXi 5.5.0", "snmp-eol"},
		{"VMware ESXi 5.5.0 build-3248547", "snmp-eol"},
		{"Linux test 5.4.0", ""},
		{"VMware ESXi 8.0.0", ""},
		{"", ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.sysDescr, func(t *testing.T) {
			finding := checkSNMPEOL(tt.sysDescr)
			if tt.wantID == "" {
				if finding != nil {
					t.Errorf("checkSNMPEOL(%q) = %+v, want nil", tt.sysDescr, finding)
				}
				return
			}
			if finding == nil {
				t.Fatalf("checkSNMPEOL(%q) = nil, want ID %q", tt.sysDescr, tt.wantID)
			}
			if finding.ID != tt.wantID {
				t.Errorf("finding.ID = %q, want %q", finding.ID, tt.wantID)
			}
		})
	}
}

func TestSNMPEOLFinding(t *testing.T) {
	tests := []struct {
		name       string
		sysDescr   string
		misconfigs bool
		wantIDs    []string
	}{
		{
			name:       "esxi 5.5 misconfigs",
			sysDescr:   "VMware ESXi 5.5.0",
			misconfigs: true,
			wantIDs:    []string{"snmp-default-community", "snmp-eol"},
		},
		{
			name:       "linux misconfigs",
			sysDescr:   "Linux test 5.4.0",
			misconfigs: true,
			wantIDs:    []string{"snmp-default-community"},
		},
		{
			name:       "esxi 5.5 misconfigs disabled",
			sysDescr:   "VMware ESXi 5.5.0",
			misconfigs: false,
			wantIDs:    nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			requestID := []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
			padding := make([]byte, 10)
			afterPublic := make([]byte, 33)
			response := append(padding, []byte("public")...)
			response = append(response, afterPublic...)
			response = append(response, []byte(tt.sysDescr)...)
			response = append(response, requestID...)

			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to start mock UDP server: %v", err)
			}
			defer pc.Close()

			serverAddr := pc.LocalAddr().String()

			go func() {
				buf := make([]byte, 4096)
				n, addr, err := pc.ReadFrom(buf)
				if err != nil || n == 0 {
					return
				}
				_, _ = pc.WriteTo(response, addr)
			}()

			conn, err := net.DialTimeout("udp", serverAddr, 5*time.Second)
			if err != nil {
				t.Fatalf("Failed to connect to mock server: %v", err)
			}
			defer conn.Close()

			addrStr := fmt.Sprintf("127.0.0.1:%s", serverAddr[len("127.0.0.1:"):])
			addrPort := netip.MustParseAddrPort(addrStr)
			target := plugins.Target{
				Host:       "127.0.0.1",
				Address:    addrPort,
				Misconfigs: tt.misconfigs,
			}

			plugin := &SNMPPlugin{}
			service, err := plugin.Run(conn, 5*time.Second, target)
			if err != nil {
				t.Fatalf("Run() returned unexpected error: %v", err)
			}
			if service == nil {
				t.Fatal("Run() returned nil, want non-nil service")
			}

			got := map[string]bool{}
			for _, f := range service.SecurityFindings {
				got[f.ID] = true
			}
			if len(service.SecurityFindings) != len(tt.wantIDs) {
				t.Fatalf("findings = %v, want %v", service.SecurityFindings, tt.wantIDs)
			}
			for _, id := range tt.wantIDs {
				if !got[id] {
					t.Errorf("missing finding ID %q in %v", id, service.SecurityFindings)
				}
			}
			if got["esxi-eol"] {
				t.Errorf("SNMP must emit snmp-eol, not esxi-eol")
			}
		})
	}
}

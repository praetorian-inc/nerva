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

package imap

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

// TestIMAPSecurityFindings verifies that the imap-cleartext finding is emitted when Misconfigs=true.
func TestIMAPSecurityFindings(t *testing.T) {
	// Minimal IMAP greeting followed by a CAPABILITY response
	greeting := "* OK IMAP server ready\r\n"
	capResponse := "* CAPABILITY IMAP4rev1\r\n7FYWU8I4 OK CAPABILITY completed\r\n"

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	defer listener.Close()

	tcpAddr := listener.Addr().(*net.TCPAddr)
	serverPort := tcpAddr.Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(greeting))
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte(capResponse))
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &IMAPPlugin{}
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
	if service.SecurityFindings[0].ID != "imap-cleartext" {
		t.Errorf("expected finding ID 'imap-cleartext', got %q", service.SecurityFindings[0].ID)
	}
	if service.SecurityFindings[0].Severity != plugins.SeverityMedium {
		t.Errorf("expected severity medium, got %s", service.SecurityFindings[0].Severity)
	}
}

// TestIMAPSecurityFindingsDisabled verifies that no findings are emitted when Misconfigs=false.
func TestIMAPSecurityFindingsDisabled(t *testing.T) {
	greeting := "* OK IMAP server ready\r\n"
	capResponse := "* CAPABILITY IMAP4rev1\r\n7FYWU8I4 OK CAPABILITY completed\r\n"

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	defer listener.Close()

	tcpAddr := listener.Addr().(*net.TCPAddr)
	serverPort := tcpAddr.Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(greeting))
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte(capResponse))
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: false,
	}

	plugin := &IMAPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	if len(service.SecurityFindings) != 0 {
		t.Errorf("expected no findings when Misconfigs=false, got %d", len(service.SecurityFindings))
	}
}

func TestIMAP(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "imap",
			Port:        143,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "instrumentisto/dovecot",
			},
		},
	}

	p := &IMAPPlugin{}

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

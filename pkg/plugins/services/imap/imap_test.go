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

func runIMAPMock(t *testing.T, capLine string, misconfigs bool) *plugins.Service {
	t.Helper()
	greeting := "* OK IMAP server ready\r\n"
	capResponse := capLine + "\r\n7FYWU8I4 OK CAPABILITY completed\r\n"

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

	addrPort := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", serverPort))
	plugin := &IMAPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: misconfigs,
	})
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}
	return service
}

func TestIMAPSecurityFindings(t *testing.T) {
	tests := []struct {
		name       string
		capLine    string
		misconfigs bool
		wantID     string
	}{
		{
			name:       "AUTH=PLAIN before STARTTLS emits imap-cleartext",
			capLine:    "* CAPABILITY IMAP4rev1 AUTH=PLAIN",
			misconfigs: true,
			wantID:     "imap-cleartext",
		},
		{
			name:       "AUTH=PLAIN with STARTTLS still emits imap-cleartext",
			capLine:    "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN",
			misconfigs: true,
			wantID:     "imap-cleartext",
		},
		{
			name:       "AUTH=LOGIN equivalent emits imap-cleartext",
			capLine:    "* CAPABILITY IMAP4rev1 AUTH=LOGIN",
			misconfigs: true,
			wantID:     "imap-cleartext",
		},
		{
			name:       "IMAP LOGIN available without AUTH=PLAIN emits imap-cleartext",
			capLine:    "* CAPABILITY IMAP4rev1",
			misconfigs: true,
			wantID:     "imap-cleartext",
		},
		{
			name:       "STARTTLS without LOGINDISABLED still emits (LOGIN remains)",
			capLine:    "* CAPABILITY IMAP4rev1 STARTTLS",
			misconfigs: true,
			wantID:     "imap-cleartext",
		},
		{
			name:       "LOGINDISABLED without AUTH=PLAIN does not emit",
			capLine:    "* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED",
			misconfigs: true,
		},
		{
			name:       "LOGINDISABLED with AUTH=PLAIN still emits",
			capLine:    "* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED AUTH=PLAIN",
			misconfigs: true,
			wantID:     "imap-cleartext",
		},
		{
			name:       "Misconfigs false does not emit even with AUTH=PLAIN",
			capLine:    "* CAPABILITY IMAP4rev1 AUTH=PLAIN",
			misconfigs: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := runIMAPMock(t, tt.capLine, tt.misconfigs)
			if tt.wantID == "" {
				if len(service.SecurityFindings) != 0 {
					t.Fatalf("expected no findings, got %d: %+v", len(service.SecurityFindings), service.SecurityFindings)
				}
				return
			}
			if len(service.SecurityFindings) != 1 {
				t.Fatalf("expected 1 finding, got %d: %+v", len(service.SecurityFindings), service.SecurityFindings)
			}
			if service.SecurityFindings[0].ID != tt.wantID {
				t.Errorf("expected finding ID %q, got %q", tt.wantID, service.SecurityFindings[0].ID)
			}
			if service.SecurityFindings[0].Severity != plugins.SeverityMedium {
				t.Errorf("expected severity medium, got %s", service.SecurityFindings[0].Severity)
			}
		})
	}
}

func TestOffersCleartextAUTH(t *testing.T) {
	tests := []struct {
		caps []string
		want bool
	}{
		{[]string{"IMAP4REV1", "AUTH=PLAIN"}, true},
		{[]string{"IMAP4REV1", "STARTTLS", "AUTH=PLAIN"}, true},
		{[]string{"IMAP4REV1", "AUTH=LOGIN"}, true},
		{[]string{"IMAP4REV1", "STARTTLS"}, true},
		{[]string{"IMAP4REV1"}, true},
		{[]string{"IMAP4REV1", "STARTTLS", "LOGINDISABLED"}, false},
		{[]string{"IMAP4REV1", "STARTTLS", "LOGINDISABLED", "AUTH=PLAIN"}, true},
		{nil, true},
	}
	for _, tt := range tests {
		if got := offersCleartextAUTH(tt.caps); got != tt.want {
			t.Errorf("offersCleartextAUTH(%v) = %v, want %v", tt.caps, got, tt.want)
		}
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

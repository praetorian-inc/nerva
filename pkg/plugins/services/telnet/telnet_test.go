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

package telnet

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

// TestTelnetSecurityFindings verifies that security findings are set when Telnet is detected via mock server.
func TestTelnetSecurityFindings(t *testing.T) {
	// Valid telnet bytes: IAC WILL ECHO (255, 251, 1)
	telnetBytes := []byte{IAC, WILL, ECHO}

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
		_, _ = conn.Write(telnetBytes)
	}()

	time.Sleep(10 * time.Millisecond)

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

	plugin := &TELNETPlugin{}
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
	if service.SecurityFindings[0].ID != "telnet-cleartext" {
		t.Errorf("expected finding ID 'telnet-cleartext', got %q", service.SecurityFindings[0].ID)
	}
	if service.SecurityFindings[0].Severity != plugins.SeverityMedium {
		t.Errorf("expected severity medium, got %s", service.SecurityFindings[0].Severity)
	}
}

func TestTelnet(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "telnet",
			Port:        23,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "ddhhz/nyancat-server",
			},
		},
	}

	p := &TELNETPlugin{}

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

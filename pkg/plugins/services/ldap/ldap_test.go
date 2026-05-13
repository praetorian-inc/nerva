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

package ldap

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

// buildLDAPBindFailureResponse constructs a minimal LDAP bind failure response
// echoing the message ID bytes from the request (bytes 4-7 of the bind request body).
func buildLDAPBindFailureResponse(requestMsgIDBytes []byte) []byte {
	// LDAP bind response: sequence { msgID (integer), bindResponse { resultCode=49 (invalidCredentials), matchedDN="", errorMessage="" } }
	// 0x30 sequence
	// 0x0f length (15 bytes follow = total 17 bytes; DetectLDAP checks len(response)-2 == byte at index 1)
	// 0x02 0x04 <4-byte msgID>  -- integer, 4 bytes, matches request
	// 0x61 0x07               -- bind response, 7 bytes
	// 0x0a 0x01 0x31          -- enumerated resultCode = 49 (invalidCredentials)
	// 0x04 0x00               -- matchedDN = ""
	// 0x04 0x00               -- errorMessage = ""
	resp := []byte{0x30, 0x0f, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x61, 0x07, 0x0a, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00}
	if len(requestMsgIDBytes) >= 4 {
		copy(resp[4:8], requestMsgIDBytes[:4])
	}
	return resp
}

// buildLDAPBindSuccessResponse constructs a minimal LDAP anonymous bind success response.
func buildLDAPBindSuccessResponse() []byte {
	// Anonymous bind uses msgID = 2 (0x00 0x00 0x00 0x02)
	// 0x30 0x0f sequence (15 bytes follow)
	// 0x02 0x04 0x00 0x00 0x00 0x02  -- msgID = 2
	// 0x61 0x07                       -- bind response, 7 bytes
	// 0x0a 0x01 0x00                  -- resultCode = 0 (success)
	// 0x04 0x00                       -- matchedDN = ""
	// 0x04 0x00                       -- errorMessage = ""
	return []byte{0x30, 0x0f, 0x02, 0x04, 0x00, 0x00, 0x00, 0x02, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
}

// TestLDAPSecurityFindingsCleartextAndAnonymousBind verifies that both ldap-cleartext and
// ldap-anonymous-bind findings are emitted when Misconfigs=true and anonymous bind succeeds.
func TestLDAPSecurityFindingsCleartextAndAnonymousBind(t *testing.T) {
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

		// First request: random-credential bind from DetectLDAP
		// The bind request is 60 bytes; read it and echo back the message ID
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil || n < 8 {
			return
		}
		// Message ID BER: bytes 2-7 are [0x02, 0x04, b0, b1, b2, b3]
		// Extract the 4 raw msgID bytes at offset 4
		msgIDBytes := buf[4:8]
		resp := buildLDAPBindFailureResponse(msgIDBytes)
		_, _ = conn.Write(resp)

		// Second request: anonymous bind from checkAnonymousBind
		n2, err2 := conn.Read(buf)
		if err2 != nil || n2 == 0 {
			return
		}
		_, _ = conn.Write(buildLDAPBindSuccessResponse())
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

	plugin := &LDAPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	if len(service.SecurityFindings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(service.SecurityFindings), service.SecurityFindings)
	}

	ids := map[string]plugins.Severity{}
	for _, f := range service.SecurityFindings {
		ids[f.ID] = f.Severity
	}

	if sev, ok := ids["ldap-cleartext"]; !ok {
		t.Error("expected ldap-cleartext finding")
	} else if sev != plugins.SeverityMedium {
		t.Errorf("expected ldap-cleartext severity medium, got %s", sev)
	}

	if sev, ok := ids["ldap-anonymous-bind"]; !ok {
		t.Error("expected ldap-anonymous-bind finding")
	} else if sev != plugins.SeverityHigh {
		t.Errorf("expected ldap-anonymous-bind severity high, got %s", sev)
	}
}

// TestLDAPSecurityFindingsCleartextOnly verifies that only ldap-cleartext is emitted
// when Misconfigs=true but anonymous bind fails.
func TestLDAPSecurityFindingsCleartextOnly(t *testing.T) {
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

		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil || n < 8 {
			return
		}
		msgIDBytes := buf[4:8]
		resp := buildLDAPBindFailureResponse(msgIDBytes)
		_, _ = conn.Write(resp)

		// Second request: anonymous bind - respond with failure (resultCode=49)
		n2, err2 := conn.Read(buf)
		if err2 != nil || n2 == 0 {
			return
		}
		// Return failure response for anonymous bind (reuse msgID=2 from anon bind)
		failResp := []byte{0x30, 0x0f, 0x02, 0x04, 0x00, 0x00, 0x00, 0x02, 0x61, 0x07, 0x0a, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00}
		_, _ = conn.Write(failResp)
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

	plugin := &LDAPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	if len(service.SecurityFindings) != 1 {
		t.Fatalf("expected 1 finding (ldap-cleartext only), got %d: %+v", len(service.SecurityFindings), service.SecurityFindings)
	}
	if service.SecurityFindings[0].ID != "ldap-cleartext" {
		t.Errorf("expected finding ID 'ldap-cleartext', got %q", service.SecurityFindings[0].ID)
	}
	if service.SecurityFindings[0].Severity != plugins.SeverityMedium {
		t.Errorf("expected severity medium, got %s", service.SecurityFindings[0].Severity)
	}
}

// TestLDAPSecurityFindingsDisabled verifies that no findings are emitted when Misconfigs=false.
func TestLDAPSecurityFindingsDisabled(t *testing.T) {
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

		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil || n < 8 {
			return
		}
		msgIDBytes := buf[4:8]
		resp := buildLDAPBindFailureResponse(msgIDBytes)
		_, _ = conn.Write(resp)
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

	plugin := &LDAPPlugin{}
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

func TestLDAP(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker-based integration test in short mode")
	}

	testcases := []test.Testcase{
		{
			Description: "ldap",
			Port:        1389,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "bitnami/openldap",
			},
		},
	}

	p := &LDAPPlugin{}

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

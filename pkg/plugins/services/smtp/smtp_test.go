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

package smtp

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

// startMockSMTPServer starts a mock SMTP server that sends the given greeting and EHLO response.
func startMockSMTPServer(t *testing.T, greeting, ehloResponse string) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}

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
		_, _ = conn.Write([]byte(ehloResponse))
	}()

	return serverPort, func() { listener.Close() }
}

// TestSMTPSecurityFindingsCleartext verifies the smtp-cleartext finding is emitted
// and smtp-no-auth is NOT emitted when AUTH is present in the EHLO response.
func TestSMTPSecurityFindingsCleartext(t *testing.T) {
	greeting := "220 mail.example.com ESMTP\r\n"
	ehloResponse := "250-mail.example.com\r\n250-AUTH LOGIN PLAIN\r\n250 SMTPUTF8\r\n"

	serverPort, cleanup := startMockSMTPServer(t, greeting, ehloResponse)
	defer cleanup()

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

	plugin := &SMTPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	if len(service.SecurityFindings) != 1 {
		t.Fatalf("expected 1 finding (smtp-cleartext only), got %d: %+v", len(service.SecurityFindings), service.SecurityFindings)
	}
	if service.SecurityFindings[0].ID != "smtp-cleartext" {
		t.Errorf("expected finding ID 'smtp-cleartext', got %q", service.SecurityFindings[0].ID)
	}
	if service.SecurityFindings[0].Severity != plugins.SeverityLow {
		t.Errorf("expected severity low, got %s", service.SecurityFindings[0].Severity)
	}
}

// TestSMTPSecurityFindingsAuthLastToken verifies smtp-no-auth is NOT emitted when AUTH
// is the last token on an EHLO line (trailing \r\n attached to token).
func TestSMTPSecurityFindingsAuthLastToken(t *testing.T) {
	greeting := "220 mail.example.com ESMTP\r\n"
	ehloResponse := "250-mail.example.com\r\n250 AUTH\r\n"

	serverPort, cleanup := startMockSMTPServer(t, greeting, ehloResponse)
	defer cleanup()

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

	plugin := &SMTPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	if len(service.SecurityFindings) != 1 {
		t.Fatalf("expected 1 finding (smtp-cleartext only), got %d: %+v", len(service.SecurityFindings), service.SecurityFindings)
	}
	if service.SecurityFindings[0].ID != "smtp-cleartext" {
		t.Errorf("expected finding ID 'smtp-cleartext', got %q", service.SecurityFindings[0].ID)
	}
}

// TestSMTPSecurityFindingsNoAuth verifies that smtp-no-auth is emitted alongside
// smtp-cleartext when the EHLO response contains no AUTH capability.
func TestSMTPSecurityFindingsNoAuth(t *testing.T) {
	greeting := "220 mail.example.com ESMTP\r\n"
	ehloResponse := "250-mail.example.com\r\n250-SIZE 10240000\r\n250 SMTPUTF8\r\n"

	serverPort, cleanup := startMockSMTPServer(t, greeting, ehloResponse)
	defer cleanup()

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

	plugin := &SMTPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	if len(service.SecurityFindings) != 2 {
		t.Fatalf("expected 2 findings (smtp-cleartext + smtp-no-auth), got %d: %+v", len(service.SecurityFindings), service.SecurityFindings)
	}

	ids := map[string]bool{}
	for _, f := range service.SecurityFindings {
		ids[f.ID] = true
	}
	if !ids["smtp-cleartext"] {
		t.Error("expected smtp-cleartext finding")
	}
	if !ids["smtp-no-auth"] {
		t.Error("expected smtp-no-auth finding")
	}

	for _, f := range service.SecurityFindings {
		if f.ID == "smtp-no-auth" && f.Severity != plugins.SeverityLow {
			t.Errorf("expected smtp-no-auth severity low, got %s", f.Severity)
		}
	}
}

// TestSMTPSecurityFindingsEHLOError verifies that smtp-no-auth is NOT emitted when the
// server rejects EHLO with an error response (e.g. 500). In this case DetectSMTP returns
// nil AuthMethods and only smtp-cleartext should be emitted.
func TestSMTPSecurityFindingsEHLOError(t *testing.T) {
	greeting := "220 mail.example.com ESMTP\r\n"
	ehloResponse := "500 Command unrecognized\r\n"

	serverPort, cleanup := startMockSMTPServer(t, greeting, ehloResponse)
	defer cleanup()

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

	plugin := &SMTPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	if len(service.SecurityFindings) != 1 {
		t.Fatalf("expected 1 finding (smtp-cleartext only), got %d: %+v", len(service.SecurityFindings), service.SecurityFindings)
	}
	if service.SecurityFindings[0].ID != "smtp-cleartext" {
		t.Errorf("expected finding ID 'smtp-cleartext', got %q", service.SecurityFindings[0].ID)
	}
	for _, f := range service.SecurityFindings {
		if f.ID == "smtp-no-auth" {
			t.Error("smtp-no-auth should not be emitted when EHLO returns an error")
		}
	}
}

// TestSMTPSecurityFindingsDisabled verifies that no findings are emitted when Misconfigs=false.
func TestSMTPSecurityFindingsDisabled(t *testing.T) {
	greeting := "220 mail.example.com ESMTP\r\n"
	ehloResponse := "250-mail.example.com\r\n250-SIZE 10240000\r\n250 SMTPUTF8\r\n"

	serverPort, cleanup := startMockSMTPServer(t, greeting, ehloResponse)
	defer cleanup()

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

	plugin := &SMTPPlugin{}
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

// startMockSMTPServerRelay starts a mock SMTP server that handles greeting, EHLO,
// and the open relay probe (MAIL FROM, RCPT TO, RSET).
func startMockSMTPServerRelay(t *testing.T, greeting, ehloResponse string, mailFromResp, rcptToResp, rsetResp string) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}

	tcpAddr := listener.Addr().(*net.TCPAddr)
	serverPort := tcpAddr.Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)

		// Greeting
		_, _ = conn.Write([]byte(greeting))
		// EHLO
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte(ehloResponse))
		// MAIL FROM
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte(mailFromResp))
		// RCPT TO
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte(rcptToResp))
		// RSET
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte(rsetResp))
	}()

	return serverPort, func() { listener.Close() }
}

// TestSMTPSecurityFindingsOpenRelay verifies that smtp-open-relay is emitted when the
// server accepts both MAIL FROM and RCPT TO with 250 responses.
func TestSMTPSecurityFindingsOpenRelay(t *testing.T) {
	greeting := "220 mail.example.com ESMTP\r\n"
	ehloResponse := "250-mail.example.com\r\n250 SIZE 10240000\r\n"

	serverPort, cleanup := startMockSMTPServerRelay(t, greeting, ehloResponse,
		"250 OK\r\n", "250 OK\r\n", "250 OK\r\n")
	defer cleanup()

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

	plugin := &SMTPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	if len(service.SecurityFindings) != 3 {
		t.Fatalf("expected 3 findings (smtp-cleartext, smtp-no-auth, smtp-open-relay), got %d: %+v",
			len(service.SecurityFindings), service.SecurityFindings)
	}

	ids := map[string]bool{}
	for _, f := range service.SecurityFindings {
		ids[f.ID] = true
	}
	if !ids["smtp-cleartext"] {
		t.Error("expected smtp-cleartext finding")
	}
	if !ids["smtp-no-auth"] {
		t.Error("expected smtp-no-auth finding")
	}
	if !ids["smtp-open-relay"] {
		t.Error("expected smtp-open-relay finding")
	}

	for _, f := range service.SecurityFindings {
		if f.ID == "smtp-open-relay" && f.Severity != plugins.SeverityHigh {
			t.Errorf("expected smtp-open-relay severity high, got %s", f.Severity)
		}
	}
}

// TestSMTPSecurityFindingsRelayRejected verifies that smtp-open-relay is NOT emitted
// when the server rejects RCPT TO with a 550 response.
func TestSMTPSecurityFindingsRelayRejected(t *testing.T) {
	greeting := "220 mail.example.com ESMTP\r\n"
	ehloResponse := "250-mail.example.com\r\n250 SIZE 10240000\r\n"

	serverPort, cleanup := startMockSMTPServerRelay(t, greeting, ehloResponse,
		"250 OK\r\n", "550 Relay denied\r\n", "250 OK\r\n")
	defer cleanup()

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

	plugin := &SMTPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	if len(service.SecurityFindings) != 2 {
		t.Fatalf("expected 2 findings (smtp-cleartext, smtp-no-auth), got %d: %+v",
			len(service.SecurityFindings), service.SecurityFindings)
	}

	ids := map[string]bool{}
	for _, f := range service.SecurityFindings {
		ids[f.ID] = true
	}
	if !ids["smtp-cleartext"] {
		t.Error("expected smtp-cleartext finding")
	}
	if !ids["smtp-no-auth"] {
		t.Error("expected smtp-no-auth finding")
	}
	if ids["smtp-open-relay"] {
		t.Error("smtp-open-relay should not be emitted when relay is rejected")
	}
}

// TestSMTPSecurityFindingsOpenRelayWithAuth verifies that smtp-open-relay fires even
// when the server advertises AUTH (so smtp-no-auth is suppressed).
func TestSMTPSecurityFindingsOpenRelayWithAuth(t *testing.T) {
	greeting := "220 mail.example.com ESMTP\r\n"
	ehloResponse := "250-mail.example.com\r\n250-AUTH LOGIN PLAIN\r\n250 SIZE 10240000\r\n"

	serverPort, cleanup := startMockSMTPServerRelay(t, greeting, ehloResponse,
		"250 OK\r\n", "250 OK\r\n", "250 OK\r\n")
	defer cleanup()

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

	plugin := &SMTPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	if len(service.SecurityFindings) != 2 {
		t.Fatalf("expected 2 findings (smtp-cleartext, smtp-open-relay), got %d: %+v",
			len(service.SecurityFindings), service.SecurityFindings)
	}

	ids := map[string]bool{}
	for _, f := range service.SecurityFindings {
		ids[f.ID] = true
	}
	if !ids["smtp-cleartext"] {
		t.Error("expected smtp-cleartext finding")
	}
	if !ids["smtp-open-relay"] {
		t.Error("expected smtp-open-relay finding")
	}
	if ids["smtp-no-auth"] {
		t.Error("smtp-no-auth should not be emitted when server advertises AUTH")
	}

	for _, f := range service.SecurityFindings {
		if f.ID == "smtp-open-relay" && f.Severity != plugins.SeverityHigh {
			t.Errorf("expected smtp-open-relay severity high, got %s", f.Severity)
		}
	}
}

func TestSMTP(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "smtp",
			Port:        25,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "bytemark/smtp",
			},
		},
	}

	p := &SMTPPlugin{}

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

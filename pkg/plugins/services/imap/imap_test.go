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
	"encoding/binary"
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
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("S8TLS BAD STARTTLS not supported\r\n"))
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
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("S8TLS BAD STARTTLS not supported\r\n"))
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

func TestIMAPSTARTTLSThenTLS10EmitsWeakVersionNotCleartext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveIMAPSTARTTLSThen10(c)
		}
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	conn, err := net.DialTimeout("tcp", tcpAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    netip.MustParseAddrPort(tcpAddr.String()),
		Misconfigs: true,
	}
	service, err := (&IMAPPlugin{}).Run(conn, 2*time.Second, target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if service == nil {
		t.Fatal("Run returned nil")
	}
	ids := map[string]bool{}
	for _, f := range service.SecurityFindings {
		ids[f.ID] = true
	}
	if !ids["imap-cleartext"] {
		t.Fatalf("STARTTLS-then-1.0 missing imap-cleartext (plaintext listener still open): %+v", service.SecurityFindings)
	}
	if !ids["tls-weak-version-10"] {
		t.Fatalf("STARTTLS-then-1.0 missing tls-weak-version-10: %+v", service.SecurityFindings)
	}
	if service.TLS {
		t.Fatal("opportunistic STARTTLS must not set Service.TLS (implicit TLS only)")
	}
}

func serveIMAPSTARTTLSThen10(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte("* OK IMAP server ready\r\n"))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		return
	}
	msg := string(buf[:n])
	if len(msg) >= 9 && msg[len(msg)-10:] != "" {
		_, _ = c.Write([]byte("* CAPABILITY IMAP4rev1 STARTTLS\r\n7FYWU8I4 OK CAPABILITY completed\r\n"))
	}
	n, err = c.Read(buf)
	if err != nil {
		return
	}
	_, _ = c.Write([]byte("S8TLS OK begin TLS\r\n"))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	nbody := int(binary.BigEndian.Uint16(hdr[3:5]))
	body := make([]byte, nbody)
	if _, err := io.ReadFull(c, body); err != nil {
		return
	}
	_, _ = c.Write(rawServerHelloTLS10())
}

func rawServerHelloTLS10() []byte {
	body := []byte{0x03, 0x01}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00, 0x00, 0x2f, 0x00)
	hs := []byte{0x02, 0x00, 0x00, byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
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

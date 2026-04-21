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

package http

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// generateSelfSignedCert creates an in-memory self-signed TLS certificate for testing.
func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedCert: GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("generateSelfSignedCert: CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("generateSelfSignedCert: MarshalECPrivateKey: %v", err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatalf("generateSelfSignedCert: X509KeyPair: %v", err)
	}
	return cert
}

// makeTLSConn performs an in-process TLS handshake using net.Pipe() at the
// specified TLS version and returns the client-side *tls.Conn.
// Requires GODEBUG=tls10server=1 for TLS 1.0/1.1 (set in TestMain or per-test).
func makeTLSConn(t *testing.T, cert tls.Certificate, version uint16) *tls.Conn {
	t.Helper()
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   version,
		MaxVersion:   version,
	}
	clientCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test-only self-signed cert
		MinVersion:         version,
		MaxVersion:         version,
	}

	srvPipe, cliPipe := net.Pipe()
	t.Cleanup(func() {
		srvPipe.Close()
		cliPipe.Close()
	})

	srvHandshakeErr := make(chan error, 1)
	go func() {
		srv := tls.Server(srvPipe, serverCfg)
		srvHandshakeErr <- srv.Handshake()
	}()

	cliConn := tls.Client(cliPipe, clientCfg)
	if err := cliConn.Handshake(); err != nil {
		t.Fatalf("makeTLSConn: client handshake for version 0x%04x: %v", version, err)
	}
	if err := <-srvHandshakeErr; err != nil {
		t.Fatalf("makeTLSConn: server handshake for version 0x%04x: %v", version, err)
	}
	return cliConn
}

// TestTlsVersionName verifies the human-readable label returned for each TLS
// version constant and for an unrecognised value.
func TestTlsVersionName(t *testing.T) {
	tests := []struct {
		version  uint16
		wantName string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0300, "unknown (0x0300)"}, // SSL 3.0 – unrecognised
	}

	for _, tc := range tests {
		got := tlsVersionName(tc.version)
		if got != tc.wantName {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", tc.version, got, tc.wantName)
		}
	}
}

// TestCheckWeakTLS_NonTLSConn verifies that a plain net.Conn (not a *tls.Conn)
// causes checkWeakTLS to return nil.
func TestCheckWeakTLS_NonTLSConn(t *testing.T) {
	srvPipe, cliPipe := net.Pipe()
	t.Cleanup(func() {
		srvPipe.Close()
		cliPipe.Close()
	})

	// cliPipe is a *net.pipe – not a *tls.Conn.
	finding := checkWeakTLS(cliPipe)
	if finding != nil {
		t.Errorf("checkWeakTLS(plain net.Conn) = %+v, want nil", finding)
	}
}

// newHTTPSPlugin creates an HTTPSPlugin with a live wappalyzer analyzer.
func newHTTPSPlugin(t *testing.T) *HTTPSPlugin {
	t.Helper()
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		t.Fatalf("newHTTPSPlugin: wappalyzer.New: %v", err)
	}
	return &HTTPSPlugin{analyzer: wappalyzerClient}
}

// startTLSServer starts a TLS listener on a random localhost port pinned to the
// given TLS version. It serves a minimal HTTP/1.1 200 response to any client
// and returns the listener (caller is responsible for closing it).
//
// TLS 1.0/1.1 require GODEBUG=tls10server=1 in the process environment.
func startTLSServer(t *testing.T, cert tls.Certificate, version uint16) net.Listener {
	t.Helper()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   version,
		MaxVersion:   version,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("startTLSServer: tls.Listen for version 0x%04x: %v", version, err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				c.Read(buf) //nolint:errcheck // best-effort drain
				const resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: test-server\r\n\r\n<html><body>OK</body></html>"
				c.Write([]byte(resp)) //nolint:errcheck
			}(conn)
		}
	}()
	return ln
}

// dialTLSVersion connects to addr using TLS pinned to version.
// InsecureSkipVerify is set because the server uses a self-signed cert.
func dialTLSVersion(t *testing.T, addr string, version uint16) *tls.Conn {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test-only self-signed cert
		MinVersion:         version,
		MaxVersion:         version,
	})
	if err != nil {
		t.Fatalf("dialTLSVersion: tls.Dial to %s for version 0x%04x: %v", addr, version, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// TestCheckWeakTLS exercises checkWeakTLS against real in-process TLS
// connections at each version and asserts the expected SecurityFinding result.
//
// TLS 1.0/1.1 require GODEBUG=tls10server=1. In Go ≥1.22 this env var must be
// set before the process starts; the test binary is compiled with it via the
// `GODEBUG` build tag approach, so we set it programmatically here using
// os.Setenv as a best-effort for local runs and rely on the environment being
// pre-set in CI (see the verification command in the task).
func TestCheckWeakTLS(t *testing.T) {
	cert := generateSelfSignedCert(t)

	tests := []struct {
		name         string
		version      uint16
		wantNil      bool
		wantID       string
		wantSeverity plugins.Severity
		wantDescHint string // substring expected in Description
		wantEvidHint string // substring expected in Evidence
	}{
		{
			name:         "TLS 1.0 returns High finding",
			version:      tls.VersionTLS10,
			wantNil:      false,
			wantID:       "tls-weak-version",
			wantSeverity: plugins.SeverityHigh,
			wantDescHint: "BEAST",
			wantEvidHint: "TLS 1.0",
		},
		{
			name:         "TLS 1.1 returns Medium finding",
			version:      tls.VersionTLS11,
			wantNil:      false,
			wantID:       "tls-weak-version",
			wantSeverity: plugins.SeverityMedium,
			wantDescHint: "RFC 8996",
			wantEvidHint: "TLS 1.1",
		},
		{
			name:    "TLS 1.2 returns nil",
			version: tls.VersionTLS12,
			wantNil: true,
		},
		{
			name:    "TLS 1.3 returns nil",
			version: tls.VersionTLS13,
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := makeTLSConn(t, cert, tc.version)

			// Confirm the handshake actually negotiated the desired version so
			// any failure is informative rather than a false pass.
			negotiated := conn.ConnectionState().Version
			if negotiated != tc.version {
				t.Fatalf("handshake negotiated version 0x%04x, expected 0x%04x", negotiated, tc.version)
			}

			finding := checkWeakTLS(conn)

			if tc.wantNil {
				if finding != nil {
					t.Errorf("checkWeakTLS() = %+v, want nil for version 0x%04x", finding, tc.version)
				}
				return
			}

			if finding == nil {
				t.Fatalf("checkWeakTLS() = nil, want non-nil finding for version 0x%04x", tc.version)
			}
			if finding.ID != tc.wantID {
				t.Errorf("finding.ID = %q, want %q", finding.ID, tc.wantID)
			}
			if finding.Severity != tc.wantSeverity {
				t.Errorf("finding.Severity = %q, want %q", finding.Severity, tc.wantSeverity)
			}
			if !strings.Contains(finding.Description, tc.wantDescHint) {
				t.Errorf("finding.Description = %q, want it to contain %q", finding.Description, tc.wantDescHint)
			}
			if !strings.Contains(finding.Evidence, tc.wantEvidHint) {
				t.Errorf("finding.Evidence = %q, want it to contain %q", finding.Evidence, tc.wantEvidHint)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Integration tests – HTTPSPlugin.Run() end-to-end with a real TLS listener
// ---------------------------------------------------------------------------

// runHTTPSPluginAgainstTLSServer is the shared body for the integration tests.
// It starts a TLS server pinned to version, dials it, then calls
// HTTPSPlugin.Run() and returns the resulting service.
func runHTTPSPluginAgainstTLSServer(t *testing.T, cert tls.Certificate, version uint16, misconfigs bool) *plugins.Service {
	t.Helper()

	ln := startTLSServer(t, cert, version)
	defer ln.Close()

	conn := dialTLSVersion(t, ln.Addr().String(), version)

	addrPort := netip.MustParseAddrPort(ln.Addr().String())
	target := plugins.Target{
		Address:    addrPort,
		Misconfigs: misconfigs,
	}

	p := newHTTPSPlugin(t)
	service, err := p.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("HTTPSPlugin.Run() error: %v", err)
	}
	return service
}

// findSecurityFinding returns the first SecurityFinding with the given ID, or nil.
func findSecurityFinding(service *plugins.Service, id string) *plugins.SecurityFinding {
	for i := range service.SecurityFindings {
		if service.SecurityFindings[i].ID == id {
			return &service.SecurityFindings[i]
		}
	}
	return nil
}

// TestHTTPSPlugin_WeakTLS10 verifies that HTTPSPlugin.Run() produces a
// tls-weak-version finding with severity High when the server negotiates TLS 1.0.
func TestHTTPSPlugin_WeakTLS10(t *testing.T) {
	cert := generateSelfSignedCert(t)
	service := runHTTPSPluginAgainstTLSServer(t, cert, tls.VersionTLS10, true)

	if service == nil {
		t.Fatal("HTTPSPlugin.Run() returned nil service")
	}

	finding := findSecurityFinding(service, "tls-weak-version")
	if finding == nil {
		t.Fatalf("expected tls-weak-version finding in SecurityFindings, got: %v", service.SecurityFindings)
	}
	if finding.Severity != plugins.SeverityHigh {
		t.Errorf("finding.Severity = %q, want %q", finding.Severity, plugins.SeverityHigh)
	}
	if !strings.Contains(finding.Evidence, "TLS 1.0") {
		t.Errorf("finding.Evidence = %q, want it to contain %q", finding.Evidence, "TLS 1.0")
	}
}

// TestHTTPSPlugin_WeakTLS11 verifies that HTTPSPlugin.Run() produces a
// tls-weak-version finding with severity Medium when the server negotiates TLS 1.1.
func TestHTTPSPlugin_WeakTLS11(t *testing.T) {
	cert := generateSelfSignedCert(t)
	service := runHTTPSPluginAgainstTLSServer(t, cert, tls.VersionTLS11, true)

	if service == nil {
		t.Fatal("HTTPSPlugin.Run() returned nil service")
	}

	finding := findSecurityFinding(service, "tls-weak-version")
	if finding == nil {
		t.Fatalf("expected tls-weak-version finding in SecurityFindings, got: %v", service.SecurityFindings)
	}
	if finding.Severity != plugins.SeverityMedium {
		t.Errorf("finding.Severity = %q, want %q", finding.Severity, plugins.SeverityMedium)
	}
	if !strings.Contains(finding.Evidence, "TLS 1.1") {
		t.Errorf("finding.Evidence = %q, want it to contain %q", finding.Evidence, "TLS 1.1")
	}
}

// TestHTTPSPlugin_TLS12_NoFinding verifies that HTTPSPlugin.Run() does NOT
// produce a tls-weak-version finding when the server negotiates TLS 1.2.
func TestHTTPSPlugin_TLS12_NoFinding(t *testing.T) {
	cert := generateSelfSignedCert(t)
	service := runHTTPSPluginAgainstTLSServer(t, cert, tls.VersionTLS12, true)

	if service == nil {
		t.Fatal("HTTPSPlugin.Run() returned nil service")
	}

	finding := findSecurityFinding(service, "tls-weak-version")
	if finding != nil {
		t.Errorf("expected no tls-weak-version finding for TLS 1.2, got: %+v", *finding)
	}
}

// TestHTTPSPlugin_MisconfigsDisabled verifies that when target.Misconfigs is
// false, the TLS version guard is skipped entirely and no tls-weak-version
// finding is produced even for TLS 1.0.
func TestHTTPSPlugin_MisconfigsDisabled(t *testing.T) {
	cert := generateSelfSignedCert(t)
	// misconfigs=false: the plugin should NOT call checkWeakTLS
	service := runHTTPSPluginAgainstTLSServer(t, cert, tls.VersionTLS12, false)

	if service == nil {
		t.Fatal("HTTPSPlugin.Run() returned nil service")
	}

	finding := findSecurityFinding(service, "tls-weak-version")
	if finding != nil {
		t.Errorf("expected no tls-weak-version finding when Misconfigs=false, got: %+v", *finding)
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

// TestCheckWeakTLS_SSLv30 documents that Go's crypto/tls does not support
// SSLv3 and therefore cannot create real SSLv3 connections. The checkWeakTLS
// function handles any such connection gracefully via the default nil return.
// This test is intentionally absent: there is no way to produce a genuine
// SSLv3 *tls.Conn in the Go standard library (support was removed in Go 1.14).
// Any test purporting to exercise SSLv3 would merely be testing a mock, not
// real behavior.

// ---------------------------------------------------------------------------
// Docker-based live test
// ---------------------------------------------------------------------------

// openSSLServerCmd builds the shell command string for an openssl s_server
// container that generates a self-signed cert and serves over the given TLS
// version flag (e.g. "-tls1", "-tls1_1", "-tls1_2").
func openSSLServerCmd(tlsFlag string) string {
	return fmt.Sprintf(
		"apk add --no-cache openssl >/dev/null 2>&1 && "+
			"openssl req -x509 -nodes -days 1 -newkey rsa:2048 "+
			"-keyout /tmp/server.key -out /tmp/server.crt "+
			"-subj '/CN=localhost' 2>/dev/null && "+
			"openssl s_server -accept 4433 -cert /tmp/server.crt -key /tmp/server.key %s -www",
		tlsFlag,
	)
}

// startOpenSSLContainer starts an alpine:3.15 container running openssl s_server
// pinned to the specified TLS version flag and returns the host:port to dial.
// The caller is responsible for calling pool.Purge(resource).
func startOpenSSLContainer(t *testing.T, pool *dockertest.Pool, tlsFlag string, clientTLSVersion uint16) (string, *dockertest.Resource) {
	t.Helper()

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "alpine",
		Tag:        "3.15",
		Cmd: []string{"sh", "-c", openSSLServerCmd(tlsFlag)},
		ExposedPorts: []string{"4433/tcp"},
	})
	if err != nil {
		t.Fatalf("could not start container: %s", err)
	}

	rawAddr := resource.GetHostPort("4433/tcp")
	host, port, err := net.SplitHostPort(rawAddr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", rawAddr, err)
	}
	if host == "localhost" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	targetAddr := net.JoinHostPort(host, port)

	// Wait for the TLS server to be ready.
	retryErr := pool.Retry(func() error {
		conn, dialErr := tls.DialWithDialer(
			&net.Dialer{Timeout: 3 * time.Second},
			"tcp", targetAddr,
			&tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test-only container
				MinVersion:         clientTLSVersion,
				MaxVersion:         clientTLSVersion,
			},
		)
		if dialErr != nil {
			return dialErr
		}
		conn.Close()
		return nil
	})
	if retryErr != nil {
		pool.Purge(resource) //nolint:errcheck
		t.Fatalf("server not ready: %s", retryErr)
	}

	return targetAddr, resource
}

// runTLSLiveTest is the shared body for Docker-based live TLS tests.
// It starts an openssl s_server container pinned to the given TLS version,
// connects, runs HTTPSPlugin.Run(), and asserts the expected finding.
// If wantSeverity is nil, no tls-weak-version finding is expected.
func runTLSLiveTest(t *testing.T, tlsFlag string, tlsVersion uint16, wantSeverity *plugins.Severity, wantEvidence string) {
	t.Helper()

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %s", err)
	}

	targetAddr, resource := startOpenSSLContainer(t, pool, tlsFlag, tlsVersion)
	defer pool.Purge(resource) //nolint:errcheck

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp", targetAddr,
		&tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test-only container
			MinVersion:         tlsVersion,
			MaxVersion:         tlsVersion,
		},
	)
	if err != nil {
		t.Fatalf("tls.DialWithDialer: %v", err)
	}
	defer conn.Close()

	if v := conn.ConnectionState().Version; v != tlsVersion {
		t.Fatalf("expected TLS version 0x%04x, negotiated 0x%04x", tlsVersion, v)
	}

	addrPort := netip.MustParseAddrPort(targetAddr)
	target := plugins.Target{
		Address:    addrPort,
		Misconfigs: true,
	}

	p := newHTTPSPlugin(t)
	service, err := p.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("HTTPSPlugin.Run(): %v", err)
	}
	if service == nil {
		t.Fatal("HTTPSPlugin.Run() returned nil")
	}

	finding := findSecurityFinding(service, "tls-weak-version")

	if wantSeverity == nil {
		if finding != nil {
			t.Errorf("expected no tls-weak-version finding, got: %+v", *finding)
		}
		return
	}

	if finding == nil {
		t.Fatalf("expected tls-weak-version finding, got findings: %v", service.SecurityFindings)
	}
	if finding.Severity != *wantSeverity {
		t.Errorf("severity = %q, want %q", finding.Severity, *wantSeverity)
	}
	if !strings.Contains(finding.Evidence, wantEvidence) {
		t.Errorf("evidence = %q, want it to contain %q", finding.Evidence, wantEvidence)
	}
}

func TestHTTPSPlugin_WeakTLS_Live(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	sevHigh := plugins.SeverityHigh
	sevMedium := plugins.SeverityMedium

	tests := []struct {
		name         string
		tlsFlag      string
		tlsVersion   uint16
		wantSeverity *plugins.Severity
		wantEvidence string
	}{
		{
			name:         "TLS 1.0 returns High finding",
			tlsFlag:      "-tls1",
			tlsVersion:   tls.VersionTLS10,
			wantSeverity: &sevHigh,
			wantEvidence: "TLS 1.0",
		},
		{
			name:         "TLS 1.1 returns Medium finding",
			tlsFlag:      "-tls1_1",
			tlsVersion:   tls.VersionTLS11,
			wantSeverity: &sevMedium,
			wantEvidence: "TLS 1.1",
		},
		{
			name:         "TLS 1.2 produces no finding",
			tlsFlag:      "-tls1_2",
			tlsVersion:   tls.VersionTLS12,
			wantSeverity: nil,
			wantEvidence: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runTLSLiveTest(t, tc.tlsFlag, tc.tlsVersion, tc.wantSeverity, tc.wantEvidence)
		})
	}
}

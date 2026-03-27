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

package anydesk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

var defaultTarget = plugins.Target{
	Address: netip.MustParseAddrPort("127.0.0.1:7070"),
}

func TestAnyDeskPlugin_Name(t *testing.T) {
	p := &AnyDeskPlugin{}
	if got := p.Name(); got != "anydesk" {
		t.Errorf("Name() = %q, want %q", got, "anydesk")
	}
}

func TestAnyDeskPlugin_Type(t *testing.T) {
	p := &AnyDeskPlugin{}
	if got := p.Type(); got != plugins.TCPTLS {
		t.Errorf("Type() = %v, want TCPTLS", got)
	}
}

func TestAnyDeskPlugin_PortPriority(t *testing.T) {
	p := &AnyDeskPlugin{}

	tests := []struct {
		port uint16
		want bool
	}{
		{7070, true},
		{6568, true},
		{443, false},
		{8080, false},
	}

	for _, tt := range tests {
		if got := p.PortPriority(tt.port); got != tt.want {
			t.Errorf("PortPriority(%d) = %v, want %v", tt.port, got, tt.want)
		}
	}
}

func TestAnyDeskPlugin_Priority(t *testing.T) {
	p := &AnyDeskPlugin{}
	if got := p.Priority(); got != 175 {
		t.Errorf("Priority() = %d, want 175", got)
	}
}

func TestBuildAnyDeskCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Unknown version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:anydesk:anydesk:*:*:*:*:*:*:*:*",
		},
		{
			name:    "Known version",
			version: "7.1.5",
			want:    "cpe:2.3:a:anydesk:anydesk:7.1.5:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildAnyDeskCPE(tt.version); got != tt.want {
				t.Errorf("buildAnyDeskCPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

// generateTestCert creates a self-signed TLS certificate for testing.
func generateTestCert(subjectCN, issuerCN string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: subjectCN},
		Issuer:       pkix.Name{CommonName: issuerCN},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(50 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

// startTLSServer starts a TLS server with the given certificate on a random port.
// Returns the listener address and a cleanup function.
func startTLSServer(t *testing.T, cert tls.Certificate) (string, func()) {
	t.Helper()

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("failed to start TLS server: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Keep connection alive so client can complete TLS handshake and read cert.
			go func(c net.Conn) {
				buf := make([]byte, 1)
				c.Read(buf) //nolint:errcheck
				c.Close()
			}(conn)
		}
	}()

	return listener.Addr().String(), func() { listener.Close() }
}

func TestAnyDeskPlugin_Run_ValidAnyDesk(t *testing.T) {
	cert, err := generateTestCert("AnyDesk Client", "AnyDesk Client")
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}

	addr, cleanup := startTLSServer(t, cert)
	defer cleanup()

	// Connect with TLS
	tlsConn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("failed to dial TLS: %v", err)
	}
	defer tlsConn.Close()

	target := plugins.Target{
		Address: netip.MustParseAddrPort(addr),
	}

	p := &AnyDeskPlugin{}
	result, err := p.Run(tlsConn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result == nil {
		t.Fatal("Run() returned nil, expected AnyDesk detection")
	}

	if result.Protocol != ANYDESK {
		t.Errorf("Protocol = %q, want %q", result.Protocol, ANYDESK)
	}
	if !result.TLS {
		t.Error("TLS = false, want true")
	}
}

func TestAnyDeskPlugin_Run_NonAnyDeskCert(t *testing.T) {
	cert, err := generateTestCert("Example Server", "Example CA")
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}

	addr, cleanup := startTLSServer(t, cert)
	defer cleanup()

	tlsConn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("failed to dial TLS: %v", err)
	}
	defer tlsConn.Close()

	target := defaultTarget

	p := &AnyDeskPlugin{}
	result, err := p.Run(tlsConn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result != nil {
		t.Errorf("Run() = %+v, want nil for non-AnyDesk cert", result)
	}
}

func TestAnyDeskPlugin_Run_NonTLSConn(t *testing.T) {
	// Create a plain TCP connection (not TLS) — should return nil
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	target := defaultTarget

	p := &AnyDeskPlugin{}
	result, err := p.Run(client, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result != nil {
		t.Errorf("Run() = %+v, want nil for non-TLS conn", result)
	}
}

func TestAnyDeskPlugin_Run_MetadataAndCPE(t *testing.T) {
	cert, err := generateTestCert("AnyDesk Client", "AnyDesk Client")
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}

	addr, cleanup := startTLSServer(t, cert)
	defer cleanup()

	tlsConn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("failed to dial TLS: %v", err)
	}
	defer tlsConn.Close()

	target := defaultTarget

	p := &AnyDeskPlugin{}
	result, err := p.Run(tlsConn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result == nil {
		t.Fatal("Run() returned nil")
	}

	// Unmarshal the raw metadata
	metadata := result.Metadata()
	anydesk, ok := metadata.(plugins.ServiceAnyDesk)
	if !ok {
		t.Fatalf("metadata type = %T, want ServiceAnyDesk", metadata)
	}

	if anydesk.CertSubject != "AnyDesk Client" {
		t.Errorf("CertSubject = %q, want %q", anydesk.CertSubject, "AnyDesk Client")
	}
	if !anydesk.SelfSigned {
		t.Error("SelfSigned = false, want true")
	}
	if len(anydesk.CPEs) == 0 {
		t.Fatal("CPEs is empty")
	}
	expectedCPE := "cpe:2.3:a:anydesk:anydesk:*:*:*:*:*:*:*:*"
	if anydesk.CPEs[0] != expectedCPE {
		t.Errorf("CPE = %q, want %q", anydesk.CPEs[0], expectedCPE)
	}
}

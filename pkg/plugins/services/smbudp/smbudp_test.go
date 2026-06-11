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

package smbudp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestPlugin_Metadata(t *testing.T) {
	p := &Plugin{}

	if p.Name() != "smbudp" {
		t.Errorf("expected name smbudp, got %s", p.Name())
	}
	if p.Type() != plugins.UDP {
		t.Errorf("expected protocol type UDP, got %v", p.Type())
	}
	if p.Priority() != smbudpPriority {
		t.Errorf("expected priority %d, got %d", smbudpPriority, p.Priority())
	}
	if !p.PortPriority(443) {
		t.Error("expected PortPriority(443) to return true")
	}
	if p.PortPriority(80) {
		t.Error("expected PortPriority(80) to return false")
	}
}

func TestPlugin_RunEmptyTarget(t *testing.T) {
	p := &Plugin{}
	// Empty target should return nil (no address to dial)
	target := plugins.Target{}
	conn, _ := net.Dial("udp", "127.0.0.1:1")
	if conn != nil {
		defer conn.Close()
	}
	service, err := p.Run(conn, 1*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if service != nil {
		t.Error("expected nil service for empty target")
	}
}

func TestPlugin_RunNoServer(t *testing.T) {
	// Target a port with no QUIC server -- should return nil (timeout/no response)
	p := &Plugin{}
	addr := netip.MustParseAddrPort("127.0.0.1:19999")
	target := plugins.Target{Address: addr}

	conn, err := net.Dial("udp", "127.0.0.1:19999")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	service, err := p.Run(conn, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if service != nil {
		t.Error("expected nil service when no QUIC server is running")
	}
}

// generateTestCert creates a self-signed TLS certificate for testing.
func generateTestCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"smb.test.local"},
	}
	template.Subject.CommonName = "smb.test.local"
	template.Subject.Organization = []string{"Test Org"}
	template.Issuer.CommonName = "Test CA"
	template.Issuer.Organization = []string{"Test CA Org"}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

func TestPlugin_RunWithMockServer(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpnSMB},
	}

	// Listen on a random port
	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConf, nil)
	if err != nil {
		t.Fatalf("failed to start QUIC listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.UDPAddr)

	// Mock server: accept one connection then close
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		// Keep connection alive briefly so plugin can extract metadata
		time.Sleep(500 * time.Millisecond)
		conn.CloseWithError(0, "")
	}()

	// Run the plugin against the mock server
	p := &Plugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort(addr.String()),
	}

	// Use a dummy conn (smbudp ignores it and dials its own)
	dummyConn, err := net.Dial("udp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer dummyConn.Close()

	service, err := p.Run(dummyConn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if service == nil {
		t.Fatal("Run returned nil service; expected smbudp detection")
	}
	if service.Protocol != "smbudp" {
		t.Errorf("expected protocol smbudp, got %s", service.Protocol)
	}

	// Verify metadata contains certificate and QUIC version info
	var meta plugins.ServiceSMBUDP
	if err := json.Unmarshal(service.Raw, &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}
	if meta.CertSubject == "" {
		t.Error("expected non-empty CertSubject in metadata")
	}
	if len(meta.QUICVersions) == 0 {
		t.Error("expected at least one QUIC version in metadata")
	}

	<-serverDone
}

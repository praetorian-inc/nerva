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

package sstp

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// mockSSTPServer implements a minimal SSTP server for testing
type mockSSTPServer struct {
	serverHeader string
	statusCode   int
}

func (m *mockSSTPServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read the request line
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	// Read headers until empty line
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}

	// Verify it's an SSTP_DUPLEX_POST request
	if !strings.HasPrefix(requestLine, "SSTP_DUPLEX_POST") {
		// Not SSTP, send 404
		response := "HTTP/1.1 404 Not Found\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n"
		conn.Write([]byte(response))
		return
	}

	// Send SSTP response
	response := fmt.Sprintf("HTTP/1.1 %d OK\r\n", m.statusCode)
	if m.serverHeader != "" {
		response += fmt.Sprintf("Server: %s\r\n", m.serverHeader)
	}
	response += "Content-Length: 18446744073709551615\r\n"
	response += "\r\n"

	conn.Write([]byte(response))
}

func startMockSSTPServer(t *testing.T, serverHeader string, statusCode int) (string, func()) {
	// Generate a self-signed certificate for testing
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}

	addr := listener.Addr().String()
	server := &mockSSTPServer{
		serverHeader: serverHeader,
		statusCode:   statusCode,
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.handleConnection(conn)
		}
	}()

	cleanup := func() {
		listener.Close()
	}

	return addr, cleanup
}

func TestSSTPPlugin_WindowsSSTP(t *testing.T) {
	addr, cleanup := startMockSSTPServer(t, "Microsoft-HTTPAPI/2.0", 200)
	defer cleanup()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	target := plugins.Target{
		Host: host,
	}
	target.Address, _ = netip.ParseAddrPort(addr)

	// Establish TLS connection
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	plugin := &SSTPluginHTTPS{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if service == nil {
		t.Fatal("Expected service to be detected, got nil")
	}

	if service.Protocol != plugins.ProtoSSTP {
		t.Errorf("Expected protocol %s, got %s", plugins.ProtoSSTP, service.Protocol)
	}

	// Check metadata
	metadata := service.Metadata()
	sstpService, ok := metadata.(plugins.ServiceSSTP)
	if !ok {
		t.Fatalf("Expected ServiceSSTP metadata, got %T", metadata)
	}

	if sstpService.Server != "Microsoft-HTTPAPI/2.0" {
		t.Errorf("Expected Server 'Microsoft-HTTPAPI/2.0', got '%s'", sstpService.Server)
	}

	if sstpService.Vendor != "Microsoft" {
		t.Errorf("Expected Vendor 'Microsoft', got '%s'", sstpService.Vendor)
	}

	if len(sstpService.CPEs) == 0 {
		t.Error("Expected CPEs to be populated for Windows SSTP")
	}
}

func TestSSTPPlugin_MikroTikSSTP(t *testing.T) {
	addr, cleanup := startMockSSTPServer(t, "MikroTik-SSTP", 200)
	defer cleanup()

	time.Sleep(100 * time.Millisecond)

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	target := plugins.Target{
		Host: host,
	}
	target.Address, _ = netip.ParseAddrPort(addr)

	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	plugin := &SSTPluginHTTPS{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if service == nil {
		t.Fatal("Expected service to be detected, got nil")
	}

	metadata := service.Metadata()
	sstpService, ok := metadata.(plugins.ServiceSSTP)
	if !ok {
		t.Fatalf("Expected ServiceSSTP metadata, got %T", metadata)
	}

	if sstpService.Server != "MikroTik-SSTP" {
		t.Errorf("Expected Server 'MikroTik-SSTP', got '%s'", sstpService.Server)
	}

	if sstpService.Vendor != "MikroTik" {
		t.Errorf("Expected Vendor 'MikroTik', got '%s'", sstpService.Vendor)
	}
}

func TestSSTPPlugin_Non200Response(t *testing.T) {
	addr, cleanup := startMockSSTPServer(t, "Microsoft-HTTPAPI/2.0", 404)
	defer cleanup()

	time.Sleep(100 * time.Millisecond)

	target := plugins.Target{}
	target.Address, _ = netip.ParseAddrPort(addr)

	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	plugin := &SSTPluginHTTPS{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	// Should return nil service for non-200 response
	if service != nil {
		t.Error("Expected nil service for non-200 response")
	}
}

func TestSSTPPlugin_PortPriority(t *testing.T) {
	plugin := &SSTPluginHTTPS{}

	// Port 443 should have priority
	if !plugin.PortPriority(443) {
		t.Error("Expected port 443 to have priority")
	}

	// Other ports should not have high priority
	if plugin.PortPriority(80) {
		t.Error("Expected port 80 to not have priority for SSTP")
	}
}

func TestSSTPPlugin_Type(t *testing.T) {
	plugin := &SSTPluginHTTPS{}

	if plugin.Type() != plugins.TCPTLS {
		t.Errorf("Expected Type() to return TCPTLS, got %v", plugin.Type())
	}
}

func TestSSTPPlugin_Name(t *testing.T) {
	plugin := &SSTPluginHTTPS{}

	if plugin.Name() != "sstp" {
		t.Errorf("Expected Name() to return 'sstp', got %s", plugin.Name())
	}
}

func TestSSTPPlugin_Priority(t *testing.T) {
	plugin := &SSTPluginHTTPS{}

	// SSTP should run before generic HTTPS (priority 300 suggested)
	priority := plugin.Priority()
	if priority <= 1 {
		t.Errorf("Expected Priority() > 1 to run before HTTPS, got %d", priority)
	}
}

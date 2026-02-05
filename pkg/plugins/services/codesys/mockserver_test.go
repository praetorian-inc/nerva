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

//go:build integration

package codesys

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// MockCODESYSServer simulates a CODESYS V2 PLC for integration testing
type MockCODESYSServer struct {
	listener net.Listener
	port     int
	done     chan struct{}
}

// NewMockCODESYSServer creates and starts a mock CODESYS server
func NewMockCODESYSServer() (*MockCODESYSServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	server := &MockCODESYSServer{
		listener: listener,
		port:     listener.Addr().(*net.TCPAddr).Port,
		done:     make(chan struct{}),
	}

	go server.serve()
	return server, nil
}

func (s *MockCODESYSServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				continue
			}
		}
		go s.handleConnection(conn)
	}
}

func (s *MockCODESYSServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read the request
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	// Validate CODESYS V2 signature
	if buf[0] != 0xbb || buf[1] != 0xbb {
		return
	}

	// Build a realistic V2 response
	// Response format: starts with 0xbb, then info at offsets 65, 97, 129
	response := make([]byte, 200)
	response[0] = 0xbb // Signature byte

	// OS Name at offset 65: "Linux"
	copy(response[65:], []byte("Linux\x00"))

	// OS Type at offset 97: "armv7l"
	copy(response[97:], []byte("armv7l\x00"))

	// Product Type at offset 129: "CODESYS Control for Raspberry Pi SL V3.5.18.0"
	copy(response[129:], []byte("CODESYS Control for Raspberry Pi SL V3.5.18.0\x00"))

	conn.Write(response)
}

func (s *MockCODESYSServer) Close() {
	close(s.done)
	s.listener.Close()
}

func (s *MockCODESYSServer) Port() int {
	return s.port
}

// TestCODESYSIntegration tests the plugin against a mock server
func TestCODESYSIntegration(t *testing.T) {
	// Start mock server
	server, err := NewMockCODESYSServer()
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	defer server.Close()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Connect to mock server
	addr := fmt.Sprintf("127.0.0.1:%d", server.Port())
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	// Run the plugin
	plugin := &CODESYSPlugin{}
	addrPort := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", server.Port()))
	target := plugins.Target{
		Address: addrPort,
		Host:    "127.0.0.1",
	}

	result, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Plugin returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Expected service detection, got nil")
	}

	// Verify detection
	if result.Protocol != plugins.ProtoCODESYS {
		t.Errorf("Expected protocol %s, got %s", plugins.ProtoCODESYS, result.Protocol)
	}

	t.Logf("✓ CODESYS detected on mock server")
	t.Logf("  Protocol: %s", result.Protocol)
	t.Logf("  Version: %s", result.Version)
	t.Logf("  Transport: %s", result.Transport)
}

// TestCODESYSLiveValidation can be used for actual live testing
// Run with: go test -tags=integration -run TestCODESYSLiveValidation -v -target=<ip:port>
func TestCODESYSLiveValidation(t *testing.T) {
	// This test is for manual validation against real CODESYS targets
	// Skip if no target is provided
	t.Skip("Live validation requires -target flag with accessible CODESYS endpoint")
}

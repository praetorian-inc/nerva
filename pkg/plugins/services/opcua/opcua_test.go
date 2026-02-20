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

package opcua

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	response []byte
	err      error
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}
	copy(b, m.response)
	return len(m.response), nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestOPCUAPlugin_ValidACK(t *testing.T) {
	plugin := &OPCUAPlugin{}

	// Valid ACK response (8 bytes minimum)
	// "ACK" + "F" (final) + 4-byte message size
	validACK := []byte{'A', 'C', 'K', 'F', 0x00, 0x00, 0x00, 0x08}

	conn := &mockConn{response: validACK}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:4840"),
		Host:    "localhost",
	}

	service, err := plugin.Run(conn, time.Second, target)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if service == nil {
		t.Fatal("Expected service to be detected, got nil")
	}

	if service.Protocol != "opcua" {
		t.Errorf("Expected protocol 'opcua', got '%s'", service.Protocol)
	}

	if service.Port != 4840 {
		t.Errorf("Expected port 4840, got %d", service.Port)
	}
}

func TestOPCUAPlugin_InvalidResponse(t *testing.T) {
	plugin := &OPCUAPlugin{}

	// Invalid response (not ACK)
	invalidResponse := []byte{'E', 'R', 'R', 'F', 0x00, 0x00, 0x00, 0x08}

	conn := &mockConn{response: invalidResponse}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:4840"),
		Host:    "localhost",
	}

	service, err := plugin.Run(conn, time.Second, target)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if service != nil {
		t.Errorf("Expected nil service for invalid response, got %+v", service)
	}
}

func TestOPCUAPlugin_MalformedResponse(t *testing.T) {
	plugin := &OPCUAPlugin{}

	// Response too short (less than 8 bytes)
	shortResponse := []byte{'A', 'C', 'K', 'F'}

	conn := &mockConn{response: shortResponse}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:4840"),
		Host:    "localhost",
	}

	service, err := plugin.Run(conn, time.Second, target)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if service != nil {
		t.Errorf("Expected nil service for malformed response, got %+v", service)
	}
}

func TestOPCUAPlugin_EmptyResponse(t *testing.T) {
	plugin := &OPCUAPlugin{}

	// Empty response
	emptyResponse := []byte{}

	conn := &mockConn{response: emptyResponse}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:4840"),
		Host:    "localhost",
	}

	service, err := plugin.Run(conn, time.Second, target)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if service != nil {
		t.Errorf("Expected nil service for empty response, got %+v", service)
	}
}

func TestOPCUAPlugin_PortPriority(t *testing.T) {
	plugin := &OPCUAPlugin{}

	if !plugin.PortPriority(4840) {
		t.Error("Expected port 4840 to have priority")
	}

	if plugin.PortPriority(8080) {
		t.Error("Expected port 8080 to not have priority")
	}
}

func TestOPCUAPlugin_Name(t *testing.T) {
	plugin := &OPCUAPlugin{}

	if plugin.Name() != OPCUA {
		t.Errorf("Expected name %s, got %s", OPCUA, plugin.Name())
	}
}

func TestOPCUAPlugin_Type(t *testing.T) {
	plugin := &OPCUAPlugin{}

	if plugin.Type() != plugins.TCP {
		t.Errorf("Expected type TCP, got %v", plugin.Type())
	}
}

func TestOPCUAPlugin_Priority(t *testing.T) {
	plugin := &OPCUAPlugin{}

	if plugin.Priority() != 400 {
		t.Errorf("Expected priority 400, got %d", plugin.Priority())
	}
}

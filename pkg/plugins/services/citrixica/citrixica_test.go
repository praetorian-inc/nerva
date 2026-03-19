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

package citrixica

import (
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// mockConn implements net.Conn for testing. SetDeadline methods return nil so
// that utils.Recv (which calls SetReadDeadline) works without a real connection.
type mockConn struct {
	readData []byte
	readErr  error
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	n = copy(b, m.readData)
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

var defaultTarget = plugins.Target{
	Address: netip.MustParseAddrPort("127.0.0.1:1494"),
}

// TestPluginMetadata verifies Name, Type, Priority, and PortPriority.
func TestPluginMetadata(t *testing.T) {
	p := &CitrixICAPlugin{}

	if p.Name() != "citrix-ica" {
		t.Errorf("Name() = %q, want %q", p.Name(), "citrix-ica")
	}
	if p.Type() != plugins.TCP {
		t.Errorf("Type() = %v, want plugins.TCP", p.Type())
	}
	if p.Priority() <= 0 {
		t.Errorf("Priority() = %d, want > 0", p.Priority())
	}
}

// TestPortPriority verifies that ports 1494 and 2598 return true.
func TestPortPriority(t *testing.T) {
	p := &CitrixICAPlugin{}

	tests := []struct {
		port     uint16
		expected bool
	}{
		{1494, true},
		{2598, true},
		{1493, false},
		{1495, false},
		{0, false},
		{443, false},
		{65535, false},
	}

	for _, tt := range tests {
		got := p.PortPriority(tt.port)
		if got != tt.expected {
			t.Errorf("PortPriority(%d) = %v, want %v", tt.port, got, tt.expected)
		}
	}
}

// TestRunSingleSignature tests detection with a single ICA signature (6 bytes).
func TestRunSingleSignature(t *testing.T) {
	p := &CitrixICAPlugin{}
	// Single ICA banner: \x7f\x7f ICA \x00
	conn := &mockConn{readData: []byte{0x7f, 0x7f, 0x49, 0x43, 0x41, 0x00}}

	svc, err := p.Run(conn, 5*time.Second, defaultTarget)
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service, want non-nil")
	}
	if svc.Protocol != "citrix-ica" {
		t.Errorf("Protocol = %q, want %q", svc.Protocol, "citrix-ica")
	}

	var payload plugins.ServiceCitrixICA
	if err := json.Unmarshal(svc.Raw, &payload); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	if payload.BannerMatch {
		t.Error("BannerMatch = true, want false for single signature")
	}
}

// TestRunDoubleSignature tests detection with the repeated ICA banner (12 bytes),
// matching nmap's pattern: \x7f\x7fICA\0\x7f\x7fICA\0
func TestRunDoubleSignature(t *testing.T) {
	p := &CitrixICAPlugin{}
	banner := []byte{
		0x7f, 0x7f, 0x49, 0x43, 0x41, 0x00,
		0x7f, 0x7f, 0x49, 0x43, 0x41, 0x00,
	}
	conn := &mockConn{readData: banner}

	svc, err := p.Run(conn, 5*time.Second, defaultTarget)
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service, want non-nil")
	}

	var payload plugins.ServiceCitrixICA
	if err := json.Unmarshal(svc.Raw, &payload); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	if !payload.BannerMatch {
		t.Error("BannerMatch = false, want true for double signature")
	}
}

// TestRunLongBanner tests detection when the server sends many repeated signatures.
func TestRunLongBanner(t *testing.T) {
	p := &CitrixICAPlugin{}
	unit := []byte{0x7f, 0x7f, 0x49, 0x43, 0x41, 0x00}
	var banner []byte
	for i := 0; i < 10; i++ {
		banner = append(banner, unit...)
	}
	conn := &mockConn{readData: banner}

	svc, err := p.Run(conn, 5*time.Second, defaultTarget)
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service, want non-nil")
	}

	var payload plugins.ServiceCitrixICA
	if err := json.Unmarshal(svc.Raw, &payload); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	if !payload.BannerMatch {
		t.Error("BannerMatch = false, want true for long repeated banner")
	}
}

// TestRunEdgeCases tests negative and boundary conditions.
func TestRunEdgeCases(t *testing.T) {
	p := &CitrixICAPlugin{}

	tests := []struct {
		name     string
		response []byte
		wantSvc  bool
		wantErr  bool
	}{
		{
			name:     "empty response returns nil",
			response: []byte{},
			wantSvc:  false,
			wantErr:  false,
		},
		{
			name:     "too short (5 bytes)",
			response: []byte{0x7f, 0x7f, 0x49, 0x43, 0x41},
			wantSvc:  false,
			wantErr:  false,
		},
		{
			name:     "wrong first byte",
			response: []byte{0x00, 0x7f, 0x49, 0x43, 0x41, 0x00},
			wantSvc:  false,
			wantErr:  false,
		},
		{
			name:     "wrong second byte",
			response: []byte{0x7f, 0x00, 0x49, 0x43, 0x41, 0x00},
			wantSvc:  false,
			wantErr:  false,
		},
		{
			name:     "wrong ASCII (not ICA)",
			response: []byte{0x7f, 0x7f, 0x56, 0x4e, 0x43, 0x00},
			wantSvc:  false,
			wantErr:  false,
		},
		{
			name:     "missing null terminator",
			response: []byte{0x7f, 0x7f, 0x49, 0x43, 0x41, 0x01},
			wantSvc:  false,
			wantErr:  false,
		},
		{
			name:     "random garbage",
			response: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE},
			wantSvc:  false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{readData: tt.response}
			svc, err := p.Run(conn, 5*time.Second, defaultTarget)

			if tt.wantErr && err == nil {
				t.Error("Run() error = nil, want non-nil error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Run() error = %v, want nil", err)
			}
			if tt.wantSvc && svc == nil {
				t.Error("Run() returned nil service, want non-nil")
			}
			if !tt.wantSvc && svc != nil {
				t.Errorf("Run() returned non-nil service %v, want nil", svc)
			}
		})
	}
}

// TestRunReadError verifies that I/O errors propagate correctly.
func TestRunReadError(t *testing.T) {
	p := &CitrixICAPlugin{}
	readErr := net.UnknownNetworkError("mock read failure")
	conn := &mockConn{readErr: readErr}

	svc, err := p.Run(conn, 5*time.Second, defaultTarget)
	if svc != nil {
		t.Errorf("Run() returned non-nil service on read error: %v", svc)
	}
	if err == nil {
		t.Fatal("Run() returned nil error, want propagated read error")
	}
}

// TestBuildCitrixCPE verifies CPE string construction.
func TestBuildCitrixCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "empty version uses wildcard",
			version:  "",
			expected: "cpe:2.3:a:citrix:virtual_apps_and_desktops:*:*:*:*:*:*:*:*",
		},
		{
			name:     "specific version",
			version:  "7.15",
			expected: "cpe:2.3:a:citrix:virtual_apps_and_desktops:7.15:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCitrixCPE(tt.version)
			if got != tt.expected {
				t.Errorf("buildCitrixCPE(%q) = %q, want %q", tt.version, got, tt.expected)
			}
		})
	}
}

// TestRunCPEInPayload verifies that the CPE is included in the service payload.
func TestRunCPEInPayload(t *testing.T) {
	p := &CitrixICAPlugin{}
	banner := []byte{
		0x7f, 0x7f, 0x49, 0x43, 0x41, 0x00,
		0x7f, 0x7f, 0x49, 0x43, 0x41, 0x00,
	}
	conn := &mockConn{readData: banner}

	svc, err := p.Run(conn, 5*time.Second, defaultTarget)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service")
	}

	var payload plugins.ServiceCitrixICA
	if err := json.Unmarshal(svc.Raw, &payload); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}

	if len(payload.CPEs) == 0 {
		t.Fatal("CPEs is empty, want at least one CPE")
	}

	expectedCPE := "cpe:2.3:a:citrix:virtual_apps_and_desktops:*:*:*:*:*:*:*:*"
	if payload.CPEs[0] != expectedCPE {
		t.Errorf("CPEs[0] = %q, want %q", payload.CPEs[0], expectedCPE)
	}
}

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

package melsecq

import (
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestIsValidMelsecQResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		want     bool
	}{
		{
			name:     "Valid response (0xD7 header, >= 43 bytes)",
			response: make([]byte, 43),
			want:     true,
		},
		{
			name:     "Valid response (longer than 43 bytes)",
			response: make([]byte, 60),
			want:     true,
		},
		{
			name:     "Too short response (42 bytes)",
			response: make([]byte, 42),
			want:     false,
		},
		{
			name:     "Wrong header byte",
			response: append([]byte{0xAA}, make([]byte, 42)...),
			want:     false,
		},
		{
			name:     "Empty response",
			response: []byte{},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set magic byte for valid cases
			if len(tt.response) >= 43 && tt.name == "Valid response (0xD7 header, >= 43 bytes)" {
				tt.response[0] = MelsecQResponseMagic
			}
			if len(tt.response) >= 43 && tt.name == "Valid response (longer than 43 bytes)" {
				tt.response[0] = MelsecQResponseMagic
			}

			got := isValidMelsecQResponse(tt.response)
			if got != tt.want {
				t.Errorf("isValidMelsecQResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractCPUModel(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		want     string
	}{
		{
			name:     "Valid Q03UDECPU",
			response: buildResponseWithCPUModel("Q03UDECPU"),
			want:     "Q03UDECPU",
		},
		{
			name:     "Valid Q04UDEHCPU",
			response: buildResponseWithCPUModel("Q04UDEHCPU"),
			want:     "Q04UDEHCPU",
		},
		{
			name:     "Valid Q26UDVCPU",
			response: buildResponseWithCPUModel("Q26UDVCPU"),
			want:     "Q26UDVCPU",
		},
		{
			name:     "Null-terminated short model",
			response: buildResponseWithCPUModel("Q02CPU\x00\x00\x00"),
			want:     "Q02CPU",
		},
		{
			name:     "Response too short",
			response: make([]byte, 40),
			want:     "",
		},
		{
			name:     "Empty CPU model (all nulls)",
			response: buildResponseWithCPUModel("\x00\x00\x00\x00\x00\x00"),
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCPUModel(tt.response)
			if got != tt.want {
				t.Errorf("extractCPUModel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildMelsecQCPE(t *testing.T) {
	want := "cpe:2.3:h:mitsubishielectric:melsec-q:*:*:*:*:*:*:*:*"
	got := buildMelsecQCPE()
	if got != want {
		t.Errorf("buildMelsecQCPE() = %q, want %q", got, want)
	}
}

func TestMelsecQPlugin_Run(t *testing.T) {
	plugin := &MelsecQPlugin{}

	tests := []struct {
		name          string
		mockResponse  []byte
		mockErr       error
		wantService   bool
		wantErr       bool
		wantCPUModel  string
		wantCPEsCount int
	}{
		{
			name:          "Valid MELSEC-Q response",
			mockResponse:  buildValidMelsecQResponse("Q03UDECPU"),
			mockErr:       nil,
			wantService:   true,
			wantErr:       false,
			wantCPUModel:  "Q03UDECPU",
			wantCPEsCount: 1,
		},
		{
			name:         "Empty response",
			mockResponse: []byte{},
			mockErr:      nil,
			wantService:  false,
			wantErr:      false,
		},
		{
			name:         "Response with wrong header",
			mockResponse: buildInvalidMelsecQResponse(),
			mockErr:      nil,
			wantService:  false,
			wantErr:      false,
		},
		{
			name:         "Response too short",
			mockResponse: make([]byte, 20),
			mockErr:      nil,
			wantService:  false,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{
				readData: tt.mockResponse,
				readErr:  tt.mockErr,
			}

			target := plugins.Target{
				Address: netip.MustParseAddrPort("192.168.1.100:5006"),
				Host:    "test-plc.local",
			}

			service, err := plugin.Run(conn, 5*time.Second, target)

			if (err != nil) != tt.wantErr {
				t.Errorf("MelsecQPlugin.Run() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if (service != nil) != tt.wantService {
				t.Errorf("MelsecQPlugin.Run() service = %v, wantService %v", service != nil, tt.wantService)
				return
			}

			if service != nil {
				// Verify service protocol
				if service.Protocol != MELSECQ {
					t.Errorf("service.Protocol = %q, want %q", service.Protocol, MELSECQ)
				}

				// Verify CPU model and CPEs
				metadata := service.Metadata().(plugins.ServiceMelsecQ)

				if metadata.CPUModel != tt.wantCPUModel {
					t.Errorf("service.CPUModel = %q, want %q", metadata.CPUModel, tt.wantCPUModel)
				}

				if len(metadata.CPEs) != tt.wantCPEsCount {
					t.Errorf("len(service.CPEs) = %d, want %d", len(metadata.CPEs), tt.wantCPEsCount)
				}
			}
		})
	}
}

func TestMelsecQPlugin_PortPriority(t *testing.T) {
	plugin := &MelsecQPlugin{}

	tests := []struct {
		port uint16
		want bool
	}{
		{5006, true},
		{5007, true},
		{502, false},
		{80, false},
		{443, false},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := plugin.PortPriority(tt.port)
			if got != tt.want {
				t.Errorf("PortPriority(%d) = %v, want %v", tt.port, got, tt.want)
			}
		})
	}
}

func TestMelsecQPlugin_Name(t *testing.T) {
	plugin := &MelsecQPlugin{}
	if got := plugin.Name(); got != MELSECQ {
		t.Errorf("Name() = %q, want %q", got, MELSECQ)
	}
}

func TestMelsecQPlugin_Type(t *testing.T) {
	plugin := &MelsecQPlugin{}
	if got := plugin.Type(); got != plugins.TCP {
		t.Errorf("Type() = %v, want %v", got, plugins.TCP)
	}
}

func TestMelsecQPlugin_Priority(t *testing.T) {
	plugin := &MelsecQPlugin{}
	if got := plugin.Priority(); got != 400 {
		t.Errorf("Priority() = %d, want %d", got, 400)
	}
}

// Test 1: Probe Byte Verification
func TestBuildMelsecQProbe(t *testing.T) {
	probe := buildMelsecQProbe()

	// Verify probe length
	if len(probe) != 40 {
		t.Errorf("probe length = %d, want 40", len(probe))
	}

	// Verify subheader (3E request magic, little-endian 0x0057)
	if probe[0] != 0x57 {
		t.Errorf("subheader byte 0 = 0x%02X, want 0x57", probe[0])
	}
	if probe[1] != 0x00 {
		t.Errorf("subheader byte 1 = 0x%02X, want 0x00", probe[1])
	}

	// Verify command code 0x0101 (Read CPU Model) at offset 33-34
	if probe[33] != 0x01 {
		t.Errorf("command byte 33 = 0x%02X, want 0x01", probe[33])
	}
	if probe[34] != 0x01 {
		t.Errorf("command byte 34 = 0x%02X, want 0x01", probe[34])
	}

	// Full probe bytes verification (from Nmap NSE script)
	expected := []byte{
		0x57, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x07,
		0x00, 0x00, 0xff, 0xff, 0x03, 0x00, 0x00, 0xfe,
		0x03, 0x00, 0x00, 0x14, 0x00, 0x1c, 0x08, 0x0a,
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01,
	}

	for i, expected := range expected {
		if probe[i] != expected {
			t.Errorf("probe[%d] = 0x%02X, want 0x%02X", i, probe[i], expected)
		}
	}
}

// Test 2: TCP Mock Server Integration Test
func TestMelsecQPlugin_RunWithTCPServer(t *testing.T) {
	// Subtest: valid MELSEC-Q server
	t.Run("valid_melsecq_server", func(t *testing.T) {
		// Start a TCP listener that responds with a valid MELSEC-Q response
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to create listener: %v", err)
		}
		defer listener.Close()

		// Build a realistic response
		cpuModel := "Q03UDECPU"
		mockResponse := buildValidMelsecQResponse(cpuModel)

		// Server goroutine: accept one connection, read probe, send response
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// Read the probe (40 bytes)
			buf := make([]byte, 40)
			_, _ = conn.Read(buf)

			// Send response
			_, _ = conn.Write(mockResponse)
		}()

		// Client: connect and run plugin
		addr := listener.Addr().String()
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}
		defer conn.Close()

		// Parse the address for the target
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatalf("Failed to parse address: %v", err)
		}
		addrPort := netip.MustParseAddrPort(host + ":" + portStr)

		target := plugins.Target{
			Address: addrPort,
			Host:    "test-plc.local",
		}

		plugin := &MelsecQPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		if err != nil {
			t.Errorf("Run() error = %v, want nil", err)
		}
		if service == nil {
			t.Fatal("Run() returned nil service, want non-nil")
		}
		if service.Protocol != MELSECQ {
			t.Errorf("service.Protocol = %q, want %q", service.Protocol, MELSECQ)
		}

		metadata := service.Metadata().(plugins.ServiceMelsecQ)
		if metadata.CPUModel != "Q03UDECPU" {
			t.Errorf("metadata.CPUModel = %q, want %q", metadata.CPUModel, "Q03UDECPU")
		}
		if len(metadata.CPEs) != 1 {
			t.Errorf("len(metadata.CPEs) = %d, want 1", len(metadata.CPEs))
		}
	})

	// Subtest: server that returns garbage
	t.Run("non_melsecq_server", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to create listener: %v", err)
		}
		defer listener.Close()

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, 40)
			_, _ = conn.Read(buf)
			// Send garbage response
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		}()

		addr := listener.Addr().String()
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}
		defer conn.Close()

		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatalf("Failed to parse address: %v", err)
		}
		addrPort := netip.MustParseAddrPort(host + ":" + portStr)

		target := plugins.Target{
			Address: addrPort,
			Host:    "test-server.local",
		}

		plugin := &MelsecQPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		if err != nil {
			t.Errorf("Run() error = %v, want nil", err)
		}
		if service != nil {
			t.Errorf("Run() returned service, want nil for non-MELSEC-Q server")
		}
	})

	// Subtest: server that closes immediately
	t.Run("server_closes_connection", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Failed to create listener: %v", err)
		}
		defer listener.Close()

		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close() // Close immediately
		}()

		addr := listener.Addr().String()
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}
		defer conn.Close()

		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatalf("Failed to parse address: %v", err)
		}
		addrPort := netip.MustParseAddrPort(host + ":" + portStr)

		target := plugins.Target{
			Address: addrPort,
			Host:    "test-server.local",
		}

		plugin := &MelsecQPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		// Connection error should return error (not panic)
		if err == nil {
			t.Error("Run() error = nil, want error for closed connection")
		}
		if service != nil {
			t.Errorf("Run() returned service, want nil for closed connection")
		}
	})
}

// Test 3: Additional Edge Cases for extractCPUModel
func TestExtractCPUModel_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		want     string
	}{
		{
			name:     "CPU model with trailing spaces",
			response: buildResponseWithCPUModel("Q03CPU   \x00"),
			want:     "Q03CPU",
		},
		{
			name:     "CPU model filling entire 16-byte buffer (no null within buffer)",
			response: buildResponseWithCPUModel("Q03UDECPU1234567"), // Exactly 16 chars
			want:     "Q03UDECPU1234567",
		},
		{
			name: "Response with non-ASCII bytes at offset 42",
			response: func() []byte {
				resp := make([]byte, 60)
				resp[0] = MelsecQResponseMagic
				// Non-ASCII bytes
				copy(resp[42:], []byte{0xFF, 0xFE, 0xFD})
				return resp
			}(),
			want: "\xFF\xFE\xFD", // Non-ASCII preserved
		},
		{
			name:     "CPU model with only 1 character",
			response: buildResponseWithCPUModel("Q\x00"),
			want:     "Q",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCPUModel(tt.response)
			if got != tt.want {
				t.Errorf("extractCPUModel() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Test 4: Response Validation Edge Cases
func TestIsValidMelsecQResponse_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		want     bool
	}{
		{
			name:     "Response exactly 43 bytes (minimum valid)",
			response: func() []byte { r := make([]byte, 43); r[0] = MelsecQResponseMagic; return r }(),
			want:     true,
		},
		{
			name:     "Response with 0xD7 header but only 1 byte long",
			response: []byte{MelsecQResponseMagic},
			want:     false,
		},
		{
			name: "Response with all 0xFF bytes (but correct length and magic)",
			response: func() []byte {
				r := make([]byte, 60)
				for i := range r {
					r[i] = 0xFF
				}
				r[0] = MelsecQResponseMagic // Set correct magic
				return r
			}(),
			want: true,
		},
		{
			name: "Response with 0xD7 at position 0 and position 1",
			response: func() []byte {
				r := make([]byte, 60)
				r[0] = MelsecQResponseMagic
				r[1] = MelsecQResponseMagic // Also at position 1
				return r
			}(),
			want: true, // Should still be valid (we only check position 0)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidMelsecQResponse(tt.response)
			if got != tt.want {
				t.Errorf("isValidMelsecQResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper functions for testing

// buildResponseWithCPUModel creates a mock response with CPU model at offset 42
func buildResponseWithCPUModel(cpuModel string) []byte {
	response := make([]byte, 60)
	response[0] = MelsecQResponseMagic // Set magic byte
	copy(response[42:], cpuModel)
	return response
}

// buildValidMelsecQResponse creates a valid MELSEC-Q response
func buildValidMelsecQResponse(cpuModel string) []byte {
	response := make([]byte, 60)
	response[0] = MelsecQResponseMagic // 3E response magic
	copy(response[42:], cpuModel)
	return response
}

// buildInvalidMelsecQResponse creates an invalid MELSEC-Q response (wrong magic)
func buildInvalidMelsecQResponse() []byte {
	response := make([]byte, 60)
	response[0] = 0xAA // Wrong magic byte
	return response
}

// mockConn is a mock net.Conn for testing
type mockConn struct {
	readData  []byte
	readErr   error
	writeData []byte
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	n = copy(b, m.readData)
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 5006}
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// Test 5: Service Metadata Serialization Test
func TestServiceMelsecQ_JSONRoundTrip(t *testing.T) {
	// Create service metadata
	original := plugins.ServiceMelsecQ{
		CPUModel: "Q03UDECPU",
		CPEs:     []string{"cpe:2.3:h:mitsubishielectric:melsec-q:*:*:*:*:*:*:*:*"},
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Deserialize from JSON
	var deserialized plugins.ServiceMelsecQ
	err = json.Unmarshal(jsonData, &deserialized)
	if err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Verify fields
	if deserialized.CPUModel != original.CPUModel {
		t.Errorf("deserialized.CPUModel = %q, want %q", deserialized.CPUModel, original.CPUModel)
	}

	if len(deserialized.CPEs) != len(original.CPEs) {
		t.Fatalf("len(deserialized.CPEs) = %d, want %d", len(deserialized.CPEs), len(original.CPEs))
	}

	for i := range original.CPEs {
		if deserialized.CPEs[i] != original.CPEs[i] {
			t.Errorf("deserialized.CPEs[%d] = %q, want %q", i, deserialized.CPEs[i], original.CPEs[i])
		}
	}
}

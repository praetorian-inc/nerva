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

package omronfins

import (
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// mockConn implements net.Conn for testing.
type mockConn struct {
	readData  []byte
	writeData []byte
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	n = copy(b, m.readData)
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// buildFINSResponse constructs a valid FINS Read Controller Data response byte slice.
// The model field occupies bytes 14-33 (20 bytes, null-padded).
// The version field occupies bytes 34-53 (20 bytes, null-padded).
func buildFINSResponse(model, version string) []byte {
	// 14-byte FINS response header
	header := []byte{
		0xC0, 0x00, 0x02, // ICF (response), RSV, GCT
		0x00, 0x63, 0x00, // DNA, DA1, DA2
		0x00, 0x00, 0x00, // SNA, SA1, SA2
		0xEF,             // SID
		0x05, 0x01,       // MRC, SRC (Controller Data Read response)
		0x00, 0x00,       // Response code: Normal completion
	}

	// Model field: 20 bytes, null-padded
	modelBytes := make([]byte, 20)
	copy(modelBytes, model)

	// Version field: 20 bytes, null-padded
	versionBytes := make([]byte, 20)
	copy(versionBytes, version)

	result := append(header, modelBytes...)
	result = append(result, versionBytes...)
	return result
}

// ---------------------------------------------------------------------------
// UDP Plugin Tests
// ---------------------------------------------------------------------------

func TestUDPPluginType(t *testing.T) {
	p := &UDPPlugin{}
	if p.Type() != plugins.UDP {
		t.Errorf("expected UDP, got %v", p.Type())
	}
}

func TestUDPPluginPriority(t *testing.T) {
	p := &UDPPlugin{}
	if p.Priority() != 400 {
		t.Errorf("expected priority 400, got %d", p.Priority())
	}
}

func TestUDPPluginPortPriority(t *testing.T) {
	p := &UDPPlugin{}
	if !p.PortPriority(9600) {
		t.Error("expected PortPriority(9600) to return true")
	}
	if p.PortPriority(80) {
		t.Error("expected PortPriority(80) to return false")
	}
}

func TestUDPPluginName(t *testing.T) {
	p := &UDPPlugin{}
	if p.Name() != "omron-fins" {
		t.Errorf("expected omron-fins, got %s", p.Name())
	}
}

// ---------------------------------------------------------------------------
// TCP Plugin Tests
// ---------------------------------------------------------------------------

func TestTCPPluginType(t *testing.T) {
	p := &TCPPlugin{}
	if p.Type() != plugins.TCP {
		t.Errorf("expected TCP, got %v", p.Type())
	}
}

func TestTCPPluginPriority(t *testing.T) {
	p := &TCPPlugin{}
	if p.Priority() != 400 {
		t.Errorf("expected priority 400, got %d", p.Priority())
	}
}

func TestTCPPluginPortPriority(t *testing.T) {
	p := &TCPPlugin{}
	if !p.PortPriority(9600) {
		t.Error("expected PortPriority(9600) to return true")
	}
	if p.PortPriority(80) {
		t.Error("expected PortPriority(80) to return false")
	}
}

func TestTCPPluginName(t *testing.T) {
	p := &TCPPlugin{}
	if p.Name() != "omron-fins" {
		t.Errorf("expected omron-fins, got %s", p.Name())
	}
}

// ---------------------------------------------------------------------------
// parseControllerData Tests
// ---------------------------------------------------------------------------

func TestParseValidControllerData(t *testing.T) {
	tests := []struct {
		name            string
		model           string
		version         string
		expectedModel   string
		expectedVersion string
		expectedCPE     string
	}{
		{
			name:            "CJ2M PLC",
			model:           "CJ2M-CPU31",
			version:         "V2.1",
			expectedModel:   "CJ2M-CPU31",
			expectedVersion: "V2.1",
			expectedCPE:     "cpe:2.3:h:omron:cj2m_cpu31:v2_1:*:*:*:*:*:*:*",
		},
		{
			name:            "CS1G PLC",
			model:           "CS1G-CPU45H",
			version:         "V3.0",
			expectedModel:   "CS1G-CPU45H",
			expectedVersion: "V3.0",
			expectedCPE:     "cpe:2.3:h:omron:cs1g_cpu45h:v3_0:*:*:*:*:*:*:*",
		},
		{
			name:            "NX1P2 PLC no version",
			model:           "NX1P2-9024DT",
			version:         "",
			expectedModel:   "NX1P2-9024DT",
			expectedVersion: "",
			expectedCPE:     "cpe:2.3:h:omron:nx1p2_9024dt:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := buildFINSResponse(tt.model, tt.version)

			model, version, err := parseControllerData(data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if model != tt.expectedModel {
				t.Errorf("expected model %q, got %q", tt.expectedModel, model)
			}
			if version != tt.expectedVersion {
				t.Errorf("expected version %q, got %q", tt.expectedVersion, version)
			}

			cpes := generateCPE(model, version)
			if len(cpes) != 1 {
				t.Fatalf("expected 1 CPE, got %d", len(cpes))
			}
			if cpes[0] != tt.expectedCPE {
				t.Errorf("expected CPE %q, got %q", tt.expectedCPE, cpes[0])
			}
		})
	}
}

func TestParseInvalidControllerData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "too short",
			data: []byte{0xC0, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEF, 0x05, 0x01, 0x00},
		},
		{
			name: "invalid ICF",
			data: func() []byte {
				d := buildFINSResponse("CJ2M-CPU31", "V2.1")
				d[0] = 0x80 // command frame, not response
				return d
			}(),
		},
		{
			name: "error response code",
			data: func() []byte {
				d := buildFINSResponse("CJ2M-CPU31", "V2.1")
				d[12] = 0x10 // non-zero response code
				d[13] = 0x01
				return d
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseControllerData(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseNodeAddrResponse Tests (TCP)
// ---------------------------------------------------------------------------

func TestParseValidNodeAddrResponse(t *testing.T) {
	// Valid 24-byte FINS/TCP node address response:
	//   [0:4]   "FINS" magic = 0x46 0x49 0x4E 0x53
	//   [4:8]   length = 0x00000010 (16)
	//   [8:12]  command = 0x00000001 (Node Address Data Send Response)
	//   [12:16] error code = 0x00000000
	//   [16:20] client node = 0x00000002 (last byte = 2)
	//   [20:24] server node = 0x00000001 (last byte = 1)
	data := []byte{
		0x46, 0x49, 0x4E, 0x53, // "FINS" magic
		0x00, 0x00, 0x00, 0x10, // length 16
		0x00, 0x00, 0x00, 0x01, // command 1 (response)
		0x00, 0x00, 0x00, 0x00, // error code 0
		0x00, 0x00, 0x00, 0x02, // client node 2
		0x00, 0x00, 0x00, 0x01, // server node 1
	}

	clientNode, serverNode, err := parseNodeAddrResponse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clientNode != 2 {
		t.Errorf("expected clientNode 2, got %d", clientNode)
	}
	if serverNode != 1 {
		t.Errorf("expected serverNode 1, got %d", serverNode)
	}
}

func TestParseInvalidNodeAddrResponse(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "too short",
			data: []byte{0x46, 0x49, 0x4E, 0x53, 0x00, 0x00, 0x00, 0x10},
		},
		{
			name: "invalid magic",
			data: func() []byte {
				d := make([]byte, 24)
				d[0] = 0xFF // invalid first magic byte
				d[8], d[9], d[10], d[11] = 0x00, 0x00, 0x00, 0x01
				return d
			}(),
		},
		{
			name: "wrong command",
			data: func() []byte {
				d := make([]byte, 24)
				copy(d[0:4], []byte{0x46, 0x49, 0x4E, 0x53})
				d[8], d[9], d[10], d[11] = 0x00, 0x00, 0x00, 0x02 // command 2, not 1
				return d
			}(),
		},
		{
			name: "error code",
			data: func() []byte {
				d := make([]byte, 24)
				copy(d[0:4], []byte{0x46, 0x49, 0x4E, 0x53})
				d[8], d[9], d[10], d[11] = 0x00, 0x00, 0x00, 0x01 // command 1
				d[12], d[13], d[14], d[15] = 0x00, 0x00, 0x00, 0x01 // non-zero error
				return d
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseNodeAddrResponse(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractFinsTCPPayload Tests
// ---------------------------------------------------------------------------

func TestExtractValidFinsTCPPayload(t *testing.T) {
	// Build a valid FINS/TCP frame with command=2 (FINS Frame Send) and a small payload.
	payload := []byte{0xC0, 0x00, 0x02, 0x00} // 4-byte FINS payload
	frame := buildFinsTCPFrame(finsTCPCmdFrameSend, payload)

	result, err := extractFinsTCPPayload(frame)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != len(payload) {
		t.Fatalf("expected payload length %d, got %d", len(payload), len(result))
	}
	for i, b := range payload {
		if result[i] != b {
			t.Errorf("payload byte %d: expected 0x%02x, got 0x%02x", i, b, result[i])
		}
	}
}

func TestExtractInvalidFinsTCPPayload(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "too short",
			data: []byte{0x46, 0x49, 0x4E, 0x53, 0x00, 0x00},
		},
		{
			name: "invalid magic",
			data: func() []byte {
				frame := buildFinsTCPFrame(finsTCPCmdFrameSend, []byte{0x00, 0x00, 0x00, 0x00})
				frame[0] = 0xFF // corrupt magic
				return frame
			}(),
		},
		{
			name: "wrong command",
			data: func() []byte {
				// Use command 1 (node addr response) instead of 2 (frame send)
				frame := buildFinsTCPFrame(finsTCPCmdNodeAddrResp, []byte{0x00, 0x00, 0x00, 0x00})
				return frame
			}(),
		},
		{
			name: "error code",
			data: func() []byte {
				frame := buildFinsTCPFrame(finsTCPCmdFrameSend, []byte{0x00, 0x00, 0x00, 0x00})
				// Set error code at bytes 12-15
				frame[12] = 0x00
				frame[13] = 0x00
				frame[14] = 0x00
				frame[15] = 0x01 // non-zero error
				return frame
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := extractFinsTCPPayload(tt.data)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// generateCPE Tests
// ---------------------------------------------------------------------------

func TestGenerateCPE(t *testing.T) {
	tests := []struct {
		name        string
		model       string
		version     string
		expectedCPE string
		expectNil   bool
	}{
		{
			name:        "model with version",
			model:       "CJ2M-CPU31",
			version:     "V2.1",
			expectedCPE: "cpe:2.3:h:omron:cj2m_cpu31:v2_1:*:*:*:*:*:*:*",
		},
		{
			name:      "empty model",
			model:     "",
			version:   "V1.0",
			expectNil: true,
		},
		{
			name:        "model without version",
			model:       "NX1P2",
			version:     "",
			expectedCPE: "cpe:2.3:h:omron:nx1p2:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpes := generateCPE(tt.model, tt.version)
			if tt.expectNil {
				if len(cpes) != 0 {
					t.Errorf("expected nil CPEs, got %v", cpes)
				}
				return
			}
			if len(cpes) != 1 {
				t.Fatalf("expected 1 CPE, got %d", len(cpes))
			}
			if cpes[0] != tt.expectedCPE {
				t.Errorf("expected CPE %q, got %q", tt.expectedCPE, cpes[0])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// normalizeCPE Tests
// ---------------------------------------------------------------------------

func TestNormalizeCPE(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"CJ2M-CPU31", "cj2m_cpu31"},
		{"V2.1", "v2_1"},
		{"", "*"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeCPE(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// sanitizeString / extractNullTerminatedString Tests
// ---------------------------------------------------------------------------

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "null terminated via extractNullTerminatedString",
			input:    extractNullTerminatedString([]byte("hello\x00world")),
			expected: "hello",
		},
		{
			name:     "non-printable stripped",
			input:    "CJ2M\x01CPU",
			expected: "CJ2MCPU",
		},
		{
			name:     "trimmed whitespace",
			input:    "  test  ",
			expected: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeString(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildFinsTCPFrame Tests
// ---------------------------------------------------------------------------

func TestBuildFinsTCPFrame(t *testing.T) {
	payload := []byte{0x00, 0x00, 0x00, 0x00} // 4 zero bytes
	frame := buildFinsTCPFrame(0, payload)

	// Frame should be 20 bytes: 16-byte header + 4-byte payload
	if len(frame) != 20 {
		t.Fatalf("expected 20-byte frame, got %d bytes", len(frame))
	}

	// Verify magic bytes [0:4] = "FINS"
	expectedMagic := []byte{0x46, 0x49, 0x4E, 0x53}
	for i, b := range expectedMagic {
		if frame[i] != b {
			t.Errorf("magic byte %d: expected 0x%02x, got 0x%02x", i, b, frame[i])
		}
	}

	// Verify length field [4:8] = 12 (8 + len(payload) = 8 + 4 = 12)
	// big-endian uint32: 0x00 0x00 0x00 0x0C
	if frame[4] != 0x00 || frame[5] != 0x00 || frame[6] != 0x00 || frame[7] != 0x0C {
		t.Errorf("expected length field 0x0000000C, got 0x%02x%02x%02x%02x",
			frame[4], frame[5], frame[6], frame[7])
	}

	// Verify command field [8:12] = 0 (big-endian)
	if frame[8] != 0x00 || frame[9] != 0x00 || frame[10] != 0x00 || frame[11] != 0x00 {
		t.Errorf("expected command 0x00000000, got 0x%02x%02x%02x%02x",
			frame[8], frame[9], frame[10], frame[11])
	}

	// Verify error code field [12:16] = 0
	if frame[12] != 0x00 || frame[13] != 0x00 || frame[14] != 0x00 || frame[15] != 0x00 {
		t.Errorf("expected error code 0x00000000, got 0x%02x%02x%02x%02x",
			frame[12], frame[13], frame[14], frame[15])
	}
}

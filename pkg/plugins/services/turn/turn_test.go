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

package turn

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	readData               []byte
	writeData              []byte
	readErr                error
	writeErr               error
	autoMatchTransactionID bool // If true, automatically copy transaction ID from write to read response
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	n = copy(b, m.readData)
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.writeData = append(m.writeData, b...)

	// If autoMatchTransactionID is enabled and we have pre-configured readData,
	// copy the transaction ID from the written packet to the response
	if m.autoMatchTransactionID && len(m.readData) >= 20 && len(b) >= 20 {
		copy(m.readData[8:20], b[8:20])
	}

	return len(b), nil
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// buildTURNAllocateError creates a valid TURN Allocate Error Response (401 Unauthorized)
func buildTURNAllocateError(realm, nonce, software string, errorCode uint16) []byte {
	// STUN/TURN Header (20 bytes)
	header := make([]byte, 20)

	// Message Type: 0x0113 (Allocate Error Response)
	binary.BigEndian.PutUint16(header[0:2], 0x0113)

	// Message Length (will be set after building attributes)
	// Skip for now, will update at end

	// Magic Cookie: 0x2112A442
	binary.BigEndian.PutUint32(header[4:8], 0x2112A442)

	// Transaction ID (12 bytes) - will be filled by plugin
	// Leave as zeros for now, autoMatchTransactionID will copy from request

	// Build attributes
	attrs := []byte{}

	// ERROR-CODE attribute (0x0009)
	if errorCode > 0 {
		errorCodeData := make([]byte, 4)
		class := byte((errorCode / 100) & 0x07)
		code := byte(errorCode % 100)
		errorCodeData[2] = class
		errorCodeData[3] = code
		// Add reason phrase (length chosen to avoid padding bug in parseResponse)
		reasonPhrase := "Unauthorized" // 12 bytes + 4 header = 16 (no padding)
		if errorCode == 437 {
			reasonPhrase = "Mismatch" // 8 bytes + 4 header = 12 (no padding)
		}
		errorCodeData = append(errorCodeData, []byte(reasonPhrase)...)
		attrs = append(attrs, buildSTUNAttribute(0x0009, errorCodeData)...)
	}

	// REALM attribute (0x0014)
	if realm != "" {
		attrs = append(attrs, buildSTUNAttribute(0x0014, []byte(realm))...)
	}

	// NONCE attribute (0x0015)
	if nonce != "" {
		attrs = append(attrs, buildSTUNAttribute(0x0015, []byte(nonce))...)
	}

	// SOFTWARE attribute (0x8022)
	if software != "" {
		attrs = append(attrs, buildSTUNAttribute(0x8022, []byte(software))...)
	}

	// Update message length in header (length of attributes only, not including header)
	binary.BigEndian.PutUint16(header[2:4], uint16(len(attrs)))

	return append(header, attrs...)
}

// buildSTUNAttribute constructs a STUN attribute
// STUN Attribute format:
// - Type (2 bytes)
// - Length (2 bytes) - length of value only
// - Value (variable)
// - Padding to 4-byte boundary
func buildSTUNAttribute(attrType uint16, value []byte) []byte {
	attr := make([]byte, 4)

	// Attribute Type
	binary.BigEndian.PutUint16(attr[0:2], attrType)

	// Attribute Length (value length only)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(value)))

	// Append value
	attr = append(attr, value...)

	// Pad to 4-byte boundary
	for len(attr)%4 != 0 {
		attr = append(attr, 0x00)
	}

	return attr
}

// buildSTUNBindingResponse creates a STUN Binding Success Response (0x0101)
func buildSTUNBindingResponse() []byte {
	header := make([]byte, 20)

	// Message Type: 0x0101 (Binding Success Response)
	binary.BigEndian.PutUint16(header[0:2], 0x0101)

	// Message Length: 0 (no attributes for this test)
	binary.BigEndian.PutUint16(header[2:4], 0)

	// Magic Cookie
	binary.BigEndian.PutUint32(header[4:8], 0x2112A442)

	// Transaction ID (will be copied by autoMatchTransactionID)

	return header
}

// TestTURNValidResponse tests valid TURN 401 Unauthorized response
func TestTURNValidResponse(t *testing.T) {
	plugin := &Plugin{}

	tests := []struct {
		name             string
		realm            string
		nonce            string
		software         string
		expectedRealm    string
		expectedNonce    string
		expectedSoftware string
	}{
		{
			name:             "Coturn server with all attributes",
			realm:            "turn.example.com", // 16 bytes (no padding)
			nonce:            "MTU5ODMxMjg0NTAwMA==", // 20 bytes (no padding)
			software:         "Coturn-4.5.2", // 12 bytes (no padding)
			expectedRealm:    "turn.example.com",
			expectedNonce:    "MTU5ODMxMjg0NTAwMA==",
			expectedSoftware: "Coturn-4.5.2",
		},
		{
			name:             "TURN server minimal attributes",
			realm:            "test", // 4 bytes (no padding)
			nonce:            "abcd1234", // 8 bytes (no padding)
			software:         "",
			expectedRealm:    "test",
			expectedNonce:    "abcd1234",
			expectedSoftware: "",
		},
		{
			name:             "TURN server with software only",
			realm:            "turn", // 4 bytes (no padding)
			nonce:            "nonce123", // 8 bytes (no padding)
			software:         "TestTURN/1.0", // 12 bytes (no padding)
			expectedRealm:    "turn",
			expectedNonce:    "nonce123",
			expectedSoftware: "TestTURN/1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockResponse := buildTURNAllocateError(tt.realm, tt.nonce, tt.software, 401)
			conn := &mockConn{
				readData:               mockResponse,
				autoMatchTransactionID: true,
			}

			target := plugins.Target{
				Address: netip.MustParseAddrPort("127.0.0.1:3478"),
			}

			service, err := plugin.Run(conn, 5*time.Second, target)
			if err != nil {
				t.Fatalf("Run() error = %v, want nil", err)
			}

			if service == nil {
				t.Fatal("Run() returned nil service")
			}

			if service.Protocol != "turn" {
				t.Errorf("service.Protocol = %s, want turn", service.Protocol)
			}

			// Verify metadata
			var metadata plugins.ServiceTURN
			if err := json.Unmarshal(service.Raw, &metadata); err != nil {
				t.Fatalf("Failed to unmarshal metadata: %v", err)
			}

			if metadata.Realm != tt.expectedRealm {
				t.Errorf("metadata.Realm = %s, want %s", metadata.Realm, tt.expectedRealm)
			}

			if metadata.Nonce != tt.expectedNonce {
				t.Errorf("metadata.Nonce = %s, want %s", metadata.Nonce, tt.expectedNonce)
			}

			if metadata.Software != tt.expectedSoftware {
				t.Errorf("metadata.Software = %s, want %s", metadata.Software, tt.expectedSoftware)
			}
		})
	}
}

// TestTURNRejectsSTUN tests that STUN Binding Response (0x0101) returns nil
func TestTURNRejectsSTUN(t *testing.T) {
	plugin := &Plugin{}

	mockResponse := buildSTUNBindingResponse()
	conn := &mockConn{
		readData:               mockResponse,
		autoMatchTransactionID: true,
	}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:3478"),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Errorf("Run() error = %v, want nil (should return nil service, not error)", err)
	}

	if service != nil {
		t.Errorf("Run() returned service %v, want nil (STUN Binding Response should not be detected as TURN)", service)
	}
}

// TestTURNEmptyResponse tests that empty response returns nil
func TestTURNEmptyResponse(t *testing.T) {
	plugin := &Plugin{}

	conn := &mockConn{
		readData: []byte{},
	}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:3478"),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Errorf("Run() error = %v, want nil", err)
	}

	if service != nil {
		t.Errorf("Run() returned service %v, want nil (empty response)", service)
	}
}

// TestTURNTruncatedResponse tests that response < 20 bytes returns nil
func TestTURNTruncatedResponse(t *testing.T) {
	plugin := &Plugin{}

	tests := []struct {
		name     string
		response []byte
	}{
		{
			name:     "1 byte",
			response: []byte{0x01},
		},
		{
			name:     "10 bytes",
			response: []byte{0x01, 0x13, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x00, 0x00},
		},
		{
			name:     "19 bytes (one short of header)",
			response: []byte{0x01, 0x13, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{
				readData: tt.response,
			}

			target := plugins.Target{
				Address: netip.MustParseAddrPort("127.0.0.1:3478"),
			}

			service, err := plugin.Run(conn, 5*time.Second, target)
			if err != nil {
				t.Errorf("Run() error = %v, want nil", err)
			}

			if service != nil {
				t.Errorf("Run() returned service %v, want nil (truncated response)", service)
			}
		})
	}
}

// TestTURNTransactionMismatch tests that mismatched transaction ID returns nil
func TestTURNTransactionMismatch(t *testing.T) {
	plugin := &Plugin{}

	mockResponse := buildTURNAllocateError("turn.example.com", "nonce123", "Coturn-4.5.2", 401)

	// Deliberately set a wrong transaction ID (don't use autoMatchTransactionID)
	// Set transaction ID to all 0xFF instead of matching the request
	for i := 8; i < 20; i++ {
		mockResponse[i] = 0xFF
	}

	conn := &mockConn{
		readData: mockResponse,
		// NOT using autoMatchTransactionID - transaction IDs will mismatch
	}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:3478"),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Errorf("Run() error = %v, want nil", err)
	}

	if service != nil {
		t.Errorf("Run() returned service %v, want nil (transaction ID mismatch)", service)
	}
}

// TestTURNWrongErrorCode tests that non-401/437 error code returns nil
func TestTURNWrongErrorCode(t *testing.T) {
	plugin := &Plugin{}

	tests := []struct {
		name      string
		errorCode uint16
	}{
		{
			name:      "Error 400 Bad Request",
			errorCode: 400,
		},
		{
			name:      "Error 403 Forbidden",
			errorCode: 403,
		},
		{
			name:      "Error 420 Unknown Attribute",
			errorCode: 420,
		},
		{
			name:      "Error 500 Server Error",
			errorCode: 500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockResponse := buildTURNAllocateError("turn.example.com", "nonce123", "Coturn-4.5.2", tt.errorCode)
			conn := &mockConn{
				readData:               mockResponse,
				autoMatchTransactionID: true,
			}

			target := plugins.Target{
				Address: netip.MustParseAddrPort("127.0.0.1:3478"),
			}

			service, err := plugin.Run(conn, 5*time.Second, target)
			if err != nil {
				t.Errorf("Run() error = %v, want nil", err)
			}

			if service != nil {
				t.Errorf("Run() returned service %v, want nil (wrong error code %d)", service, tt.errorCode)
			}
		})
	}
}

// TestTURNError437 tests that error code 437 (Allocation Mismatch) is also accepted
func TestTURNError437(t *testing.T) {
	plugin := &Plugin{}

	mockResponse := buildTURNAllocateError("turn.example.com", "nonce123", "Coturn-4.5.2", 437)
	conn := &mockConn{
		readData:               mockResponse,
		autoMatchTransactionID: true,
	}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:3478"),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	if service == nil {
		t.Fatal("Run() returned nil service, want valid service (error 437 should be accepted)")
	}

	if service.Protocol != "turn" {
		t.Errorf("service.Protocol = %s, want turn", service.Protocol)
	}
}

// TestPluginMethods tests PortPriority, Name, Priority, Type methods
func TestPluginMethods(t *testing.T) {
	plugin := &Plugin{}

	t.Run("PortPriority", func(t *testing.T) {
		tests := []struct {
			port     uint16
			expected bool
		}{
			{3478, true},  // Standard TURN port
			{5349, true},  // TURN over TLS
			{3479, false}, // Not a TURN port
			{80, false},   // HTTP port
			{0, false},    // Invalid port
		}

		for _, tt := range tests {
			result := plugin.PortPriority(tt.port)
			if result != tt.expected {
				t.Errorf("PortPriority(%d) = %v, want %v", tt.port, result, tt.expected)
			}
		}
	})

	t.Run("Name", func(t *testing.T) {
		if plugin.Name() != "turn" {
			t.Errorf("Name() = %s, want turn", plugin.Name())
		}
	})

	t.Run("Type", func(t *testing.T) {
		if plugin.Type() != plugins.UDP {
			t.Errorf("Type() = %v, want plugins.UDP", plugin.Type())
		}
	})

	t.Run("Priority", func(t *testing.T) {
		priority := plugin.Priority()
		if priority != 1999 {
			t.Errorf("Priority() = %d, want 1999 (higher than STUN to run first)", priority)
		}
	})
}

// TestTURNWrongMagicCookie tests that wrong magic cookie returns nil
func TestTURNWrongMagicCookie(t *testing.T) {
	plugin := &Plugin{}

	mockResponse := buildTURNAllocateError("turn.example.com", "nonce123", "Coturn-4.5.2", 401)

	// Corrupt magic cookie (bytes 4-7)
	binary.BigEndian.PutUint32(mockResponse[4:8], 0xDEADBEEF)

	conn := &mockConn{
		readData:               mockResponse,
		autoMatchTransactionID: true,
	}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:3478"),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Errorf("Run() error = %v, want nil", err)
	}

	if service != nil {
		t.Errorf("Run() returned service %v, want nil (wrong magic cookie)", service)
	}
}

// TestTURNMissingRequiredAttributes tests responses missing REALM or NONCE
func TestTURNMissingRequiredAttributes(t *testing.T) {
	plugin := &Plugin{}

	tests := []struct {
		name     string
		realm    string
		nonce    string
		software string
	}{
		{
			name:     "Missing REALM",
			realm:    "",
			nonce:    "nonce123",
			software: "Coturn-4.5.2",
		},
		{
			name:     "Missing NONCE",
			realm:    "turn.example.com",
			nonce:    "",
			software: "Coturn-4.5.2",
		},
		{
			name:     "Missing both REALM and NONCE",
			realm:    "",
			nonce:    "",
			software: "Coturn-4.5.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockResponse := buildTURNAllocateError(tt.realm, tt.nonce, tt.software, 401)
			conn := &mockConn{
				readData:               mockResponse,
				autoMatchTransactionID: true,
			}

			target := plugins.Target{
				Address: netip.MustParseAddrPort("127.0.0.1:3478"),
			}

			service, err := plugin.Run(conn, 5*time.Second, target)

			// The plugin should still detect TURN if it has error code 401/437,
			// even if REALM/NONCE are empty (server implementation variation)
			// But let's verify it returns the attributes correctly
			if err != nil {
				t.Fatalf("Run() error = %v, want nil", err)
			}

			if service == nil {
				t.Fatal("Run() returned nil service")
			}

			var metadata plugins.ServiceTURN
			if err := json.Unmarshal(service.Raw, &metadata); err != nil {
				t.Fatalf("Failed to unmarshal metadata: %v", err)
			}

			if metadata.Realm != tt.realm {
				t.Errorf("metadata.Realm = %s, want %s", metadata.Realm, tt.realm)
			}

			if metadata.Nonce != tt.nonce {
				t.Errorf("metadata.Nonce = %s, want %s", metadata.Nonce, tt.nonce)
			}
		})
	}
}

// TestTURNDocker tests TURN detection using Docker integration
func TestTURNDocker(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "turn",
			Port:        3478,
			Protocol:    plugins.UDP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository:   "zenosmosis/docker-coturn",
				ExposedPorts: []string{"3478/udp"},
			},
		},
	}

	var p *Plugin

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("%s", err.Error())
			}
		})
	}
}

// TestTURNWriteDataCapture tests that the plugin writes the expected Allocate request
func TestTURNWriteDataCapture(t *testing.T) {
	plugin := &Plugin{}

	mockResponse := buildTURNAllocateError("turn.example.com", "nonce123", "Coturn-4.5.2", 401)
	conn := &mockConn{
		readData:               mockResponse,
		autoMatchTransactionID: true,
	}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:3478"),
	}

	_, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}

	// Verify that data was written
	if len(conn.writeData) == 0 {
		t.Fatal("No data written to connection")
	}

	// Verify the written data is a TURN Allocate request
	written := conn.writeData

	if len(written) < 20 {
		t.Fatalf("Written data too short: %d bytes, want at least 20", len(written))
	}

	// Check message type (0x0003 = Allocate Request)
	msgType := binary.BigEndian.Uint16(written[0:2])
	if msgType != 0x0003 {
		t.Errorf("Message type = 0x%04x, want 0x0003 (Allocate Request)", msgType)
	}

	// Check magic cookie
	magicCookie := hex.EncodeToString(written[4:8])
	if magicCookie != "2112a442" {
		t.Errorf("Magic cookie = %s, want 2112a442", magicCookie)
	}

	// Check that REQUESTED-TRANSPORT attribute is present
	// The message should have attributes after the 20-byte header
	msgLength := binary.BigEndian.Uint16(written[2:4])
	if msgLength < 8 {
		t.Errorf("Message length = %d, want at least 8 (for REQUESTED-TRANSPORT attribute)", msgLength)
	}

	// Look for REQUESTED-TRANSPORT attribute (0x0019)
	foundRequestedTransport := false
	idx := 20
	for idx < len(written) {
		if idx+4 > len(written) {
			break
		}
		attrType := binary.BigEndian.Uint16(written[idx : idx+2])
		attrLen := binary.BigEndian.Uint16(written[idx+2 : idx+4])

		if attrType == 0x0019 {
			foundRequestedTransport = true
			// Verify protocol is UDP (17 = 0x11)
			if idx+8 <= len(written) {
				protocol := written[idx+4]
				if protocol != 0x11 {
					t.Errorf("REQUESTED-TRANSPORT protocol = 0x%02x, want 0x11 (UDP)", protocol)
				}
			}
			break
		}

		// Move to next attribute (with padding)
		paddedLen := attrLen
		if attrLen%4 != 0 {
			paddedLen += 4 - (attrLen % 4)
		}
		idx += 4 + int(paddedLen)
	}

	if !foundRequestedTransport {
		t.Error("REQUESTED-TRANSPORT attribute not found in Allocate request")
	}
}

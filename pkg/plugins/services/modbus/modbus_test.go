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

package modbus

import (
	"log"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// mockModbusConn is a mock net.Conn for testing
type mockModbusConn struct {
	responseData []byte
	readIndex    int
	writeData    []byte
}

func (m *mockModbusConn) Read(b []byte) (n int, err error) {
	// Build response with transaction ID from write (if we have write data)
	if len(m.writeData) >= 2 && m.readIndex == 0 {
		// Echo back transaction ID (first 2 bytes from write) plus rest of response
		m.responseData = append(m.writeData[:2], m.responseData[2:]...)
	}

	if m.readIndex >= len(m.responseData) {
		return 0, nil
	}
	n = copy(b, m.responseData[m.readIndex:])
	m.readIndex += n
	return n, nil
}

func (m *mockModbusConn) Write(b []byte) (n int, err error) {
	m.writeData = make([]byte, len(b))
	copy(m.writeData, b)
	return len(b), nil
}

func (m *mockModbusConn) Close() error {
	return nil
}

func (m *mockModbusConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (m *mockModbusConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (m *mockModbusConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockModbusConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockModbusConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestModbus(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "modbus",
			Port:        5020,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "oitc/modbus-server",
			},
		},
	}

	p := &MODBUSPlugin{}

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

func TestBuildReadDeviceIDRequest(t *testing.T) {
	transactionID := []byte{0x12, 0x34}
	request := buildReadDeviceIDRequest(transactionID)

	// Expected: [0x12, 0x34, 0x00, 0x00, 0x00, 0x05, 0x01, 0x2B, 0x0E, 0x01, 0x00]
	expected := []byte{
		0x12, 0x34, // Transaction ID
		0x00, 0x00, // Protocol ID
		0x00, 0x05, // Length
		0x01, // Unit ID
		0x2B, // Function code (Read Device ID)
		0x0E, // MEI type
		0x01, // Device ID code (Basic)
		0x00, // Start object ID (VendorName)
	}

	assert.Equal(t, expected, request, "buildReadDeviceIDRequest should return correct byte sequence")
}

func TestParseDeviceIDResponse(t *testing.T) {
	tests := []struct {
		name          string
		response      []byte
		transactionID []byte
		expected      map[byte]string
	}{
		{
			name: "valid response with multiple objects",
			response: []byte{
				0x12, 0x34, // Transaction ID
				0x00, 0x00, // Protocol ID
				0x00, 0x19, // Length (25 bytes)
				0x01, // Unit ID
				0x2B, // Function code
				0x0E, // MEI type
				0x01, // Device ID code
				0x01, // Conformity level
				0x00, // More follows (no)
				0x00, // Next object ID
				0x03, // Number of objects
				// Object 0x00 (VendorName)
				0x00, 0x09, 'S', 'c', 'h', 'n', 'e', 'i', 'd', 'e', 'r',
				// Object 0x01 (ProductCode)
				0x01, 0x04, 'M', '2', '2', '1',
				// Object 0x02 (Revision)
				0x02, 0x05, '1', '.', '2', '.', '3',
			},
			transactionID: []byte{0x12, 0x34},
			expected: map[byte]string{
				0x00: "Schneider",
				0x01: "M221",
				0x02: "1.2.3",
			},
		},
		{
			name:          "empty response",
			response:      []byte{},
			transactionID: []byte{0x12, 0x34},
			expected:      map[byte]string{},
		},
		{
			name: "mismatched transaction ID",
			response: []byte{
				0xFF, 0xFF, // Wrong transaction ID
				0x00, 0x00, 0x00, 0x07, 0x01, 0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x00,
			},
			transactionID: []byte{0x12, 0x34},
			expected:      map[byte]string{},
		},
		{
			name: "wrong function code",
			response: []byte{
				0x12, 0x34, // Transaction ID
				0x00, 0x00, 0x00, 0x07, 0x01,
				0x02, // Wrong function code (not 0x2B)
				0x0E, 0x01, 0x01, 0x00, 0x00, 0x00,
			},
			transactionID: []byte{0x12, 0x34},
			expected:      map[byte]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDeviceIDResponse(tt.response, tt.transactionID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeCPEComponent(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Schneider Electric", "schneider_electric"},
		{"ABB Group", "abb_group"},
		{"Siemens AG", "siemens_ag"},
		{"Modicon M221", "modicon_m221"},
		{"Product-123", "product-123"},
		{"Test_Name", "test_name"},
		{"", ""},
		{"UPPERCASE", "uppercase"},
		{"Mixed Case 123", "mixed_case_123"},
		{"Special!@#$Chars", "specialchars"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeCPEComponent(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateCPE(t *testing.T) {
	tests := []struct {
		name     string
		vendor   string
		product  string
		version  string
		expected string
	}{
		{
			name:     "full CPE with version",
			vendor:   "Schneider Electric",
			product:  "Modicon M221",
			version:  "1.2.3",
			expected: "cpe:2.3:h:schneider_electric:modicon_m221:1.2.3:*:*:*:*:*:*:*",
		},
		{
			name:     "CPE without version",
			vendor:   "ABB",
			product:  "AC500",
			version:  "",
			expected: "cpe:2.3:h:abb:ac500:*:*:*:*:*:*:*:*",
		},
		{
			name:     "missing vendor",
			vendor:   "",
			product:  "Product",
			version:  "1.0",
			expected: "",
		},
		{
			name:     "missing product",
			vendor:   "Vendor",
			product:  "",
			version:  "1.0",
			expected: "",
		},
		{
			name:     "vendor and product with special characters",
			vendor:   "Schneider Electric",
			product:  "Modicon M221 PLC",
			version:  "2.0.1",
			expected: "cpe:2.3:h:schneider_electric:modicon_m221_plc:2.0.1:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateCPE(tt.vendor, tt.product, tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestModbusSecurityFinding verifies that security findings are set when Misconfigs is true.
func TestModbusSecurityFinding(t *testing.T) {
	// Mock returns a valid Modbus success response (function code 0x02, byte count 1, data 0x00)
	// Transaction ID bytes [0,1] are overwritten by mockModbusConn.Read with the echoed txID
	mockConn := &mockModbusConn{
		responseData: []byte{
			0xFF, 0xFF, // placeholder transaction ID (overwritten by mock)
			0x00, 0x00, // protocol ID
			0x00, 0x03, // length: 3 bytes follow
			0x01,       // unit ID
			0x02,       // function code (Read Discrete Input success)
			0x01,       // byte count: 1
			0x00,       // data: bit value 0 (high bits zero, passes (>>1)==0x00 check)
		},
	}

	plugin := &MODBUSPlugin{}
	target := plugins.Target{Host: "127.0.0.1", Misconfigs: true}

	service, err := plugin.Run(mockConn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}
	if !service.AnonymousAccess {
		t.Error("expected AnonymousAccess to be true")
	}
	if len(service.SecurityFindings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(service.SecurityFindings))
	}
	if service.SecurityFindings[0].ID != "modbus-no-auth" {
		t.Errorf("expected finding ID 'modbus-no-auth', got %q", service.SecurityFindings[0].ID)
	}
	if service.SecurityFindings[0].Severity != plugins.SeverityHigh {
		t.Errorf("expected severity high, got %s", service.SecurityFindings[0].Severity)
	}
}

// TestModbusNoSecurityFinding verifies that no findings are set when Misconfigs is false.
func TestModbusNoSecurityFinding(t *testing.T) {
	mockConn := &mockModbusConn{
		responseData: []byte{
			0xFF, 0xFF, // placeholder transaction ID (overwritten by mock)
			0x00, 0x00, // protocol ID
			0x00, 0x03, // length: 3 bytes follow
			0x01,       // unit ID
			0x02,       // function code (Read Discrete Input success)
			0x01,       // byte count: 1
			0x00,       // data
		},
	}

	plugin := &MODBUSPlugin{}
	target := plugins.Target{Host: "127.0.0.1", Misconfigs: false}

	service, err := plugin.Run(mockConn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}
	if service.AnonymousAccess {
		t.Error("expected AnonymousAccess to be false when Misconfigs is false")
	}
	if len(service.SecurityFindings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(service.SecurityFindings))
	}
}

// TestModbusSecurityFindingErrorPath verifies findings on Modbus error response (function code 0x82).
// The error path (0x02 + 0x80 = 0x82) is a distinct code path from the success response (0x02).
func TestModbusSecurityFindingErrorPath(t *testing.T) {
	// Build a 10-byte response where response[ModbusHeaderLength] == 0x82 (error response)
	mockConn := &mockModbusConn{
		responseData: []byte{
			0xFF, 0xFF, // placeholder transaction ID (overwritten by mock)
			0x00, 0x00, // protocol ID
			0x00, 0x03, // length: 3 bytes follow
			0x01,       // unit ID
			0x82,       // function code: 0x02 + 0x80 = error response for Read Discrete Input
			0x02,       // exception code (ILLEGAL DATA ADDRESS)
			0x00,       // padding to reach 10 bytes
		},
	}

	plugin := &MODBUSPlugin{}
	target := plugins.Target{Host: "127.0.0.1", Misconfigs: true}

	service, err := plugin.Run(mockConn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil on error response path, want non-nil service")
	}
	if !service.AnonymousAccess {
		t.Error("expected AnonymousAccess to be true on error response path")
	}
	if len(service.SecurityFindings) != 1 {
		t.Fatalf("expected 1 finding on error response path, got %d", len(service.SecurityFindings))
	}
	if service.SecurityFindings[0].ID != "modbus-no-auth" {
		t.Errorf("expected finding ID 'modbus-no-auth', got %q", service.SecurityFindings[0].ID)
	}
	if service.SecurityFindings[0].Severity != plugins.SeverityHigh {
		t.Errorf("expected severity high, got %s", service.SecurityFindings[0].Severity)
	}
}

// TestModbusSecurityFindingLive spins up a real Modbus container and verifies misconfig detection.
func TestModbusSecurityFindingLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("could not connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "oitc/modbus-server",
	})
	if err != nil {
		t.Fatalf("could not start modbus container: %s", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	rawAddr := resource.GetHostPort("5020/tcp")

	host, port, err := net.SplitHostPort(rawAddr)
	if err != nil {
		t.Fatalf("could not split host:port %q: %v", rawAddr, err)
	}
	if host == "localhost" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	targetAddr := net.JoinHostPort(host, port)

	err = pool.Retry(func() error {
		time.Sleep(3 * time.Second)
		conn, dialErr := net.DialTimeout("tcp", targetAddr, 5*time.Second)
		if dialErr != nil {
			return dialErr
		}
		conn.Close()
		return nil
	})
	if err != nil {
		t.Fatalf("failed to connect to modbus container: %s", err)
	}

	conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to open connection to modbus container: %s", err)
	}
	defer conn.Close()

	addrPort := netip.MustParseAddrPort(targetAddr)
	target := plugins.Target{
		Host:       addrPort.Addr().String(),
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &MODBUSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	if !service.AnonymousAccess {
		t.Error("expected AnonymousAccess to be true")
	}
	if len(service.SecurityFindings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(service.SecurityFindings))
	}
	if service.SecurityFindings[0].ID != "modbus-no-auth" {
		t.Errorf("expected finding ID 'modbus-no-auth', got %q", service.SecurityFindings[0].ID)
	}
	if service.SecurityFindings[0].Severity != plugins.SeverityHigh {
		t.Errorf("expected severity high, got %s", service.SecurityFindings[0].Severity)
	}
}

// TestRunWithShortResponse tests the vulnerability fix for CWE-125 (out-of-bounds read)
// A malicious Modbus server could send a response shorter than expected (e.g., 8 bytes),
// which would cause an out-of-bounds read when accessing response[ModbusHeaderLength+2] (index 9).
func TestRunWithShortResponse(t *testing.T) {
	// This test validates that the code handles short responses gracefully
	// without panicking. The vulnerability was that after checking len(response) == 0,
	// the code accessed response[7], response[8], and response[9] without verifying
	// the response was at least 10 bytes long.

	// Create a mock connection that returns an 8-byte response
	// This response is long enough to pass initial checks but not long enough
	// for the vulnerable code path that accesses response[9]
	// Format: [0-1: txID (echoed), 2-3: protocol ID, 4-5: length, 6: unit ID, 7: function code]
	mockConn := &mockModbusConn{
		responseData: []byte{0xFF, 0xFF, 0x00, 0x00, 0x00, 0x02, 0x01, 0x02},
	}

	plugin := &MODBUSPlugin{}
	target := plugins.Target{Host: "127.0.0.1"}

	// This should not panic even with a short response
	result, err := plugin.Run(mockConn, 5*time.Second, target)

	// Expected: function returns nil without panicking
	assert.Nil(t, result, "should return nil for invalid short response")
	assert.Nil(t, err, "should not return error for short response")
}

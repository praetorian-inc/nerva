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

package crimsonv3

import (
	"net"
	"net/netip"
	"os/exec"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// TestPluginMetadata verifies plugin registration and metadata
func TestPluginMetadata(t *testing.T) {
	t.Parallel()
	plugin := &CrimsonV3Plugin{}

	assert.Equal(t, "crimsonv3", plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, 400, plugin.Priority())
	assert.True(t, plugin.PortPriority(789))
	assert.False(t, plugin.PortPriority(80))
	assert.False(t, plugin.PortPriority(443))
}

// buildMockCR3Response builds a mock Crimson V3 response with the given register and string data
func buildMockCR3Response(register uint16, data string) []byte {
	dataBytes := append([]byte(data), 0x00) // null terminate
	payloadLen := 2 + 2 + len(dataBytes)    // register(2) + type(2) + data

	resp := make([]byte, 0, 2+payloadLen)
	resp = append(resp, byte(payloadLen>>8), byte(payloadLen&0xFF)) // length (big-endian)
	resp = append(resp, byte(register>>8), byte(register&0xFF))     // register (big-endian)
	resp = append(resp, 0x03, 0x00)                                 // type 0x0300
	resp = append(resp, dataBytes...)                               // data

	return resp
}

// TestRunWithMockConnection tests the Run() method with mock connections using net.Pipe()
func TestRunWithMockConnection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		manufacturerResp   []byte
		modelResp          []byte
		expectService      bool
		expectManufacturer string
		expectModel        string
		expectCPE          string
	}{
		{
			name:               "valid manufacturer and model response",
			manufacturerResp:   buildMockCR3Response(RegisterManufacturer, "Red Lion Controls"),
			modelResp:          buildMockCR3Response(RegisterModel, "G310C2"),
			expectService:      true,
			expectManufacturer: "Red Lion Controls",
			expectModel:        "G310C2",
			expectCPE:          "cpe:2.3:h:red_lion:g310c2:*:*:*:*:*:*:*:*",
		},
		{
			name:               "valid manufacturer only (model probe fails)",
			manufacturerResp:   buildMockCR3Response(RegisterManufacturer, "Red Lion Controls"),
			modelResp:          nil, // no model response
			expectService:      true,
			expectManufacturer: "Red Lion Controls",
			expectModel:        "",
		},
		{
			name:               "manufacturer with spaces in model",
			manufacturerResp:   buildMockCR3Response(RegisterManufacturer, "Red Lion"),
			modelResp:          buildMockCR3Response(RegisterModel, "CR1000 EXT"),
			expectService:      true,
			expectManufacturer: "Red Lion",
			expectModel:        "CR1000 EXT",
			expectCPE:          "cpe:2.3:h:red_lion:cr1000_ext:*:*:*:*:*:*:*:*",
		},
		{
			name:             "invalid start bytes (not CR3)",
			manufacturerResp: []byte{0xFF, 0xFF, 0xFF}, // too short to be valid
			expectService:    false,
		},
		{
			name:             "too short response (only header, no data)",
			manufacturerResp: []byte{0x00, 0x04, 0x01, 0x2b, 0x00, 0x00}, // exactly 6 bytes
			expectService:    false,
		},
		{
			name:             "empty response",
			manufacturerResp: []byte{},
			expectService:    false,
		},
		{
			name:             "MySQL X Protocol response (must not match CR3)",
			manufacturerResp: []byte{0x05, 0x00, 0x00, 0x00, 0x0b, 0x08, 0x05, 0x1a, 0x00},
			expectService:    false,
		},
	}

	p := &CrimsonV3Plugin{}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create pipe for mock connection
			server, client := net.Pipe()

			// Write responses in background
			go func() {
				defer server.Close()

				// Read manufacturer probe (discard it)
				buf := make([]byte, 256)
				_, err := server.Read(buf)
				if err != nil {
					return
				}

				// Send manufacturer response
				if len(tc.manufacturerResp) > 0 {
					_, _ = server.Write(tc.manufacturerResp)
				} else {
					// Close to simulate no response
					server.Close()
					return
				}

				// If model response is provided, handle model probe
				if tc.modelResp != nil {
					// Read model probe
					_, err = server.Read(buf)
					if err != nil {
						return
					}
					// Send model response
					_, _ = server.Write(tc.modelResp)
				}
			}()

			addr := netip.MustParseAddrPort("127.0.0.1:789")
			target := plugins.Target{Host: "127.0.0.1", Address: addr}
			result, err := p.Run(client, 5*time.Second, target)

			if tc.expectService {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, plugins.ProtoCrimsonV3, result.Protocol)

				// Check metadata
				meta := result.Metadata()
				cr3Meta, ok := meta.(plugins.ServiceCrimsonV3)
				require.True(t, ok)
				assert.Equal(t, tc.expectManufacturer, cr3Meta.Manufacturer)
				if tc.expectModel != "" {
					assert.Equal(t, tc.expectModel, cr3Meta.Model)
				}
				if tc.expectCPE != "" {
					require.Len(t, cr3Meta.CPEs, 1)
					assert.Equal(t, tc.expectCPE, cr3Meta.CPEs[0])
				}
			} else {
				if err != nil {
					return // error is acceptable for invalid responses
				}
				assert.Nil(t, result)
			}
		})
	}
}

// TestExtractString tests the extractString helper function
func TestExtractString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		response []byte
		expected string
	}{
		{
			name:     "valid string with null terminator",
			response: buildMockCR3Response(RegisterManufacturer, "Red Lion Controls"),
			expected: "Red Lion Controls",
		},
		{
			name:     "string without null terminator",
			response: append([]byte{0x00, 0x10, 0x01, 0x2b, 0x00, 0x00}, []byte("Red Lion")...),
			expected: "Red Lion",
		},
		{
			name:     "single character",
			response: buildMockCR3Response(RegisterModel, "X"),
			expected: "X",
		},
		{
			name:     "empty data (header only)",
			response: []byte{0x00, 0x04, 0x01, 0x2b, 0x00, 0x00},
			expected: "",
		},
		{
			name:     "response too short for header",
			response: []byte{0x00, 0x04, 0x01},
			expected: "",
		},
		{
			name:     "empty response",
			response: []byte{},
			expected: "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := extractString(tc.response)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestIsValidResponse tests the isValidResponse helper function
func TestIsValidResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		response []byte
		expected bool
	}{
		{
			name:     "valid response with data",
			response: buildMockCR3Response(RegisterManufacturer, "Test"),
			expected: true,
		},
		{
			name:     "exactly header size (no data)",
			response: []byte{0x00, 0x04, 0x01, 0x2b, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "MySQL X Protocol NOTICE response (must not match CR3)",
			response: []byte{0x05, 0x00, 0x00, 0x00, 0x0b, 0x08, 0x05, 0x1a, 0x00},
			expected: false,
		},
		{
			name:     "payload length mismatch",
			response: []byte{0x00, 0x99, 0x01, 0x2b, 0x1b, 0x00, 0x41},
			expected: false,
		},
		{
			name:     "shorter than header",
			response: []byte{0x00, 0x04, 0x01},
			expected: false,
		},
		{
			name:     "empty response",
			response: []byte{},
			expected: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := isValidResponse(tc.response)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestIsPrintableASCII tests the printable ASCII validation
func TestIsPrintableASCII(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "normal text", input: "Red Lion Controls", expected: true},
		{name: "alphanumeric", input: "G310C2", expected: true},
		{name: "with punctuation", input: "Red-Lion v3.0", expected: true},
		{name: "empty string", input: "", expected: false},
		{name: "binary data", input: "\x05\x1a", expected: false},
		{name: "null byte", input: "Red\x00Lion", expected: false},
		{name: "control characters", input: "\x01\x02\x03", expected: false},
		{name: "high byte", input: "caf\xe9", expected: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, isPrintableASCII(tc.input))
		})
	}
}

// TestGenerateCPE tests the CPE generation function
func TestGenerateCPE(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		model    string
		expected string
	}{
		{
			name:     "simple model",
			model:    "G310C2",
			expected: "cpe:2.3:h:red_lion:g310c2:*:*:*:*:*:*:*:*",
		},
		{
			name:     "model with spaces",
			model:    "CR1000 EXT",
			expected: "cpe:2.3:h:red_lion:cr1000_ext:*:*:*:*:*:*:*:*",
		},
		{
			name:     "model with special characters",
			model:    "DA30D-00!0",
			expected: "cpe:2.3:h:red_lion:da30d-000:*:*:*:*:*:*:*:*",
		},
		{
			name:     "empty model",
			model:    "",
			expected: "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := generateCPE(tc.model)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestCrimsonV3Docker is the Docker integration test
func TestCrimsonV3Docker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Docker integration test in short mode")
	}

	// Build the Docker image using docker CLI (works around dockertest API version issues)
	buildCmd := "cd testdata && docker build -t nerva-crimsonv3-test:latest ."
	if _, err := exec.Command("sh", "-c", buildCmd).CombinedOutput(); err != nil {
		t.Skipf("Could not build Docker image (docker may not be available): %v", err)
		return
	}

	pool, err := dockertest.NewPool("")
	require.NoError(t, err, "could not connect to docker")

	// Run the pre-built image
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "nerva-crimsonv3-test",
		Tag:          "latest",
		ExposedPorts: []string{"789/tcp"},
	})
	require.NoError(t, err, "could not start mock server")
	defer pool.Purge(resource) //nolint:errcheck

	// Wait for server to start
	time.Sleep(5 * time.Second)

	targetAddr := resource.GetHostPort("789/tcp")
	require.NotEmpty(t, targetAddr, "could not get host port mapping")

	t.Logf("Mock Crimson V3 server at: %s", targetAddr)

	// Wait for connection to be ready
	err = pool.Retry(func() error {
		time.Sleep(2 * time.Second)
		conn, dialErr := net.DialTimeout("tcp", targetAddr, 5*time.Second)
		if dialErr != nil {
			return dialErr
		}
		conn.Close()
		return nil
	})
	require.NoError(t, err, "failed to connect to mock server")

	// Run the plugin against the Docker mock server
	p := &CrimsonV3Plugin{}

	conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	require.NoError(t, err, "failed to dial mock server")

	result, err := p.Run(conn, 5*time.Second, plugins.Target{})
	require.NoError(t, err, "plugin Run() returned error")
	require.NotNil(t, result, "plugin should detect Crimson V3 service")

	// Verify protocol detection
	assert.Equal(t, plugins.ProtoCrimsonV3, result.Protocol, "protocol should be crimsonv3")
	assert.Equal(t, "tcp", result.Transport, "transport should be tcp")

	// Verify metadata
	meta := result.Metadata()
	cr3Meta, ok := meta.(plugins.ServiceCrimsonV3)
	require.True(t, ok, "metadata should be ServiceCrimsonV3")

	assert.Equal(t, "Red Lion Controls", cr3Meta.Manufacturer, "manufacturer should match")
	assert.Equal(t, "G310C2", cr3Meta.Model, "model should match")
	require.Len(t, cr3Meta.CPEs, 1, "should have 1 CPE")
	assert.Equal(t, "cpe:2.3:h:red_lion:g310c2:*:*:*:*:*:*:*:*", cr3Meta.CPEs[0], "CPE should match")

	t.Log("Docker integration test PASSED - Crimson V3 detection working correctly")
}

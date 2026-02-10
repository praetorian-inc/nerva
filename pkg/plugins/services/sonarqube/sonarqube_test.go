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

package sonarqube

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanSonarQubeVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "4-part version with build number",
			input:    "10.3.0.82913",
			expected: "10.3.0",
		},
		{
			name:     "3-part version without build number",
			input:    "9.9.0",
			expected: "9.9.0",
		},
		{
			name:     "3-part version (no change needed)",
			input:    "10.3.0",
			expected: "10.3.0",
		},
		{
			name:     "new year-based versioning with build",
			input:    "2025.1.0.12345",
			expected: "2025.1.0",
		},
		{
			name:     "empty version",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanSonarQubeVersion(tt.input)
			if result != tt.expected {
				t.Errorf("cleanSonarQubeVersion(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBuildSonarQubeCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "with version",
			version:  "10.3.0",
			expected: "cpe:2.3:a:sonarsource:sonarqube:10.3.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version (wildcard)",
			version:  "",
			expected: "cpe:2.3:a:sonarsource:sonarqube:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildSonarQubeCPE(tt.version)
			if result != tt.expected {
				t.Errorf("buildSonarQubeCPE(%q) = %q, expected %q", tt.version, result, tt.expected)
			}
		})
	}
}

func TestExtractHTTPHeaders(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected map[string]string
	}{
		{
			name: "typical HTTP response",
			response: []byte("HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"Content-Length: 123\r\n" +
				"\r\n" +
				"body"),
			expected: map[string]string{
				"content-type":   "application/json",
				"content-length": "123",
			},
		},
		{
			name:     "empty response",
			response: []byte(""),
			expected: map[string]string{},
		},
		{
			name: "no headers (status line only)",
			response: []byte("HTTP/1.1 200 OK\r\n" +
				"\r\n"),
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractHTTPHeaders(tt.response)
			if len(result) != len(tt.expected) {
				t.Errorf("extractHTTPHeaders() returned %d headers, expected %d", len(result), len(tt.expected))
			}
			for key, expectedValue := range tt.expected {
				if actualValue, ok := result[key]; !ok {
					t.Errorf("extractHTTPHeaders() missing header %q", key)
				} else if actualValue != expectedValue {
					t.Errorf("extractHTTPHeaders() header %q = %q, expected %q", key, actualValue, expectedValue)
				}
			}
		})
	}
}

func TestExtractHTTPBody(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected []byte
	}{
		{
			name: "response with body",
			response: []byte("HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				`{"id":"abc","version":"10.3.0","status":"UP"}`),
			expected: []byte(`{"id":"abc","version":"10.3.0","status":"UP"}`),
		},
		{
			name: "response without body (empty)",
			response: []byte("HTTP/1.1 204 No Content\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n"),
			expected: nil,
		},
		{
			name:     "no separator (malformed)",
			response: []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractHTTPBody(tt.response)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("extractHTTPBody() = %q, expected nil", result)
				}
			} else {
				if string(result) != string(tt.expected) {
					t.Errorf("extractHTTPBody() = %q, expected %q", result, tt.expected)
				}
			}
		})
	}
}

// buildMockSonarQubeStatusResponse creates a mock HTTP response for GET /api/system/status
func buildMockSonarQubeStatusResponse(version, status string) []byte {
	jsonBody := `{"id":"unique-server-id","version":"` + version + `","status":"` + status + `"}`
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: " + fmt.Sprintf("%d", len(jsonBody)) + "\r\n" +
		"\r\n" +
		jsonBody
	return []byte(response)
}

// buildMockGrafanaResponse creates a mock Grafana response (false positive test)
func buildMockGrafanaResponse() []byte {
	jsonBody := `{"database":"ok","version":"9.5.3"}`
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		jsonBody
	return []byte(response)
}

// buildMock404Response creates a mock 404 response
func buildMock404Response() []byte {
	response := "HTTP/1.1 404 Not Found\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<html><body>Not Found</body></html>"
	return []byte(response)
}

func TestBuildSonarQubeHTTPRequest(t *testing.T) {
	path := "/api/system/status"
	host := "localhost:9000"

	result := buildSonarQubeHTTPRequest(path, host)

	// Verify request structure
	expectedSubstrings := []string{
		"GET /api/system/status HTTP/1.1",
		"Host: localhost:9000",
		"User-Agent: nerva/1.0",
		"Connection: close",
	}

	for _, substr := range expectedSubstrings {
		if !strings.Contains(result, substr) {
			t.Errorf("buildSonarQubeHTTPRequest() missing %q", substr)
		}
	}
}

// TestDetectSonarQube tests the core detection function with various response scenarios
func TestDetectSonarQube(t *testing.T) {
	tests := []struct {
		name            string
		mockResponse    []byte
		expectedVersion string
		expectedStatus  string
		expectedDetect  bool
		expectError     bool
	}{
		{
			name:            "valid SonarQube response",
			mockResponse:    buildMockSonarQubeStatusResponse("10.3.0.82913", "UP"),
			expectedVersion: "10.3.0",
			expectedStatus:  "UP",
			expectedDetect:  true,
			expectError:     false,
		},
		{
			name:            "Grafana response (missing id field)",
			mockResponse:    buildMockGrafanaResponse(),
			expectedVersion: "",
			expectedStatus:  "",
			expectedDetect:  false,
			expectError:     false,
		},
		{
			name:            "404 response",
			mockResponse:    buildMock404Response(),
			expectedVersion: "",
			expectedStatus:  "",
			expectedDetect:  false,
			expectError:     false,
		},
		{
			name:            "empty response (connection closed)",
			mockResponse:    []byte(""),
			expectedVersion: "",
			expectedStatus:  "",
			expectedDetect:  false,
			expectError:     true, // EOF error expected
		},
		{
			name: "invalid JSON",
			mockResponse: []byte("HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				"{invalid json}"),
			expectedVersion: "",
			expectedStatus:  "",
			expectedDetect:  false,
			expectError:     false,
		},
		{
			name: "valid JSON but invalid status value",
			mockResponse: []byte("HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				`{"id":"abc","version":"10.3.0","status":"INVALID_STATUS"}`),
			expectedVersion: "",
			expectedStatus:  "",
			expectedDetect:  false,
			expectError:     false,
		},
		{
			name: "valid JSON but empty version",
			mockResponse: []byte("HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				`{"id":"abc","version":"","status":"UP"}`),
			expectedVersion: "",
			expectedStatus:  "",
			expectedDetect:  false,
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock connection using net.Pipe
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			// Target for detection
			target := plugins.Target{
				Host:    "localhost",
				Address: netip.MustParseAddrPort("127.0.0.1:9000"),
			}

			// Goroutine to simulate server response
			go func() {
				defer server.Close()
				// Read the request (discard it)
				buf := make([]byte, 512)
				_, _ = server.Read(buf)

				// Send mock response
				if len(tt.mockResponse) > 0 {
					_, _ = server.Write(tt.mockResponse)
				}
			}()

			// Run detection
			version, status, detected, err := detectSonarQube(client, target, 5*time.Second)

			// Verify results
			if tt.expectError {
				assert.Error(t, err, "expected error but got none")
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.expectedDetect, detected, "detection result mismatch")
			assert.Equal(t, tt.expectedVersion, version, "version mismatch")
			assert.Equal(t, tt.expectedStatus, status, "status mismatch")
		})
	}
}

// TestSonarQubePlugin_PortPriority tests the PortPriority method
func TestSonarQubePlugin_PortPriority(t *testing.T) {
	plugin := &SonarQubePlugin{}

	tests := []struct {
		name     string
		port     uint16
		expected bool
	}{
		{
			name:     "default SonarQube port 9000",
			port:     9000,
			expected: true,
		},
		{
			name:     "non-default port 8080",
			port:     8080,
			expected: false,
		},
		{
			name:     "non-default port 80",
			port:     80,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.PortPriority(tt.port)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSonarQubePlugin_Name tests the Name method
func TestSonarQubePlugin_Name(t *testing.T) {
	plugin := &SonarQubePlugin{}
	assert.Equal(t, "sonarqube", plugin.Name())
}

// TestSonarQubePlugin_Type tests the Type method
func TestSonarQubePlugin_Type(t *testing.T) {
	plugin := &SonarQubePlugin{}
	assert.Equal(t, plugins.TCP, plugin.Type())
}

// TestSonarQubePlugin_Priority tests the Priority method
func TestSonarQubePlugin_Priority(t *testing.T) {
	plugin := &SonarQubePlugin{}
	assert.Equal(t, 100, plugin.Priority())
}


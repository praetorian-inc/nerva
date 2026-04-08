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

package docker

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// TestParseDockerVersionResponse tests parsing of Docker /version endpoint JSON responses
func TestParseDockerVersionResponse(t *testing.T) {
	tests := []struct {
		name               string
		response           string
		expectDetected     bool
		expectedVersion    string
		expectedApiVersion string
		expectedOs         string
		expectedArch       string
	}{
		{
			name: "valid_docker_24.0.7_response",
			response: `{
				"Platform": {"Name": "Docker Engine - Community"},
				"Version": "24.0.7",
				"ApiVersion": "1.43",
				"MinAPIVersion": "1.24",
				"Os": "linux",
				"Arch": "amd64",
				"KernelVersion": "5.15.0-91-generic",
				"GoVersion": "go1.20.10",
				"GitCommit": "311b9ff"
			}`,
			expectDetected:     true,
			expectedVersion:    "24.0.7",
			expectedApiVersion: "1.43",
			expectedOs:         "linux",
			expectedArch:       "amd64",
		},
		{
			name: "valid_docker_20.10.17_response",
			response: `{
				"Version": "20.10.17",
				"ApiVersion": "1.41",
				"MinAPIVersion": "1.12",
				"Os": "linux",
				"Arch": "arm64",
				"KernelVersion": "5.4.0-1045-azure",
				"GoVersion": "go1.17.11",
				"GitCommit": "100c701"
			}`,
			expectDetected:     true,
			expectedVersion:    "20.10.17",
			expectedApiVersion: "1.41",
			expectedOs:         "linux",
			expectedArch:       "arm64",
		},
		{
			name: "valid_docker_windows_response",
			response: `{
				"Version": "24.0.5",
				"ApiVersion": "1.43",
				"MinAPIVersion": "1.24",
				"Os": "windows",
				"Arch": "amd64",
				"GoVersion": "go1.20.6"
			}`,
			expectDetected:     true,
			expectedVersion:    "24.0.5",
			expectedApiVersion: "1.43",
			expectedOs:         "windows",
			expectedArch:       "amd64",
		},
		{
			name: "valid_docker_minimal_response",
			response: `{
				"Version": "19.03.12",
				"ApiVersion": "1.40"
			}`,
			expectDetected:     true,
			expectedVersion:    "19.03.12",
			expectedApiVersion: "1.40",
			expectedOs:         "",
			expectedArch:       "",
		},
		{
			name: "invalid_missing_api_version",
			response: `{
				"Version": "24.0.7",
				"Os": "linux",
				"Arch": "amd64"
			}`,
			expectDetected:     false,
			expectedVersion:    "",
			expectedApiVersion: "",
			expectedOs:         "",
			expectedArch:       "",
		},
		{
			name: "invalid_empty_api_version",
			response: `{
				"Version": "24.0.7",
				"ApiVersion": "",
				"Os": "linux"
			}`,
			expectDetected:     false,
			expectedVersion:    "",
			expectedApiVersion: "",
			expectedOs:         "",
			expectedArch:       "",
		},
		{
			name:               "invalid_empty_json",
			response:           `{}`,
			expectDetected:     false,
			expectedVersion:    "",
			expectedApiVersion: "",
			expectedOs:         "",
			expectedArch:       "",
		},
		{
			name:               "invalid_not_json",
			response:           `This is not JSON`,
			expectDetected:     false,
			expectedVersion:    "",
			expectedApiVersion: "",
			expectedOs:         "",
			expectedArch:       "",
		},
		{
			name:               "invalid_empty_response",
			response:           ``,
			expectDetected:     false,
			expectedVersion:    "",
			expectedApiVersion: "",
			expectedOs:         "",
			expectedArch:       "",
		},
		{
			name: "invalid_different_service_response",
			response: `{
				"status": "ok",
				"version": "1.0.0"
			}`,
			expectDetected:     false,
			expectedVersion:    "",
			expectedApiVersion: "",
			expectedOs:         "",
			expectedArch:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDockerVersionResponse([]byte(tt.response))
			if tt.expectDetected {
				assert.NotNil(t, result, "Expected detection result")
				assert.True(t, result.detected, "Detection result should be true")
				assert.Equal(t, tt.expectedVersion, result.version, "Version mismatch")
				assert.Equal(t, tt.expectedApiVersion, result.apiVersion, "ApiVersion mismatch")
				assert.Equal(t, tt.expectedOs, result.os, "Os mismatch")
				assert.Equal(t, tt.expectedArch, result.arch, "Arch mismatch")
			} else {
				assert.Nil(t, result, "Expected nil result for non-Docker response")
			}
		})
	}
}

// TestParsePingResponse tests parsing of Docker /_ping endpoint responses
func TestParsePingResponse(t *testing.T) {
	tests := []struct {
		name           string
		response       string
		expectDetected bool
	}{
		{
			name:           "valid_ok_response",
			response:       "OK",
			expectDetected: true,
		},
		{
			name:           "valid_ok_with_newline",
			response:       "OK\n",
			expectDetected: true,
		},
		{
			name:           "valid_ok_with_crlf",
			response:       "OK\r\n",
			expectDetected: true,
		},
		{
			name:           "valid_ok_with_spaces",
			response:       "  OK  ",
			expectDetected: true,
		},
		{
			name:           "invalid_lowercase_ok",
			response:       "ok",
			expectDetected: false,
		},
		{
			name:           "invalid_empty",
			response:       "",
			expectDetected: false,
		},
		{
			name:           "invalid_different_response",
			response:       "pong",
			expectDetected: false,
		},
		{
			name:           "invalid_json_response",
			response:       `{"status": "ok"}`,
			expectDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePingResponse([]byte(tt.response))
			assert.Equal(t, tt.expectDetected, result, "Ping detection mismatch")
		})
	}
}

// TestBuildDockerCPE tests CPE generation for Docker
func TestBuildDockerCPE(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expectedCPE string
	}{
		{
			name:        "docker_24.0.7_with_version",
			version:     "24.0.7",
			expectedCPE: "cpe:2.3:a:docker:docker:24.0.7:*:*:*:*:*:*:*",
		},
		{
			name:        "docker_20.10.17_with_version",
			version:     "20.10.17",
			expectedCPE: "cpe:2.3:a:docker:docker:20.10.17:*:*:*:*:*:*:*",
		},
		{
			name:        "docker_unknown_version_wildcard",
			version:     "",
			expectedCPE: "cpe:2.3:a:docker:docker:*:*:*:*:*:*:*:*",
		},
		{
			name:        "docker_19.03.12_legacy_version",
			version:     "19.03.12",
			expectedCPE: "cpe:2.3:a:docker:docker:19.03.12:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildDockerCPE(tt.version)
			assert.Equal(t, tt.expectedCPE, cpe)
		})
	}
}

// TestBuildDockerHTTPRequest tests HTTP request building
func TestBuildDockerHTTPRequest(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		host     string
		expected []string
	}{
		{
			name: "version_endpoint",
			path: "/version",
			host: "localhost:2375",
			expected: []string{
				"GET /version HTTP/1.1\r\n",
				"Host: localhost:2375\r\n",
				"User-Agent: nerva/1.0\r\n",
				"Accept: application/json\r\n",
				"\r\n\r\n",
			},
		},
		{
			name: "ping_endpoint",
			path: "/_ping",
			host: "192.168.1.100:2376",
			expected: []string{
				"GET /_ping HTTP/1.1\r\n",
				"Host: 192.168.1.100:2376\r\n",
				"User-Agent: nerva/1.0\r\n",
				"\r\n\r\n",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := buildDockerHTTPRequest(tt.path, tt.host)
			for _, exp := range tt.expected {
				assert.Contains(t, request, exp)
			}
		})
	}
}

// TestExtractHTTPBody tests extracting body from HTTP response
func TestExtractHTTPBody(t *testing.T) {
	tests := []struct {
		name         string
		httpResponse string
		expectedBody string
	}{
		{
			name: "standard_http_response",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				`{"Version":"24.0.7","ApiVersion":"1.43"}`,
			expectedBody: `{"Version":"24.0.7","ApiVersion":"1.43"}`,
		},
		{
			name: "multiple_headers",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"Server: Docker/24.0.7\r\n" +
				"Date: Mon, 01 Jan 2024 00:00:00 GMT\r\n" +
				"\r\n" +
				`{"test":"body"}`,
			expectedBody: `{"test":"body"}`,
		},
		{
			name:         "no_headers_separator",
			httpResponse: "just plain text",
			expectedBody: "just plain text",
		},
		{
			name: "empty_body",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/plain\r\n" +
				"\r\n",
			expectedBody: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := extractHTTPBody([]byte(tt.httpResponse))
			if tt.expectedBody == "" {
				assert.Nil(t, body)
			} else {
				assert.Equal(t, tt.expectedBody, string(body))
			}
		})
	}
}

// TestHTTPResponseParsing tests parsing full HTTP responses
func TestHTTPResponseParsing(t *testing.T) {
	tests := []struct {
		name               string
		httpResponse       string
		expectDetected     bool
		expectedVersion    string
		expectedApiVersion string
	}{
		{
			name: "valid_http_response_with_headers",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"Server: Docker/24.0.7 (linux)\r\n" +
				"\r\n" +
				`{"Version":"24.0.7","ApiVersion":"1.43","Os":"linux","Arch":"amd64"}`,
			expectDetected:     true,
			expectedVersion:    "24.0.7",
			expectedApiVersion: "1.43",
		},
		{
			name: "valid_http_response_minimal_headers",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				`{"Version":"20.10.17","ApiVersion":"1.41"}`,
			expectDetected:     true,
			expectedVersion:    "20.10.17",
			expectedApiVersion: "1.41",
		},
		{
			name: "invalid_http_response_not_docker",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				`{"server":"NotDocker","version":"1.0.0"}`,
			expectDetected:     false,
			expectedVersion:    "",
			expectedApiVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Extract body from HTTP response (same logic as detectDocker)
			jsonBody := extractHTTPBody([]byte(tt.httpResponse))

			result := parseDockerVersionResponse(jsonBody)
			if tt.expectDetected {
				assert.NotNil(t, result, "Expected detection result")
				assert.True(t, result.detected, "Detection result should be true")
				assert.Equal(t, tt.expectedVersion, result.version, "Version mismatch")
				assert.Equal(t, tt.expectedApiVersion, result.apiVersion, "ApiVersion mismatch")
			} else {
				assert.Nil(t, result, "Expected nil result for non-Docker response")
			}
		})
	}
}

// TestPluginMetadata tests TCP plugin metadata methods
func TestPluginMetadata(t *testing.T) {
	plugin := &DockerPlugin{}

	// Test Name
	assert.Equal(t, "docker", plugin.Name())

	// Test Type
	assert.Equal(t, plugins.TCP, plugin.Type())

	// Test Priority
	assert.Equal(t, 100, plugin.Priority())

	// Test PortPriority
	assert.True(t, plugin.PortPriority(2375), "Port 2375 should be prioritized")
	assert.False(t, plugin.PortPriority(2376), "Port 2376 should not be prioritized for TCP plugin")
	assert.False(t, plugin.PortPriority(8080), "Port 8080 should not be prioritized")
	assert.False(t, plugin.PortPriority(80), "Port 80 should not be prioritized")
}

// TestTLSPluginMetadata tests TLS plugin metadata methods
func TestTLSPluginMetadata(t *testing.T) {
	plugin := &DockerTLSPlugin{}

	// Test Name
	assert.Equal(t, "docker", plugin.Name())

	// Test Type
	assert.Equal(t, plugins.TCPTLS, plugin.Type())

	// Test Priority
	assert.Equal(t, 101, plugin.Priority())

	// Test PortPriority
	assert.True(t, plugin.PortPriority(2376), "Port 2376 should be prioritized")
	assert.False(t, plugin.PortPriority(2375), "Port 2375 should not be prioritized for TLS plugin")
	assert.False(t, plugin.PortPriority(8080), "Port 8080 should not be prioritized")
	assert.False(t, plugin.PortPriority(443), "Port 443 should not be prioritized")
}

// TestDockerSecurityFindings verifies that security findings are set on a detected Docker service.
func TestDockerSecurityFindings(t *testing.T) {
	// Build a valid Docker /version HTTP response
	versionBody := `{"Version":"24.0.7","ApiVersion":"1.43","Os":"linux","Arch":"amd64"}`
	httpResponse := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + versionBody

	// Start mock TCP server on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	defer listener.Close()

	tcpAddr := listener.Addr().(*net.TCPAddr)
	serverPort := tcpAddr.Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read the request
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		// Write the Docker version response
		_, _ = conn.Write([]byte(httpResponse))
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &DockerPlugin{}
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
	if service.SecurityFindings[0].ID != "docker-unauth-api" {
		t.Errorf("expected finding ID 'docker-unauth-api', got %q", service.SecurityFindings[0].ID)
	}
	if service.SecurityFindings[0].Severity != plugins.SeverityCritical {
		t.Errorf("expected severity critical, got %s", service.SecurityFindings[0].Severity)
	}
}

// TestPluginsDifferentPorts verifies plain and TLS plugins use different ports
func TestPluginsDifferentPorts(t *testing.T) {
	plainPlugin := &DockerPlugin{}
	tlsPlugin := &DockerTLSPlugin{}

	// Verify plain plugin prioritizes 2375, not 2376
	assert.True(t, plainPlugin.PortPriority(2375), "Plain plugin should prioritize port 2375")
	assert.False(t, plainPlugin.PortPriority(2376), "Plain plugin should NOT prioritize port 2376")

	// Verify TLS plugin prioritizes 2376, not 2375
	assert.True(t, tlsPlugin.PortPriority(2376), "TLS plugin should prioritize port 2376")
	assert.False(t, tlsPlugin.PortPriority(2375), "TLS plugin should NOT prioritize port 2375")

	// Verify different transport types
	assert.Equal(t, plugins.TCP, plainPlugin.Type(), "Plain plugin should use TCP transport")
	assert.Equal(t, plugins.TCPTLS, tlsPlugin.Type(), "TLS plugin should use TCPTLS transport")
}

// TestEdgeCases tests edge cases in parsing
func TestEdgeCases(t *testing.T) {
	tests := []struct {
		name               string
		response           string
		expectDetected     bool
		expectedVersion    string
		expectedApiVersion string
	}{
		{
			name: "version_with_rc_suffix",
			response: `{
				"Version": "24.0.0-rc1",
				"ApiVersion": "1.43"
			}`,
			expectDetected:     true,
			expectedVersion:    "24.0.0-rc1",
			expectedApiVersion: "1.43",
		},
		{
			name: "version_with_beta_suffix",
			response: `{
				"Version": "25.0.0-beta.1",
				"ApiVersion": "1.44"
			}`,
			expectDetected:     true,
			expectedVersion:    "25.0.0-beta.1",
			expectedApiVersion: "1.44",
		},
		{
			name: "extra_fields_present",
			response: `{
				"Version": "24.0.7",
				"ApiVersion": "1.43",
				"MinAPIVersion": "1.24",
				"Os": "linux",
				"Arch": "amd64",
				"KernelVersion": "5.15.0",
				"GoVersion": "go1.20.10",
				"GitCommit": "311b9ff",
				"BuildTime": "2023-10-26T09:08:02.000000000+00:00",
				"Experimental": false,
				"CustomField": "ignored"
			}`,
			expectDetected:     true,
			expectedVersion:    "24.0.7",
			expectedApiVersion: "1.43",
		},
		{
			name: "version_empty_string",
			response: `{
				"Version": "",
				"ApiVersion": "1.43"
			}`,
			expectDetected:     true,
			expectedVersion:    "",
			expectedApiVersion: "1.43",
		},
		{
			name: "podman_response",
			response: `{
				"Version": "4.7.0",
				"ApiVersion": "4.7.0",
				"MinAPIVersion": "4.0.0"
			}`,
			expectDetected:     true,
			expectedVersion:    "4.7.0",
			expectedApiVersion: "4.7.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDockerVersionResponse([]byte(tt.response))
			if tt.expectDetected {
				assert.NotNil(t, result, "Expected detection result")
				assert.True(t, result.detected, "Detection result should be true")
				assert.Equal(t, tt.expectedVersion, result.version, "Version mismatch")
				assert.Equal(t, tt.expectedApiVersion, result.apiVersion, "ApiVersion mismatch")
			} else {
				assert.Nil(t, result, "Expected nil result")
			}
		})
	}
}

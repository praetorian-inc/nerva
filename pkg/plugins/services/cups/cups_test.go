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

package cups

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
)

// TestExtractServerHeader tests extracting the Server header from raw HTTP responses.
func TestExtractServerHeader(t *testing.T) {
	tests := []struct {
		name           string
		httpResponse   string
		expectedHeader string
	}{
		{
			name: "cups_server_header",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/html\r\n" +
				"Server: CUPS/2.3.1 IPP/2.1\r\n" +
				"\r\n" +
				"<html>body</html>",
			expectedHeader: "CUPS/2.3.1 IPP/2.1",
		},
		{
			name: "cups_server_header_simple",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Server: CUPS/2.4.2\r\n" +
				"\r\n",
			expectedHeader: "CUPS/2.4.2",
		},
		{
			name: "cups_server_header_with_packaging_suffix",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/html\r\n" +
				"Server: CUPS/2.4.2-163+eb63a8052\r\n" +
				"\r\n",
			expectedHeader: "CUPS/2.4.2-163+eb63a8052",
		},
		{
			name: "no_server_header",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/html\r\n" +
				"\r\n" +
				"body",
			expectedHeader: "",
		},
		{
			name: "apache_server_header",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Server: Apache/2.4.51\r\n" +
				"\r\n",
			expectedHeader: "Apache/2.4.51",
		},
		{
			name:           "empty_response",
			httpResponse:   "",
			expectedHeader: "",
		},
		{
			name: "server_header_case_insensitive_key",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"server: CUPS/2.3.1\r\n" +
				"\r\n",
			expectedHeader: "CUPS/2.3.1",
		},
		{
			name: "multiple_headers_server_present",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Server: CUPS/2.3.1\r\n" +
				"Content-Type: text/html\r\n" +
				"X-Frame-Options: DENY\r\n" +
				"\r\n",
			expectedHeader: "CUPS/2.3.1",
		},
		{
			name: "body_after_blank_line_ignored",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/html\r\n" +
				"\r\n" +
				"Server: NotAHeader/1.0\r\n",
			expectedHeader: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractServerHeader([]byte(tt.httpResponse))
			assert.Equal(t, tt.expectedHeader, result)
		})
	}
}

// TestParseCUPSVersion tests version extraction from Server header values.
func TestParseCUPSVersion(t *testing.T) {
	tests := []struct {
		name            string
		serverHeader    string
		expectedVersion string
	}{
		{
			name:            "cups_2.3.1_simple",
			serverHeader:    "CUPS/2.3.1",
			expectedVersion: "2.3.1",
		},
		{
			name:            "cups_2.4.2_with_packaging_suffix",
			serverHeader:    "CUPS/2.4.2-163+eb63a8052",
			expectedVersion: "2.4.2",
		},
		{
			name:            "cups_1.7_two_part_version",
			serverHeader:    "CUPS/1.7",
			expectedVersion: "1.7",
		},
		{
			name:            "cups_with_ipp_version",
			serverHeader:    "CUPS/2.3.1 IPP/2.1",
			expectedVersion: "2.3.1",
		},
		{
			name:            "cups_lowercase",
			serverHeader:    "cups/2.3.1",
			expectedVersion: "2.3.1",
		},
		{
			name:            "cups_2.0_no_patch",
			serverHeader:    "CUPS/2.0",
			expectedVersion: "2.0",
		},
		{
			name:            "apache_not_cups",
			serverHeader:    "Apache/2.4",
			expectedVersion: "",
		},
		{
			name:            "nginx_not_cups",
			serverHeader:    "nginx/1.18.0",
			expectedVersion: "",
		},
		{
			name:            "empty_header",
			serverHeader:    "",
			expectedVersion: "",
		},
		{
			name:            "cups_no_version",
			serverHeader:    "CUPS",
			expectedVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCUPSVersion(tt.serverHeader)
			assert.Equal(t, tt.expectedVersion, result)
		})
	}
}

// TestBuildCUPSCPE tests CPE generation for CUPS.
func TestBuildCUPSCPE(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expectedCPE string
	}{
		{
			name:        "cups_2.3.1_with_version",
			version:     "2.3.1",
			expectedCPE: "cpe:2.3:a:apple:cups:2.3.1:*:*:*:*:*:*:*",
		},
		{
			name:        "cups_2.4.2_with_version",
			version:     "2.4.2",
			expectedCPE: "cpe:2.3:a:apple:cups:2.4.2:*:*:*:*:*:*:*",
		},
		{
			name:        "cups_1.7_with_version",
			version:     "1.7",
			expectedCPE: "cpe:2.3:a:apple:cups:1.7:*:*:*:*:*:*:*",
		},
		{
			name:        "cups_unknown_version_wildcard",
			version:     "",
			expectedCPE: "cpe:2.3:a:apple:cups:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildCUPSCPE(tt.version)
			assert.Equal(t, tt.expectedCPE, cpe)
		})
	}
}

// TestBuildCUPSHTTPRequest tests HTTP request building.
func TestBuildCUPSHTTPRequest(t *testing.T) {
	tests := []struct {
		name             string
		host             string
		expectedContains []string
	}{
		{
			name: "standard_cups_port",
			host: "192.168.1.10:631",
			expectedContains: []string{
				"GET / HTTP/1.1\r\n",
				"Host: 192.168.1.10:631\r\n",
				"User-Agent: nerva/1.0\r\n",
				"Connection: close\r\n",
				"\r\n\r\n",
			},
		},
		{
			name: "localhost_cups_port",
			host: "localhost:631",
			expectedContains: []string{
				"GET / HTTP/1.1\r\n",
				"Host: localhost:631\r\n",
				"\r\n\r\n",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := buildCUPSHTTPRequest(tt.host)
			for _, exp := range tt.expectedContains {
				assert.Contains(t, request, exp)
			}
		})
	}
}

// TestPluginMetadata tests TCP plugin metadata methods.
func TestPluginMetadata(t *testing.T) {
	plugin := &CUPSPlugin{}

	assert.Equal(t, "cups", plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, 100, plugin.Priority())
	assert.True(t, plugin.PortPriority(631), "Port 631 should be prioritized")
	assert.False(t, plugin.PortPriority(80), "Port 80 should not be prioritized")
	assert.False(t, plugin.PortPriority(443), "Port 443 should not be prioritized")
}

// TestTLSPluginMetadata tests TLS plugin metadata methods.
func TestTLSPluginMetadata(t *testing.T) {
	plugin := &CUPSTLSPlugin{}

	assert.Equal(t, "cups", plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, 101, plugin.Priority())
	assert.True(t, plugin.PortPriority(631), "Port 631 should be prioritized")
	assert.False(t, plugin.PortPriority(80), "Port 80 should not be prioritized")
}

// TestPluginsDifferentTransports verifies plain and TLS plugins use different transports.
func TestPluginsDifferentTransports(t *testing.T) {
	plainPlugin := &CUPSPlugin{}
	tlsPlugin := &CUPSTLSPlugin{}

	assert.Equal(t, plugins.TCP, plainPlugin.Type(), "Plain plugin should use TCP transport")
	assert.Equal(t, plugins.TCPTLS, tlsPlugin.Type(), "TLS plugin should use TCPTLS transport")

	assert.True(t, plainPlugin.PortPriority(631), "Both plugins should prioritize port 631")
	assert.True(t, tlsPlugin.PortPriority(631), "Both plugins should prioritize port 631")
}

// TestFullHTTPResponseParsing tests parsing a complete HTTP response for CUPS detection.
func TestFullHTTPResponseParsing(t *testing.T) {
	tests := []struct {
		name            string
		httpResponse    string
		expectCUPS      bool
		expectedVersion string
	}{
		{
			name: "cups_2.3.1_full_response",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Language: en\r\n" +
				"Content-Type: text/html; charset=UTF-8\r\n" +
				"Server: CUPS/2.3.1 IPP/2.1\r\n" +
				"X-Frame-Options: DENY\r\n" +
				"\r\n" +
				"<!DOCTYPE HTML>",
			expectCUPS:      true,
			expectedVersion: "2.3.1",
		},
		{
			name: "cups_2.4.2_debian_full_response",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Server: CUPS/2.4.2-163+eb63a8052 IPP/2.1\r\n" +
				"\r\n",
			expectCUPS:      true,
			expectedVersion: "2.4.2",
		},
		{
			name: "apache_not_cups",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Server: Apache/2.4.51\r\n" +
				"\r\n" +
				"<html></html>",
			expectCUPS:      false,
			expectedVersion: "",
		},
		{
			name:            "empty_response",
			httpResponse:    "",
			expectCUPS:      false,
			expectedVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverHeader := extractServerHeader([]byte(tt.httpResponse))
			isCUPS := strings.Contains(strings.ToLower(serverHeader), "cups")
			assert.Equal(t, tt.expectCUPS, isCUPS)

			if tt.expectCUPS {
				version := parseCUPSVersion(serverHeader)
				assert.Equal(t, tt.expectedVersion, version)
			}
		})
	}
}

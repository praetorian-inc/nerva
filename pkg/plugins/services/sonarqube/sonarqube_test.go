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
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
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

func TestDetectViaSystemStatus(t *testing.T) {
	tests := []struct {
		name            string
		handler         http.HandlerFunc
		expectedVersion string
		expectedStatus  string
		expectedDetect  bool
	}{
		{
			name: "valid SonarQube response with version",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"id":"abc","version":"10.3.0.82913","status":"UP"}`)
			},
			expectedVersion: "10.3.0",
			expectedStatus:  "UP",
			expectedDetect:  true,
		},
		{
			name: "valid SonarQube with empty version (newer >9.9.1)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"id":"abc","version":"","status":"UP"}`)
			},
			expectedVersion: "",
			expectedStatus:  "UP",
			expectedDetect:  true,
		},
		{
			name: "Grafana response (missing id field)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"database":"ok","version":"9.5.3"}`)
			},
			expectedVersion: "",
			expectedStatus:  "",
			expectedDetect:  false,
		},
		{
			name: "404 response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
				fmt.Fprintf(w, "Not Found")
			},
			expectedVersion: "",
			expectedStatus:  "",
			expectedDetect:  false,
		},
		{
			name: "invalid JSON",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, "{invalid json}")
			},
			expectedVersion: "",
			expectedStatus:  "",
			expectedDetect:  false,
		},
		{
			name: "invalid status value",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"id":"abc","version":"10.3.0","status":"INVALID_STATUS"}`)
			},
			expectedVersion: "",
			expectedStatus:  "",
			expectedDetect:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := server.Client()
			version, status, detected, err := detectViaSystemStatus(client, server.URL)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedDetect, detected)
			if tt.expectedDetect {
				assert.Equal(t, tt.expectedVersion, version)
				assert.Equal(t, tt.expectedStatus, status)
			}
		})
	}
}

func TestDetectViaServerVersion(t *testing.T) {
	tests := []struct {
		name            string
		handler         http.HandlerFunc
		expectedVersion string
		expectedDetect  bool
	}{
		{
			name: "valid version string",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html;charset=utf-8")
				fmt.Fprintf(w, "10.3.0.82913")
			},
			expectedVersion: "10.3.0",
			expectedDetect:  true,
		},
		{
			name: "version with whitespace",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html;charset=utf-8")
				fmt.Fprintf(w, "  10.3.0.82913  \n")
			},
			expectedVersion: "10.3.0",
			expectedDetect:  true,
		},
		{
			name: "HTML error page",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, "<html><body>Error</body></html>")
			},
			expectedVersion: "",
			expectedDetect:  false,
		},
		{
			name: "404 response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
				fmt.Fprintf(w, "Not Found")
			},
			expectedVersion: "",
			expectedDetect:  false,
		},
		{
			name: "empty body",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html;charset=utf-8")
				// Empty body
			},
			expectedVersion: "",
			expectedDetect:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := server.Client()
			version, detected, err := detectViaServerVersion(client, server.URL)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedDetect, detected)
			if tt.expectedDetect {
				assert.Equal(t, tt.expectedVersion, version)
			}
		})
	}
}

func TestCheckAnonymousAccess(t *testing.T) {
	tests := []struct {
		name           string
		handler        http.HandlerFunc
		expectedResult bool
	}{
		{
			name: "200 response (anonymous enabled)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				fmt.Fprintf(w, `{"paging":{"total":0},"components":[]}`)
			},
			expectedResult: true,
		},
		{
			name: "401 response (auth required)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(401)
				fmt.Fprintf(w, "Unauthorized")
			},
			expectedResult: false,
		},
		{
			name: "403 response (forbidden)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(403)
				fmt.Fprintf(w, "Forbidden")
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := server.Client()
			result := checkAnonymousAccess(client, server.URL)

			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

// parseTestServerAddr parses httptest server URL into netip.AddrPort
func parseTestServerAddr(t *testing.T, serverURL string) netip.AddrPort {
	t.Helper()
	hostPort := strings.TrimPrefix(serverURL, "http://")
	host, portStr, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))
}

func TestSonarQubePlugin_Run_FullDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/system/status":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id":"abc","version":"10.3.0.82913","status":"UP"}`)
		case "/api/components/search":
			w.WriteHeader(200)
			fmt.Fprintf(w, `{"paging":{"total":0},"components":[]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	// Dial real TCP connection to test server
	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}

	plugin := &SonarQubePlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	// Verify payload
	var sonarqubeService plugins.ServiceSonarQube
	err = json.Unmarshal(service.Raw, &sonarqubeService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.Equal(t, "UP", sonarqubeService.Status)
	assert.True(t, sonarqubeService.AnonymousAccess)
	assert.Len(t, sonarqubeService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:sonarsource:sonarqube:10.3.0:*:*:*:*:*:*:*", sonarqubeService.CPEs[0])
}

func TestSonarQubePlugin_Run_VersionFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/system/status":
			// Status returns empty version (newer SonarQube)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id":"abc","version":"","status":"UP"}`)
		case "/api/server/version":
			// Version endpoint provides version
			w.Header().Set("Content-Type", "text/html;charset=utf-8")
			fmt.Fprintf(w, "10.3.0.82913")
		case "/api/components/search":
			w.WriteHeader(401)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	// Dial real TCP connection to test server
	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}

	plugin := &SonarQubePlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	// Verify payload
	var sonarqubeService plugins.ServiceSonarQube
	err = json.Unmarshal(service.Raw, &sonarqubeService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.Equal(t, "UP", sonarqubeService.Status)
	assert.False(t, sonarqubeService.AnonymousAccess)
	assert.Len(t, sonarqubeService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:sonarsource:sonarqube:10.3.0:*:*:*:*:*:*:*", sonarqubeService.CPEs[0])
}

func TestSonarQubePlugin_Run_OnlyVersionEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/system/status":
			// Status endpoint returns 404
			w.WriteHeader(404)
		case "/api/server/version":
			// Only version endpoint works
			w.Header().Set("Content-Type", "text/html;charset=utf-8")
			fmt.Fprintf(w, "10.3.0")
		case "/api/components/search":
			w.WriteHeader(403)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	// Dial real TCP connection to test server
	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}

	plugin := &SonarQubePlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	// Verify payload
	var sonarqubeService plugins.ServiceSonarQube
	err = json.Unmarshal(service.Raw, &sonarqubeService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.Equal(t, "UP", sonarqubeService.Status) // Default status when version-only detection
	assert.False(t, sonarqubeService.AnonymousAccess)
	assert.Len(t, sonarqubeService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:sonarsource:sonarqube:10.3.0:*:*:*:*:*:*:*", sonarqubeService.CPEs[0])
}

func TestSonarQubePlugin_Run_NotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Everything returns 404
		w.WriteHeader(404)
	}))
	defer server.Close()

	// Dial real TCP connection to test server
	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}

	plugin := &SonarQubePlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
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

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

package librechat

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestDetectViaJSBundle(t *testing.T) {
	tests := []struct {
		name               string
		handler            http.HandlerFunc
		expectedVersion    string
		expectedConfigVer  string
		expectedDetect     bool
	}{
		{
			name: "valid HTML with script tag, JS bundle with VERSION",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/":
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprintf(w, `<html><head><script type="module" crossorigin src="/assets/index-abc123.js"></script></head></html>`)
				case "/assets/index-abc123.js":
					w.Header().Set("Content-Type", "application/javascript")
					fmt.Fprintf(w, `(function(){e.VERSION="v0.8.2";console.log("LibreChat")})()`)
				default:
					w.WriteHeader(404)
				}
			},
			expectedVersion:    "0.8.2",
			expectedConfigVer:  "",
			expectedDetect:     true,
		},
		{
			name: "valid HTML with script tag, JS bundle with VERSION and CONFIG_VERSION",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/":
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprintf(w, `<html><head><script type="module" crossorigin src="/assets/index-def456.js"></script></head></html>`)
				case "/assets/index-def456.js":
					w.Header().Set("Content-Type", "application/javascript")
					fmt.Fprintf(w, `(function(){e.VERSION="v0.8.2";e.CONFIG_VERSION="1.3.3";console.log("LibreChat")})()`)
				default:
					w.WriteHeader(404)
				}
			},
			expectedVersion:    "0.8.2",
			expectedConfigVer:  "1.3.3",
			expectedDetect:     true,
		},
		{
			name: "HTML without script tags",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `<html><head><title>Not LibreChat</title></head></html>`)
			},
			expectedVersion:    "",
			expectedConfigVer:  "",
			expectedDetect:     false,
		},
		{
			name: "HTML with script tag but 404 on JS bundle",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/":
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprintf(w, `<html><head><script type="module" crossorigin src="/assets/index-missing.js"></script></head></html>`)
				default:
					w.WriteHeader(404)
				}
			},
			expectedVersion:    "",
			expectedConfigVer:  "",
			expectedDetect:     false,
		},
		{
			name: "HTML with script tag but no VERSION in JS bundle",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/":
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprintf(w, `<html><head><script type="module" crossorigin src="/assets/index-novs.js"></script></head></html>`)
				case "/assets/index-novs.js":
					w.Header().Set("Content-Type", "application/javascript")
					fmt.Fprintf(w, `(function(){console.log("Generic React App")})()`)
				default:
					w.WriteHeader(404)
				}
			},
			expectedVersion:    "",
			expectedConfigVer:  "",
			expectedDetect:     false,
		},
		{
			name: "HTTP 404 on root page",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
			},
			expectedVersion:    "",
			expectedConfigVer:  "",
			expectedDetect:     false,
		},
		{
			name: "invalid HTML response",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `{{{ not html }}}`)
			},
			expectedVersion:    "",
			expectedConfigVer:  "",
			expectedDetect:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := server.Client()
			version, configVer, detected, err := detectViaJSBundle(client, server.URL)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedDetect, detected)
			if tt.expectedDetect {
				assert.Equal(t, tt.expectedVersion, version)
				assert.Equal(t, tt.expectedConfigVer, configVer)
			}
		})
	}
}

func TestDetectViaAPIConfig(t *testing.T) {
	tests := []struct {
		name           string
		handler        http.HandlerFunc
		expectedDetect bool
	}{
		{
			name: "valid JSON with 4 LibreChat fields",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"endpoints":{},"modelSpecs":{},"checkBalance":true,"interfaceConfig":{}}`)
			},
			expectedDetect: true,
		},
		{
			name: "valid JSON with 2 LibreChat fields (threshold is >=2)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"endpoints":{},"modelSpecs":{}}`)
			},
			expectedDetect: true,
		},
		{
			name: "valid JSON with only 1 LibreChat field",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"endpoints":{}}`)
			},
			expectedDetect: false,
		},
		{
			name: "invalid JSON",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{invalid json}`)
			},
			expectedDetect: false,
		},
		{
			name: "HTTP 404",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
			},
			expectedDetect: false,
		},
		{
			name: "empty JSON object",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{}`)
			},
			expectedDetect: false,
		},
		{
			name: "false positive: generic auth fields without LibreChat-specific fields",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				// These fields would match the OLD (pre-fix) check but NOT the new one
				fmt.Fprintf(w, `{"registration":false,"socialLoginEnabled":true,"emailLoginEnabled":true,"serverDomain":"example.com"}`)
			},
			expectedDetect: false,
		},
		{
			name: "valid JSON with 3 LibreChat fields",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"endpoints":{},"checkBalance":true,"interfaceConfig":{}}`)
			},
			expectedDetect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := server.Client()
			detected, err := detectViaAPIConfig(client, server.URL)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedDetect, detected)
		})
	}
}

func TestCheckHealthEndpoint(t *testing.T) {
	tests := []struct {
		name           string
		handler        http.HandlerFunc
		expectedResult bool
	}{
		{
			name: "HTTP 200",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				fmt.Fprintf(w, "OK")
			},
			expectedResult: true,
		},
		{
			name: "HTTP 404",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
			},
			expectedResult: false,
		},
		{
			name: "HTTP 503",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(503)
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			client := server.Client()
			result := checkHealthEndpoint(client, server.URL)

			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestBuildLibreChatCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "with version 0.8.2",
			version:  "0.8.2",
			expected: "cpe:2.3:a:librechat:librechat:0.8.2:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:librechat:librechat:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildLibreChatCPE(tt.version)
			assert.Equal(t, tt.expected, result)
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

func TestLibreChatPlugin_Run_FullDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><script type="module" crossorigin src="/assets/index-abc123.js"></script></head></html>`)
		case "/assets/index-abc123.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `(function(){e.VERSION="v0.8.2";e.CONFIG_VERSION="1.3.3";console.log("LibreChat")})()`)
		case "/api/config":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"endpoints":{},"modelSpecs":{},"checkBalance":true,"interfaceConfig":{}}`)
		case "/health":
			w.WriteHeader(200)
			fmt.Fprintf(w, "OK")
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

	plugin := &LibreChatPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	// Verify payload
	var librechatService plugins.ServiceLibreChat
	err = json.Unmarshal(service.Raw, &librechatService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.Equal(t, "1.3.3", librechatService.ConfigVersion)
	assert.True(t, librechatService.HasHealth)
	assert.Len(t, librechatService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:librechat:librechat:0.8.2:*:*:*:*:*:*:*", librechatService.CPEs[0])
}

func TestLibreChatPlugin_Run_FallbackToAPIConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			// Root page returns HTML without script tags
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>LibreChat</title></head></html>`)
		case "/api/config":
			// /api/config returns valid LibreChat config
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"endpoints":{},"modelSpecs":{},"checkBalance":true,"interfaceConfig":{}}`)
		case "/health":
			w.WriteHeader(200)
			fmt.Fprintf(w, "OK")
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

	plugin := &LibreChatPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	// Verify payload - should detect but without version
	var librechatService plugins.ServiceLibreChat
	err = json.Unmarshal(service.Raw, &librechatService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.Empty(t, librechatService.ConfigVersion) // No config version without JS bundle
	assert.True(t, librechatService.HasHealth)
	assert.Len(t, librechatService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:librechat:librechat:*:*:*:*:*:*:*:*", librechatService.CPEs[0]) // Wildcard version
}

func TestLibreChatPlugin_Run_NotDetected(t *testing.T) {
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

	plugin := &LibreChatPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestLibreChatPlugin_Run_Phase1JSBundleFailsFallsBackToPhase2(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			// HTML has a script tag, but the JS bundle will fail
			fmt.Fprintf(w, `<html><head><script type="module" crossorigin src="/assets/index-broken.js"></script></head></html>`)
		case "/assets/index-broken.js":
			// JS bundle returns 500 -- Phase 1 will get detected=false
			w.WriteHeader(500)
		case "/api/config":
			// Phase 2 succeeds
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"endpoints":{},"modelSpecs":{},"checkBalance":true,"interfaceConfig":{}}`)
		case "/health":
			w.WriteHeader(200)
			fmt.Fprintf(w, "OK")
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}

	plugin := &LibreChatPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service, "should detect via Phase 2 when Phase 1 JS bundle fails")

	var librechatService plugins.ServiceLibreChat
	err = json.Unmarshal(service.Raw, &librechatService)
	require.NoError(t, err)
	assert.Empty(t, librechatService.ConfigVersion, "no config version without JS bundle")
	assert.True(t, librechatService.HasHealth)
	assert.Equal(t, "cpe:2.3:a:librechat:librechat:*:*:*:*:*:*:*:*", librechatService.CPEs[0], "wildcard version from Phase 2")
}

func TestLibreChatPlugin_Run_Phase1NoVersionFallsBackToPhase2(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><script type="module" crossorigin src="/assets/index-other.js"></script></head></html>`)
		case "/assets/index-other.js":
			w.Header().Set("Content-Type", "application/javascript")
			// Valid JS bundle but no VERSION pattern -- different Vite app
			fmt.Fprintf(w, `(function(){console.log("Some other app");var config={name:"not-librechat"}})()`)
		case "/api/config":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"endpoints":{},"modelSpecs":{},"checkBalance":true,"interfaceConfig":{}}`)
		case "/health":
			w.WriteHeader(200)
			fmt.Fprintf(w, "OK")
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}

	plugin := &LibreChatPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service, "should detect via Phase 2 when Phase 1 JS has no VERSION")

	var librechatService plugins.ServiceLibreChat
	err = json.Unmarshal(service.Raw, &librechatService)
	require.NoError(t, err)
	assert.Empty(t, librechatService.ConfigVersion)
	assert.True(t, librechatService.HasHealth)
	assert.Equal(t, "cpe:2.3:a:librechat:librechat:*:*:*:*:*:*:*:*", librechatService.CPEs[0])
}

// TestLibreChatPlugin_PortPriority tests the PortPriority method
func TestLibreChatPlugin_PortPriority(t *testing.T) {
	plugin := &LibreChatPlugin{}

	tests := []struct {
		name     string
		port     uint16
		expected bool
	}{
		{
			name:     "default LibreChat port 3080",
			port:     3080,
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
		{
			name:     "non-default port 443",
			port:     443,
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

// TestLibreChatPlugin_Name tests the Name method
func TestLibreChatPlugin_Name(t *testing.T) {
	plugin := &LibreChatPlugin{}
	assert.Equal(t, "librechat", plugin.Name())
}

// TestLibreChatPlugin_Type tests the Type method
func TestLibreChatPlugin_Type(t *testing.T) {
	plugin := &LibreChatPlugin{}
	assert.Equal(t, plugins.TCP, plugin.Type())
}

// TestLibreChatPlugin_Priority tests the Priority method
func TestLibreChatPlugin_Priority(t *testing.T) {
	plugin := &LibreChatPlugin{}
	assert.Equal(t, 100, plugin.Priority())
}

func TestLibreChatTLSPlugin_Run_FullDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><script type="module" crossorigin src="/assets/index-tls123.js"></script></head></html>`)
		case "/assets/index-tls123.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprintf(w, `(function(){e.VERSION="v0.9.1";e.CONFIG_VERSION="2.0.0"})()`)
		case "/health":
			w.WriteHeader(200)
			fmt.Fprintf(w, "OK")
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}

	plugin := &LibreChatTLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var librechatService plugins.ServiceLibreChat
	err = json.Unmarshal(service.Raw, &librechatService)
	require.NoError(t, err)
	assert.Equal(t, "2.0.0", librechatService.ConfigVersion)
	assert.True(t, librechatService.HasHealth)
	assert.Equal(t, "cpe:2.3:a:librechat:librechat:0.9.1:*:*:*:*:*:*:*", librechatService.CPEs[0])
}

func TestLibreChatTLSPlugin_Metadata(t *testing.T) {
	plugin := &LibreChatTLSPlugin{}

	assert.Equal(t, "librechat", plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, 100, plugin.Priority())
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(3080))
	assert.False(t, plugin.PortPriority(80))
}

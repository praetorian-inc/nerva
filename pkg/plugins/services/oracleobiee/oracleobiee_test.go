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

package oracleobiee

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

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "simple title",
			body:     `<html><head><title>Oracle Analytics</title></head></html>`,
			expected: "Oracle Analytics",
		},
		{
			name:     "title with surrounding whitespace",
			body:     `<html><head><title>  Oracle Business Intelligence  </title></head></html>`,
			expected: "Oracle Business Intelligence",
		},
		{
			name:     "no title element",
			body:     `<html><head></head><body>hi</body></html>`,
			expected: "",
		},
		{
			name:     "title with attributes",
			body:     `<title lang="en">Oracle BI Publisher</title>`,
			expected: "Oracle BI Publisher",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractTitle(tt.body))
		})
	}
}

func TestContainsAny(t *testing.T) {
	tests := []struct {
		name     string
		haystack string
		needles  []string
		expected bool
	}{
		{
			name:     "case-insensitive match",
			haystack: "Welcome to ORACLE BUSINESS INTELLIGENCE",
			needles:  []string{"Oracle Business Intelligence"},
			expected: true,
		},
		{
			name:     "no match",
			haystack: "just a generic page",
			needles:  []string{"Oracle Analytics", "Oracle Data Visualization"},
			expected: false,
		},
		{
			name:     "empty needles",
			haystack: "anything",
			needles:  []string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, containsAny(tt.haystack, tt.needles))
		})
	}
}

func TestHasCookieWithPrefix(t *testing.T) {
	tests := []struct {
		name     string
		cookies  []string
		prefix   string
		expected bool
	}{
		{
			name:     "matching prefix",
			cookies:  []string{"ORA_BIPS_NQID=abc123; Path=/"},
			prefix:   oraBIPSCookiePrefix,
			expected: true,
		},
		{
			name:     "no matching cookie",
			cookies:  []string{"SESSIONID=abc123; Path=/"},
			prefix:   oraBIPSCookiePrefix,
			expected: false,
		},
		{
			name:     "prefix not at start of name (boundary-safe)",
			cookies:  []string{"XORA_BIPS_FOO=abc123; Path=/"},
			prefix:   oraBIPSCookiePrefix,
			expected: false,
		},
		{
			name:     "no cookies at all",
			cookies:  nil,
			prefix:   oraBIPSCookiePrefix,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}
			for _, c := range tt.cookies {
				header.Add("Set-Cookie", c)
			}
			resp := &http.Response{Header: header}
			assert.Equal(t, tt.expected, hasCookieWithPrefix(resp, tt.prefix))
		})
	}
}

func TestBuildOBIEECPE(t *testing.T) {
	assert.Equal(t, "cpe:2.3:a:oracle:business_intelligence:*:*:*:*:*:*:*:*", buildOBIEECPE())
}

func TestDetectOBIEE(t *testing.T) {
	tests := []struct {
		name            string
		handler         http.HandlerFunc
		expectedSurface string
		expectedDetect  bool
	}{
		{
			name: "cookie hit on /analytics/saw.dll",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/analytics/saw.dll":
					http.SetCookie(w, &http.Cookie{Name: "ORA_BIPS_NQID", Value: "abc123"})
					fmt.Fprint(w, "sign in")
				default:
					w.WriteHeader(404)
				}
			},
			expectedSurface: "analytics",
			expectedDetect:  true,
		},
		{
			name: "body marker on /xmlpserver (bi-publisher surface)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/xmlpserver":
					fmt.Fprint(w, "<html><body>Welcome to Oracle BI Publisher</body></html>")
				default:
					w.WriteHeader(404)
				}
			},
			expectedSurface: "bi-publisher",
			expectedDetect:  true,
		},
		{
			name: "title marker on /dv (dv surface)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/dv":
					fmt.Fprint(w, `<html><head><title>Oracle Analytics</title></head></html>`)
				default:
					w.WriteHeader(404)
				}
			},
			expectedSurface: "dv",
			expectedDetect:  true,
		},
		{
			name: "no matching surface",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
			},
			expectedSurface: "",
			expectedDetect:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			surface, detected := detectOBIEE(server.Client(), server.URL, "")
			assert.Equal(t, tt.expectedDetect, detected)
			assert.Equal(t, tt.expectedSurface, surface)
		})
	}
}

func dialTestServer(t *testing.T, serverURL string) (net.Conn, plugins.Target) {
	t.Helper()
	addr := parseTestServerAddr(t, serverURL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(serverURL, "http://"), 5*time.Second)
	require.NoError(t, err)
	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}
	return conn, target
}

func TestPlugin_Run_PositiveDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/analytics/saw.dll":
			http.SetCookie(w, &http.Cookie{Name: "ORA_BIPS_NQID", Value: "abc123"})
			fmt.Fprint(w, "sign in")
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var payload plugins.ServiceOracleOBIEE
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "analytics", payload.Surface)
	require.Len(t, payload.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:business_intelligence:*:*:*:*:*:*:*:*", payload.CPEs[0])
}

func TestPlugin_Run_NotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestTLSPlugin_Run_PositiveDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/xmlpserver":
			fmt.Fprint(w, "<html><body>Welcome to Oracle BI Publisher</body></html>")
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &TLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var payload plugins.ServiceOracleOBIEE
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "bi-publisher", payload.Surface)
	require.Len(t, payload.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:business_intelligence:*:*:*:*:*:*:*:*", payload.CPEs[0])
}

func TestTLSPlugin_Run_NotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &TLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestPlugin_PortPriority(t *testing.T) {
	plugin := &Plugin{}
	tests := []struct {
		port     uint16
		expected bool
	}{
		{9704, true},
		{9502, true},
		{443, false},
		{8080, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, plugin.PortPriority(tt.port))
	}
}

func TestTLSPlugin_PortPriority(t *testing.T) {
	plugin := &TLSPlugin{}
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(9704))
}

func TestPlugin_Metadata(t *testing.T) {
	plugin := &Plugin{}
	assert.Equal(t, OBIEE, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
}

func TestTLSPlugin_Metadata(t *testing.T) {
	plugin := &TLSPlugin{}
	assert.Equal(t, OBIEE, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
}

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

package oracleebs

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

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "simple title",
			body:     `<html><head><title>E-Business Suite Home Page Redirect</title></head></html>`,
			expected: "E-Business Suite Home Page Redirect",
		},
		{
			name:     "title with surrounding whitespace",
			body:     `<html><head><title>  Some Title  </title></head></html>`,
			expected: "Some Title",
		},
		{
			name:     "no title element",
			body:     `<html><head></head><body>Oracle E-Business Suite</body></html>`,
			expected: "",
		},
		{
			name:     "empty body",
			body:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTitle(tt.body)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildEBSCPE(t *testing.T) {
	result := buildEBSCPE()
	assert.Equal(t, "cpe:2.3:a:oracle:e-business_suite:*:*:*:*:*:*:*:*", result)
}

func TestEvaluateEBS(t *testing.T) {
	tests := []struct {
		name            string
		evidence        []ebsEvidence
		expectedTitle   string
		expectedRelease string
		expectedDetect  bool
	}{
		{
			name: "redirect title signal",
			evidence: []ebsEvidence{
				{
					statusCode: http.StatusOK,
					body:       `<html><head><title>E-Business Suite Home Page Redirect</title></head></html>`,
				},
			},
			expectedTitle:   "E-Business Suite Home Page Redirect",
			expectedRelease: "",
			expectedDetect:  true,
		},
		{
			name: "body marker signal only",
			evidence: []ebsEvidence{
				{
					statusCode: http.StatusOK,
					body:       `<html><body>Welcome to Oracle E-Business Suite</body></html>`,
				},
			},
			expectedTitle:   "",
			expectedRelease: "",
			expectedDetect:  true,
		},
		{
			name: "body marker Oracle Applications",
			evidence: []ebsEvidence{
				{
					statusCode: http.StatusOK,
					body:       `<html><body>Oracle Applications Login</body></html>`,
				},
			},
			expectedTitle:   "",
			expectedRelease: "",
			expectedDetect:  true,
		},
		{
			name: "redirect Location to AppsLogin",
			evidence: []ebsEvidence{
				{
					statusCode: http.StatusFound,
					location:   "/OA_HTML/AppsLogin",
					body:       "",
				},
			},
			expectedTitle:   "",
			expectedRelease: "",
			expectedDetect:  true,
		},
		{
			name: "AppsLocalLogin body implies R12",
			evidence: []ebsEvidence{
				{
					statusCode: http.StatusOK,
					body:       `<html><body>AppsLocalLogin.jsp</body></html>`,
				},
			},
			expectedTitle:   "",
			expectedRelease: "R12",
			expectedDetect:  true,
		},
		{
			name: "APPS_SSO cookie signal",
			evidence: []ebsEvidence{
				{
					statusCode: http.StatusOK,
					setCookie:  "APPS_SSO_COOKIE=abc123; Path=/",
					body:       "",
				},
			},
			expectedTitle:   "",
			expectedRelease: "",
			expectedDetect:  true,
		},
		{
			name: "no EBS markers present",
			evidence: []ebsEvidence{
				{
					statusCode: http.StatusOK,
					body:       `<html><head><title>Welcome</title></head><body>hello</body></html>`,
				},
			},
			expectedTitle:   "Welcome",
			expectedRelease: "",
			expectedDetect:  false,
		},
		{
			name:            "no evidence at all",
			evidence:        []ebsEvidence{},
			expectedTitle:   "",
			expectedRelease: "",
			expectedDetect:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			title, release, detected := evaluateEBS(tt.evidence)
			assert.Equal(t, tt.expectedTitle, title)
			assert.Equal(t, tt.expectedRelease, release)
			assert.Equal(t, tt.expectedDetect, detected)
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

func TestEBSPlugin_Run_PositiveViaRedirectAndTitle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Location", "/OA_HTML/AppsLogin")
			w.WriteHeader(http.StatusFound)
		case "/OA_HTML/AppsLogin":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>E-Business Suite Home Page Redirect</title></head><body>Welcome to Oracle E-Business Suite. Please use AppsLocalLogin.jsp</body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
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

	plugin := &EBSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var ebsService plugins.ServiceOracleEBS
	err = json.Unmarshal(service.Raw, &ebsService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.Equal(t, "R12", ebsService.Release)
	assert.Equal(t, "E-Business Suite Home Page Redirect", ebsService.Title)
	require.Len(t, ebsService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:e-business_suite:*:*:*:*:*:*:*:*", ebsService.CPEs[0])
}

func TestEBSPlugin_Run_PositiveViaBodyMarkerOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Login</title></head><body>Oracle E-Business Suite</body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
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

	plugin := &EBSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var ebsService plugins.ServiceOracleEBS
	err = json.Unmarshal(service.Raw, &ebsService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.Empty(t, ebsService.Release)
	require.Len(t, ebsService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:e-business_suite:*:*:*:*:*:*:*:*", ebsService.CPEs[0])
}

func TestEBSPlugin_Run_GenericOHSHeaderDoesNotTrigger(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generic Oracle-HTTP-Server header alone must NOT be sufficient for detection.
		w.Header().Set("Server", "Oracle-HTTP-Server")
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "hello")
		default:
			w.WriteHeader(http.StatusNotFound)
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

	plugin := &EBSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestEBSPlugin_Metadata(t *testing.T) {
	plugin := &EBSPlugin{}
	assert.Equal(t, OracleEBS, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, 100, plugin.Priority())
	assert.True(t, plugin.PortPriority(8000))
	assert.False(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(80))
}

func TestEBSTLSPlugin_Run_PositiveViaBodyMarker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Login</title></head><body>Oracle E-Business Suite</body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
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

	plugin := &EBSTLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var ebsService plugins.ServiceOracleEBS
	err = json.Unmarshal(service.Raw, &ebsService)
	require.NoError(t, err)
	require.Len(t, ebsService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:e-business_suite:*:*:*:*:*:*:*:*", ebsService.CPEs[0])
}

func TestEBSTLSPlugin_Metadata(t *testing.T) {
	plugin := &EBSTLSPlugin{}
	assert.Equal(t, OracleEBS, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, 100, plugin.Priority())
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(8000))
}

func TestEBSSecurityFindings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Login</title></head><body>Oracle E-Business Suite</body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	t.Run("with Misconfigs=true yields AnonymousAccess and finding", func(t *testing.T) {
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := parseTestServerAddr(t, server.URL)
		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		target := plugins.Target{
			Host:       addr.Addr().String(),
			Address:    addr,
			Misconfigs: true,
		}

		plugin := &EBSPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "oracle-ebs-login-exposed", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityLow, service.SecurityFindings[0].Severity)
	})

	t.Run("with Misconfigs=false yields no SecurityFindings", func(t *testing.T) {
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := parseTestServerAddr(t, server.URL)
		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		target := plugins.Target{
			Host:       addr.Addr().String(),
			Address:    addr,
			Misconfigs: false,
		}

		plugin := &EBSPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}

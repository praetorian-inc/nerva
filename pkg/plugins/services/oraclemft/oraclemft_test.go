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

package oraclemft

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
			body:     `<html><head><title>Oracle Managed File Transfer</title></head></html>`,
			expected: "Oracle Managed File Transfer",
		},
		{
			name:     "title with whitespace",
			body:     `<html><head><title>  MFT Login  </title></head></html>`,
			expected: "MFT Login",
		},
		{
			name:     "no title element",
			body:     `<html><body>MFT Console</body></html>`,
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

func TestLocationPointsToMFTConsole(t *testing.T) {
	tests := []struct {
		name     string
		location string
		expected bool
	}{
		{
			name:     "exact mftconsole path",
			location: "/mftconsole",
			expected: true,
		},
		{
			name:     "mftconsole with trailing slash",
			location: "/mftconsole/",
			expected: true,
		},
		{
			name:     "mftconsole faces login",
			location: "/mftconsole/faces/login",
			expected: true,
		},
		{
			name:     "absolute URL with mftconsole path",
			location: "http://host:7011/mftconsole/faces/login",
			expected: true,
		},
		{
			name:     "unrelated path",
			location: "/console/login",
			expected: false,
		},
		{
			name:     "empty location",
			location: "",
			expected: false,
		},
		{
			name:     "mftconsole in query string only",
			location: "/login?next=/mftconsole",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := locationPointsToMFTConsole(tt.location)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluateMFT(t *testing.T) {
	tests := []struct {
		name     string
		evidence []mftEvidence
		expected bool
	}{
		{
			name: "mftconsole with Managed File Transfer body",
			evidence: []mftEvidence{
				{
					path:       "/mftconsole/faces/login",
					statusCode: http.StatusOK,
					body:       `<html><head><title>MFT Login</title></head><body>Oracle Managed File Transfer</body></html>`,
				},
			},
			expected: true,
		},
		{
			name: "mftconsole with LoginSubmit.do form action",
			evidence: []mftEvidence{
				{
					path:       "/mftconsole/faces/login",
					statusCode: http.StatusOK,
					body:       `<html><body><form action="LoginSubmit.do" method="POST"></form></body></html>`,
				},
			},
			expected: true,
		},
		{
			name: "mftconsole with j_security_check form action",
			evidence: []mftEvidence{
				{
					path:       "/mftconsole/faces/login",
					statusCode: http.StatusOK,
					body:       `<html><body><form action="j_security_check" method="POST"></form></body></html>`,
				},
			},
			expected: true,
		},
		{
			name: "mftapp REST API with mft in body",
			evidence: []mftEvidence{
				{
					path:       "/mftapp/rest/v1/",
					statusCode: http.StatusOK,
					body:       `{"application":"mft","version":"12.2.1.4.0"}`,
				},
			},
			expected: true,
		},
		{
			name: "redirect to mftconsole path",
			evidence: []mftEvidence{
				{
					path:       "/mftconsole",
					statusCode: http.StatusFound,
					location:   "/mftconsole/faces/login",
					body:       "",
				},
			},
			expected: true,
		},
		{
			name: "308 Permanent Redirect to mftconsole",
			evidence: []mftEvidence{
				{
					path:       "/",
					statusCode: http.StatusPermanentRedirect,
					location:   "/mftconsole/",
					body:       "",
				},
			},
			expected: true,
		},
		{
			name: "mftconsole path returns 404 does not trigger",
			evidence: []mftEvidence{
				{
					path:       "/mftconsole",
					statusCode: http.StatusNotFound,
					body:       `<html><body>Not Found</body></html>`,
				},
			},
			expected: false,
		},
		{
			name: "mftapp REST API returns 404 does not trigger",
			evidence: []mftEvidence{
				{
					path:       "/mftapp/rest/v1/",
					statusCode: http.StatusNotFound,
					body:       `{"error":"not found","mft":"none"}`,
				},
			},
			expected: false,
		},
		{
			name: "soft-404 echoing path in body does not trigger",
			evidence: []mftEvidence{
				{
					path:       "/mftconsole",
					statusCode: http.StatusOK,
					body:       `<html><body>The requested resource /mftconsole was not found</body></html>`,
				},
			},
			expected: false,
		},
		{
			name: "200 on mftconsole path with no product markers does not trigger",
			evidence: []mftEvidence{
				{
					path:       "/mftconsole",
					statusCode: http.StatusOK,
					body:       `<html><body>hello world</body></html>`,
				},
			},
			expected: false,
		},
		{
			name:     "no evidence at all",
			evidence: []mftEvidence{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, detected := evaluateMFT(tt.evidence)
			assert.Equal(t, tt.expected, detected)
		})
	}
}

func TestEvaluateMFT_TitleFromMatchedResponseOnly(t *testing.T) {
	t.Run("title captured from matching response", func(t *testing.T) {
		title, detected := evaluateMFT([]mftEvidence{
			{
				path:       "/mftconsole/faces/login",
				statusCode: http.StatusOK,
				body:       `<html><head><title>Oracle MFT Console</title></head><body>Oracle Managed File Transfer</body></html>`,
			},
		})
		assert.True(t, detected)
		assert.Equal(t, "Oracle MFT Console", title)
	})

	t.Run("title not captured from non-matching response", func(t *testing.T) {
		title, detected := evaluateMFT([]mftEvidence{
			{
				path:       "/mftconsole",
				statusCode: http.StatusOK,
				body:       `<html><head><title>Generic App</title></head><body>hello</body></html>`,
			},
			{
				path:       "/mftconsole/faces/login",
				statusCode: http.StatusOK,
				body:       `<html><head><title>MFT Login</title></head><body>Managed File Transfer</body></html>`,
			},
		})
		assert.True(t, detected)
		assert.Equal(t, "MFT Login", title)
	})
}

// parseTestServerAddr parses httptest server URL into netip.AddrPort.
func parseTestServerAddr(t *testing.T, serverURL string) netip.AddrPort {
	t.Helper()
	hostPort := strings.TrimPrefix(serverURL, "http://")
	host, portStr, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))
}

func TestMFTPlugin_Run_PositiveViaLoginPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mftconsole":
			http.Redirect(w, r, "/mftconsole/faces/login", http.StatusFound)
		case "/mftconsole/faces/login":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Oracle Managed File Transfer</title></head><body><h1>Oracle Managed File Transfer</h1><form action="j_security_check" method="POST"><input name="j_username"/><input name="j_password" type="password"/></form></body></html>`)
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

	plugin := &MFTPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var svc plugins.ServiceMFT
	err = json.Unmarshal(service.Raw, &svc)
	require.NoError(t, err)
	assert.Equal(t, "Oracle Managed File Transfer", svc.Title)
	require.Len(t, svc.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:managed_file_transfer:*:*:*:*:*:*:*:*", svc.CPEs[0])
}

func TestMFTPlugin_Run_PositiveViaRESTAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mftapp/rest/v1/":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"application":"mft","status":"running"}`)
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

	plugin := &MFTPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var svc plugins.ServiceMFT
	err = json.Unmarshal(service.Raw, &svc)
	require.NoError(t, err)
	require.Len(t, svc.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:managed_file_transfer:*:*:*:*:*:*:*:*", svc.CPEs[0])
}

func TestMFTPlugin_Run_NegativeAllReturn404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
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

	plugin := &MFTPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestMFTPlugin_Run_NegativeGenericPathNoMarker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>hello world</body></html>`)
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

	plugin := &MFTPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestMFTPlugin_Metadata(t *testing.T) {
	plugin := &MFTPlugin{}
	assert.Equal(t, OracleMFT, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.False(t, plugin.PortPriority(7001))
	assert.False(t, plugin.PortPriority(80))
	assert.False(t, plugin.PortPriority(443))
}

func TestMFTTLSPlugin_Run_PositiveViaLoginPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mftconsole/faces/login":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>MFT Console</title></head><body>Oracle Managed File Transfer<form action="j_security_check"></form></body></html>`)
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

	plugin := &MFTTLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var svc plugins.ServiceMFT
	err = json.Unmarshal(service.Raw, &svc)
	require.NoError(t, err)
	require.Len(t, svc.CPEs, 1)
}

func TestMFTTLSPlugin_Metadata(t *testing.T) {
	plugin := &MFTTLSPlugin{}
	assert.Equal(t, OracleMFT, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(7001))
}

func TestMFTSecurityFindings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mftconsole/faces/login":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><body>Oracle Managed File Transfer</body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	t.Run("with Misconfigs=true yields finding but no AnonymousAccess", func(t *testing.T) {
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

		plugin := &MFTPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "oracle-mft-console-exposed", service.SecurityFindings[0].ID)
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

		plugin := &MFTPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}

func TestServiceMFT_Type(t *testing.T) {
	s := plugins.ServiceMFT{Title: "test"}
	assert.Equal(t, "oracle_mft", s.Type())
}

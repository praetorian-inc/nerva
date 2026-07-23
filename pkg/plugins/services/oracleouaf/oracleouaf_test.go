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

package oracleouaf

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
			body:     `<html><head><title>Oracle Utilities Login</title></head></html>`,
			expected: "Oracle Utilities Login",
		},
		{
			name:     "title with whitespace",
			body:     `<html><head><title>  Login Page  </title></head></html>`,
			expected: "Login Page",
		},
		{
			name:     "no title element",
			body:     `<html><body>Oracle Utilities</body></html>`,
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

func TestLocationPointsToOUAF(t *testing.T) {
	tests := []struct {
		name     string
		location string
		expected bool
	}{
		{
			name:     "exact ouaf path",
			location: "/ouaf/loginPage.jsp",
			expected: true,
		},
		{
			name:     "absolute URL with ouaf path",
			location: "http://host/ouaf/cis.jsp",
			expected: true,
		},
		{
			name:     "unrelated path",
			location: "/some/other",
			expected: false,
		},
		{
			name:     "empty location",
			location: "",
			expected: false,
		},
		{
			name:     "ouaf in query string only",
			location: "/login?next=/ouaf/loginPage.jsp",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := locationPointsToOUAF(tt.location)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLocationPointsToUTA(t *testing.T) {
	tests := []struct {
		name     string
		location string
		expected bool
	}{
		{
			name:     "exact uta path",
			location: "/uta/login.html",
			expected: true,
		},
		{
			name:     "absolute URL with uta path",
			location: "http://host/uta/login.html",
			expected: true,
		},
		{
			name:     "unrelated path",
			location: "/other",
			expected: false,
		},
		{
			name:     "empty location",
			location: "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := locationPointsToUTA(tt.location)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildOUAFCPEs(t *testing.T) {
	tests := []struct {
		name     string
		ouaf     bool
		uta      bool
		expected []string
	}{
		{
			name: "ouaf only",
			ouaf: true,
			uta:  false,
			expected: []string{
				"cpe:2.3:a:oracle:utilities_application_framework:*:*:*:*:*:*:*:*",
			},
		},
		{
			name: "uta only",
			ouaf: false,
			uta:  true,
			expected: []string{
				"cpe:2.3:a:oracle:utilities_testing_accelerator:*:*:*:*:*:*:*:*",
			},
		},
		{
			name: "both ouaf and uta",
			ouaf: true,
			uta:  true,
			expected: []string{
				"cpe:2.3:a:oracle:utilities_application_framework:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:oracle:utilities_testing_accelerator:*:*:*:*:*:*:*:*",
			},
		},
		{
			name:     "neither",
			ouaf:     false,
			uta:      false,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildOUAFCPEs(tt.ouaf, tt.uta)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluateOUAF(t *testing.T) {
	tests := []struct {
		name         string
		evidence     []ouafEvidence
		expectedOUAF bool
		expectedUTA  bool
	}{
		{
			name: "ouaf login page with Oracle Utilities body",
			evidence: []ouafEvidence{
				{
					path:       "/ouaf/loginPage.jsp",
					statusCode: http.StatusOK,
					body:       `<html><head><title>Login</title></head><body>Oracle Utilities Application Framework</body></html>`,
				},
			},
			expectedOUAF: true,
			expectedUTA:  false,
		},
		{
			name: "ouaf login page with j_security_check",
			evidence: []ouafEvidence{
				{
					path:       "/ouaf/loginPage.jsp",
					statusCode: http.StatusOK,
					body:       `<html><body><form action="j_security_check" method="POST"></form></body></html>`,
				},
			},
			expectedOUAF: true,
			expectedUTA:  false,
		},
		{
			name: "ouaf cis.jsp with product marker",
			evidence: []ouafEvidence{
				{
					path:       "/ouaf/cis.jsp",
					statusCode: http.StatusOK,
					body:       `<html><body>Oracle Utilities CIS Main</body></html>`,
				},
			},
			expectedOUAF: true,
			expectedUTA:  false,
		},
		{
			name: "ouaf cis.jsp 200 without product marker does not trigger",
			evidence: []ouafEvidence{
				{
					path:       "/ouaf/cis.jsp",
					statusCode: http.StatusOK,
					body:       `<html><body>hello world</body></html>`,
				},
			},
			expectedOUAF: false,
			expectedUTA:  false,
		},
		{
			name: "ouaf rest endpoint with Oracle Utilities body",
			evidence: []ouafEvidence{
				{
					path:       "/ouaf/rest",
					statusCode: http.StatusOK,
					body:       `<html><body>Oracle Utilities REST</body></html>`,
				},
			},
			expectedOUAF: true,
			expectedUTA:  false,
		},
		{
			name: "ouaf rest endpoint with application JSON surface",
			evidence: []ouafEvidence{
				{
					path:       "/ouaf/rest",
					statusCode: http.StatusOK,
					body:       `{"application":"Oracle Utilities Application Framework","version":"4.4.0.3.0"}`,
				},
			},
			expectedOUAF: true,
			expectedUTA:  false,
		},
		{
			name: "ouaf rest endpoint 404 does not trigger",
			evidence: []ouafEvidence{
				{
					path:       "/ouaf/rest",
					statusCode: http.StatusNotFound,
					body:       `{"error":"not found","application":"none"}`,
				},
			},
			expectedOUAF: false,
			expectedUTA:  false,
		},
		{
			name: "redirect to ouaf path",
			evidence: []ouafEvidence{
				{
					path:       "/",
					statusCode: http.StatusFound,
					location:   "/ouaf/loginPage.jsp",
					body:       "",
				},
			},
			expectedOUAF: true,
			expectedUTA:  false,
		},
		{
			name: "303 See Other redirect to ouaf path",
			evidence: []ouafEvidence{
				{
					path:       "/",
					statusCode: http.StatusSeeOther,
					location:   "/ouaf/loginPage.jsp",
					body:       "",
				},
			},
			expectedOUAF: true,
			expectedUTA:  false,
		},
		{
			name: "308 Permanent Redirect to ouaf path",
			evidence: []ouafEvidence{
				{
					path:       "/",
					statusCode: http.StatusPermanentRedirect,
					location:   "/ouaf/loginPage.jsp",
					body:       "",
				},
			},
			expectedOUAF: true,
			expectedUTA:  false,
		},
		{
			name: "uta login page with Testing Accelerator body",
			evidence: []ouafEvidence{
				{
					path:       "/uta/login.html",
					statusCode: http.StatusOK,
					body:       `<html><head><title>Testing Accelerator</title></head><body>Oracle Utilities Testing Accelerator</body></html>`,
				},
			},
			expectedOUAF: false,
			expectedUTA:  true,
		},
		{
			name: "uta login page with generic Oracle Utilities body does not trigger UTA",
			evidence: []ouafEvidence{
				{
					path:       "/uta/login.html",
					statusCode: http.StatusOK,
					body:       `<html><body>Oracle Utilities application</body></html>`,
				},
			},
			expectedOUAF: false,
			expectedUTA:  false,
		},
		{
			name: "redirect to uta path",
			evidence: []ouafEvidence{
				{
					path:       "/",
					statusCode: http.StatusFound,
					location:   "/uta/login.html",
					body:       "",
				},
			},
			expectedOUAF: false,
			expectedUTA:  true,
		},
		{
			name: "both ouaf and uta detected",
			evidence: []ouafEvidence{
				{
					path:       "/ouaf/loginPage.jsp",
					statusCode: http.StatusOK,
					body:       `<html><body>Oracle Utilities Login</body></html>`,
				},
				{
					path:       "/uta/login.html",
					statusCode: http.StatusOK,
					body:       `<html><head><title>Testing Accelerator</title></head><body>Oracle Utilities Testing Accelerator</body></html>`,
				},
			},
			expectedOUAF: true,
			expectedUTA:  true,
		},
		{
			name: "ouaf path returns 404 does not trigger",
			evidence: []ouafEvidence{
				{
					path:       "/ouaf/loginPage.jsp",
					statusCode: http.StatusNotFound,
					body:       `<html><body>Not Found</body></html>`,
				},
			},
			expectedOUAF: false,
			expectedUTA:  false,
		},
		{
			name: "uta path returns 404 does not trigger",
			evidence: []ouafEvidence{
				{
					path:       "/uta/login.html",
					statusCode: http.StatusNotFound,
					body:       `<html><body>Testing Accelerator not found</body></html>`,
				},
			},
			expectedOUAF: false,
			expectedUTA:  false,
		},
		{
			name:         "no evidence at all",
			evidence:     []ouafEvidence{},
			expectedOUAF: false,
			expectedUTA:  false,
		},
		{
			name: "soft-404 echoing loginPage in body does not trigger OUAF",
			evidence: []ouafEvidence{
				{
					path:       "/ouaf/loginPage.jsp",
					statusCode: http.StatusOK,
					body:       `<html><body>The requested resource /ouaf/loginPage.jsp was not found</body></html>`,
				},
			},
			expectedOUAF: false,
			expectedUTA:  false,
		},
		{
			name: "soft-404 echoing cis.jsp in body does not trigger OUAF",
			evidence: []ouafEvidence{
				{
					path:       "/ouaf/cis.jsp",
					statusCode: http.StatusOK,
					body:       `<html><body>Access denied: /ouaf/cis.jsp</body></html>`,
				},
			},
			expectedOUAF: false,
			expectedUTA:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ouaf, uta := evaluateOUAF(tt.evidence)
			assert.Equal(t, tt.expectedOUAF, ouaf)
			assert.Equal(t, tt.expectedUTA, uta)
		})
	}
}

func TestEvaluateOUAF_TitleFromMatchedResponseOnly(t *testing.T) {
	t.Run("title captured from matching response", func(t *testing.T) {
		title, ouaf, _ := evaluateOUAF([]ouafEvidence{
			{
				path:       "/ouaf/loginPage.jsp",
				statusCode: http.StatusOK,
				body:       `<html><head><title>OUAF Login</title></head><body>Oracle Utilities Application Framework</body></html>`,
			},
		})
		assert.True(t, ouaf)
		assert.Equal(t, "OUAF Login", title)
	})

	t.Run("title not captured from 404 response", func(t *testing.T) {
		title, ouaf, uta := evaluateOUAF([]ouafEvidence{
			{
				path:       "/ouaf/loginPage.jsp",
				statusCode: http.StatusNotFound,
				body:       `<html><head><title>Not Found</title></head><body>404</body></html>`,
			},
		})
		assert.False(t, ouaf)
		assert.False(t, uta)
		assert.Equal(t, "", title)
	})

	t.Run("title not captured from non-matching response", func(t *testing.T) {
		title, ouaf, _ := evaluateOUAF([]ouafEvidence{
			{
				path:       "/ouaf/cis.jsp",
				statusCode: http.StatusOK,
				body:       `<html><head><title>Generic App</title></head><body>hello</body></html>`,
			},
			{
				path:       "/ouaf/loginPage.jsp",
				statusCode: http.StatusOK,
				body:       `<html><head><title>OUAF Login</title></head><body>Oracle Utilities</body></html>`,
			},
		})
		assert.True(t, ouaf)
		assert.Equal(t, "OUAF Login", title)
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

func TestOUAFPlugin_Run_PositiveViaLoginPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ouaf/loginPage.jsp":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Oracle Utilities Login</title></head><body>Oracle Utilities Application Framework<form action="j_security_check" method="POST"></form></body></html>`)
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

	plugin := &OUAFPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var ouafService plugins.ServiceOracleOUAF
	err = json.Unmarshal(service.Raw, &ouafService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.True(t, ouafService.OUAF)
	assert.False(t, ouafService.UTA)
	assert.Equal(t, "Oracle Utilities Login", ouafService.Title)
	require.Len(t, ouafService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:utilities_application_framework:*:*:*:*:*:*:*:*", ouafService.CPEs[0])
}

func TestOUAFPlugin_Run_PositiveViaCisJSP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ouaf/cis.jsp":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>CIS</title></head><body>Oracle Utilities CIS Main Servlet</body></html>`)
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

	plugin := &OUAFPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var ouafService plugins.ServiceOracleOUAF
	err = json.Unmarshal(service.Raw, &ouafService)
	require.NoError(t, err)
	assert.True(t, ouafService.OUAF)
}

func TestOUAFPlugin_Run_PositiveViaUTAOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/uta/login.html":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Testing Accelerator</title></head><body>Oracle Utilities Testing Accelerator</body></html>`)
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

	plugin := &OUAFPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)
	assert.Equal(t, "oracle_uta", service.Protocol)

	var ouafService plugins.ServiceOracleOUAF
	err = json.Unmarshal(service.Raw, &ouafService)
	require.NoError(t, err)
	assert.False(t, ouafService.OUAF)
	assert.True(t, ouafService.UTA)
	require.Len(t, ouafService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:utilities_testing_accelerator:*:*:*:*:*:*:*:*", ouafService.CPEs[0])
}

func TestOUAFPlugin_Run_PositiveBothOUAFAndUTA(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ouaf/loginPage.jsp":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Oracle Utilities</title></head><body>Oracle Utilities Application Framework</body></html>`)
		case "/uta/login.html":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Testing Accelerator</title></head><body>Oracle Utilities Testing Accelerator</body></html>`)
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

	plugin := &OUAFPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)
	assert.Equal(t, "oracle_ouaf", service.Protocol)

	var ouafService plugins.ServiceOracleOUAF
	err = json.Unmarshal(service.Raw, &ouafService)
	require.NoError(t, err)
	assert.True(t, ouafService.OUAF)
	assert.True(t, ouafService.UTA)
	require.Len(t, ouafService.CPEs, 2)
}

func TestOUAFPlugin_Run_NegativeAllReturn404(t *testing.T) {
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

	plugin := &OUAFPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestOUAFPlugin_Run_NegativeGenericOUAFPathNoMarker(t *testing.T) {
	// A server that returns 200 on /ouaf/ paths but with no OUAF-specific
	// body content must NOT trigger detection.
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

	plugin := &OUAFPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestOUAFPlugin_Metadata(t *testing.T) {
	plugin := &OUAFPlugin{}
	assert.Equal(t, OracleOUAF, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(6501))
	assert.True(t, plugin.PortPriority(6500))
	assert.False(t, plugin.PortPriority(80))
	assert.False(t, plugin.PortPriority(443))
}

func TestOUAFTLSPlugin_Run_PositiveViaLoginPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ouaf/loginPage.jsp":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Oracle Utilities</title></head><body>Oracle Utilities Application Framework</body></html>`)
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

	plugin := &OUAFTLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var ouafService plugins.ServiceOracleOUAF
	err = json.Unmarshal(service.Raw, &ouafService)
	require.NoError(t, err)
	assert.True(t, ouafService.OUAF)
	require.Len(t, ouafService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:utilities_application_framework:*:*:*:*:*:*:*:*", ouafService.CPEs[0])
}

func TestOUAFTLSPlugin_Metadata(t *testing.T) {
	plugin := &OUAFTLSPlugin{}
	assert.Equal(t, OracleOUAF, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(6501))
	assert.False(t, plugin.PortPriority(8080))
}

func TestOUAFSecurityFindings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ouaf/loginPage.jsp":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><body>Oracle Utilities Application Framework</body></html>`)
		case "/uta/login.html":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Testing Accelerator</title></head><body>Oracle Utilities Testing Accelerator</body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	t.Run("with Misconfigs=true yields both findings but no AnonymousAccess", func(t *testing.T) {
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

		plugin := &OUAFPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		// A reachable login page is not anonymous access; only the findings are set.
		assert.False(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 2)

		findingIDs := make([]string, len(service.SecurityFindings))
		for i, f := range service.SecurityFindings {
			findingIDs[i] = f.ID
		}
		assert.Contains(t, findingIDs, "oracle-ouaf-login-exposed")
		assert.Contains(t, findingIDs, "oracle-uta-login-exposed")
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

		plugin := &OUAFPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}

func TestServiceOracleOUAF_Type(t *testing.T) {
	t.Run("ouaf detected returns oracle_ouaf", func(t *testing.T) {
		s := plugins.ServiceOracleOUAF{OUAF: true, UTA: false}
		assert.Equal(t, "oracle_ouaf", s.Type())
	})

	t.Run("both detected returns oracle_ouaf", func(t *testing.T) {
		s := plugins.ServiceOracleOUAF{OUAF: true, UTA: true}
		assert.Equal(t, "oracle_ouaf", s.Type())
	})

	t.Run("uta only returns oracle_uta", func(t *testing.T) {
		s := plugins.ServiceOracleOUAF{OUAF: false, UTA: true}
		assert.Equal(t, "oracle_uta", s.Type())
	})

	t.Run("neither returns oracle_ouaf", func(t *testing.T) {
		s := plugins.ServiceOracleOUAF{OUAF: false, UTA: false}
		assert.Equal(t, "oracle_ouaf", s.Type())
	})
}

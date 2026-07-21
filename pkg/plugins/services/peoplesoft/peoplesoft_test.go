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

package peoplesoft

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
			body:     `<html><head><title>Oracle PeopleSoft Sign-in</title></head></html>`,
			expected: "Oracle PeopleSoft Sign-in",
		},
		{
			name:     "title with surrounding whitespace",
			body:     `<html><head><title>  Some Title  </title></head></html>`,
			expected: "Some Title",
		},
		{
			name:     "no title element",
			body:     `<html><head></head><body>PeopleSoft</body></html>`,
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

func TestCookieContains(t *testing.T) {
	tests := []struct {
		name      string
		setCookie string
		cookie    string
		expected  bool
	}{
		{
			name:      "PS_TOKEN cookie present",
			setCookie: "PS_TOKEN=abc123; Path=/",
			cookie:    "PS_TOKEN",
			expected:  true,
		},
		{
			name:      "PS_TOKENEXPIRE does not match PS_TOKEN check",
			setCookie: "PS_TOKENEXPIRE=Fri, 15-Dec-2023; Path=/",
			cookie:    "PS_TOKEN",
			expected:  false,
		},
		{
			name:      "PS_LOGINLIST does not match PS_TOKEN check",
			setCookie: "PS_LOGINLIST=abc; Path=/",
			cookie:    "PS_TOKEN",
			expected:  false,
		},
		{
			name:      "empty Set-Cookie header",
			setCookie: "",
			cookie:    "PS_TOKEN",
			expected:  false,
		},
		{
			name:      "PS_TOKEN present among multiple cookies",
			setCookie: "PS_TOKENEXPIRE=abc; PS_TOKEN=xyz; PS_LOGINLIST=q",
			cookie:    "PS_TOKEN",
			expected:  true,
		},
		{
			name:      "PS_TOKEN after another cookie delimited by semicolon",
			setCookie: "PS_LASTSITE=x; PS_TOKEN=abc",
			cookie:    "PS_TOKEN",
			expected:  true,
		},
		{
			name:      "APP_PS_TOKEN does not match PS_TOKEN check (name embedded mid-token, not at a boundary)",
			setCookie: "APP_PS_TOKEN=abc",
			cookie:    "PS_TOKEN",
			expected:  false,
		},
		{
			name:      "PS_TOKENEXPIRE alone does not match PS_TOKEN check",
			setCookie: "PS_TOKENEXPIRE=x",
			cookie:    "PS_TOKEN",
			expected:  false,
		},
		{
			name:      "PS_LOGINLIST alone does not match PS_TOKEN check",
			setCookie: "PS_LOGINLIST=x",
			cookie:    "PS_TOKEN",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cookieContains(tt.setCookie, tt.cookie)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBodyHasPeopleSoftMarker(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "contains peoplesoft (case-insensitive)",
			body:     "Welcome to PeopleSoft Enterprise",
			expected: true,
		},
		{
			name:     "contains peopletools",
			body:     "Powered by PeopleTools",
			expected: true,
		},
		{
			name:     "bare /psp/ path reference is not a genuine marker",
			body:     `<a href="/psp/ps/?cmd=login">Login</a>`,
			expected: false,
		},
		{
			name:     "bare /psc/ path reference is not a genuine marker",
			body:     `<a href="/psc/ps/">Content</a>`,
			expected: false,
		},
		{
			name:     "contains PS_TOKEN reference",
			body:     "document.cookie has PS_TOKEN set",
			expected: true,
		},
		{
			name:     "no PeopleSoft markers",
			body:     "<html><body>hello world</body></html>",
			expected: false,
		},
		{
			name:     "empty body",
			body:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bodyHasPeopleSoftMarker(tt.body)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParsePeopleToolsVersion(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "no Registered Hosts Summary marker",
			body:     "PeopleTools 8.60.12",
			expected: "",
		},
		{
			name:     "marker present with version",
			body:     "Registered Hosts Summary ... PeopleTools 8.60.12 ...",
			expected: "8.60.12",
		},
		{
			name:     "marker present with two-component version",
			body:     "Registered Hosts Summary ... PeopleTools 8.59 ...",
			expected: "8.59",
		},
		{
			name:     "marker present but no version",
			body:     "Registered Hosts Summary but no version token here",
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
			result := parsePeopleToolsVersion(tt.body)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildPeopleSoftCPEs(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected []string
	}{
		{
			name:    "with PeopleTools version: app CPE stays wildcard, peopletools CPE carries version",
			version: "8.60.12",
			expected: []string{
				"cpe:2.3:a:oracle:peoplesoft_enterprise:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:oracle:peoplesoft_enterprise_peopletools:8.60.12:*:*:*:*:*:*:*",
			},
		},
		{
			name:    "empty version: only the wildcard app CPE is emitted",
			version: "",
			expected: []string{
				"cpe:2.3:a:oracle:peoplesoft_enterprise:*:*:*:*:*:*:*:*",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildPeopleSoftCPEs(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluatePeopleSoft(t *testing.T) {
	tests := []struct {
		name           string
		evidence       []psEvidence
		expectedTitle  string
		expectedPSTok  bool
		expectedDetect bool
	}{
		{
			name: "PS_TOKEN cookie signal",
			evidence: []psEvidence{
				{
					path:       "/psp/ps/?cmd=login",
					statusCode: http.StatusOK,
					setCookie:  "PS_TOKEN=abc123; Path=/",
				},
			},
			expectedTitle:  "",
			expectedPSTok:  true,
			expectedDetect: true,
		},
		{
			name: "PeopleSoft sign-in title signal",
			evidence: []psEvidence{
				{
					path:       "/",
					statusCode: http.StatusOK,
					body:       `<html><head><title>Oracle PeopleSoft Sign-in</title></head></html>`,
				},
			},
			expectedTitle:  "Oracle PeopleSoft Sign-in",
			expectedPSTok:  false,
			expectedDetect: true,
		},
		{
			name: "both psp and psc respond with markers",
			evidence: []psEvidence{
				{
					path:       "/psp/ps/?cmd=login",
					statusCode: http.StatusOK,
					body:       "PeopleSoft portal",
				},
				{
					path:       "/psc/ps/",
					statusCode: http.StatusOK,
					body:       "PeopleSoft content",
				},
			},
			expectedTitle:  "",
			expectedPSTok:  false,
			expectedDetect: true,
		},
		{
			name: "only psp responds, psc does not",
			evidence: []psEvidence{
				{
					path:       "/psp/ps/?cmd=login",
					statusCode: http.StatusOK,
					body:       "PeopleSoft portal",
				},
				{
					path:       "/psc/ps/",
					statusCode: http.StatusNotFound,
					body:       "",
				},
			},
			expectedTitle:  "",
			expectedPSTok:  false,
			expectedDetect: false,
		},
		{
			name: "PS_TOKENEXPIRE cookie alone does not trigger PSToken",
			evidence: []psEvidence{
				{
					path:       "/",
					statusCode: http.StatusOK,
					setCookie:  "PS_TOKENEXPIRE=abc; Path=/",
					body:       "<html><body>hello</body></html>",
				},
			},
			expectedTitle:  "",
			expectedPSTok:  false,
			expectedDetect: false,
		},
		{
			name:           "no evidence at all",
			evidence:       []psEvidence{},
			expectedTitle:  "",
			expectedPSTok:  false,
			expectedDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			title, psToken, detected := evaluatePeopleSoft(tt.evidence)
			assert.Equal(t, tt.expectedTitle, title)
			assert.Equal(t, tt.expectedPSTok, psToken)
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

func TestPeopleSoftPlugin_Run_PositiveViaPSTokenCookie(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/psp/ps/":
			w.Header().Set("Set-Cookie", "PS_TOKEN=abc123; Path=/")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Login</title></head></html>`)
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

	plugin := &PeopleSoftPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var psService plugins.ServicePeopleSoft
	err = json.Unmarshal(service.Raw, &psService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.True(t, psService.PSToken)
	require.Len(t, psService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:peoplesoft_enterprise:*:*:*:*:*:*:*:*", psService.CPEs[0])
}

func TestPeopleSoftPlugin_Run_PositiveViaTitleOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Oracle PeopleSoft Sign-in</title></head></html>`)
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

	plugin := &PeopleSoftPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var psService plugins.ServicePeopleSoft
	err = json.Unmarshal(service.Raw, &psService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.False(t, psService.PSToken)
	require.Len(t, psService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:peoplesoft_enterprise:*:*:*:*:*:*:*:*", psService.CPEs[0])
}

func TestPeopleSoftPlugin_Run_PositiveWithPeopleToolsVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Oracle PeopleSoft Sign-in</title></head></html>`)
		case "/PSEMHUB/hub":
			fmt.Fprintf(w, "Registered Hosts Summary ... PeopleTools 8.60.12 ...")
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

	plugin := &PeopleSoftPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var psService plugins.ServicePeopleSoft
	err = json.Unmarshal(service.Raw, &psService)
	require.NoError(t, err, "failed to unmarshal service payload")
	require.Len(t, psService.CPEs, 2)
	assert.Contains(t, psService.CPEs, "cpe:2.3:a:oracle:peoplesoft_enterprise:*:*:*:*:*:*:*:*")
	assert.Contains(t, psService.CPEs, "cpe:2.3:a:oracle:peoplesoft_enterprise_peopletools:8.60.12:*:*:*:*:*:*:*")
}

func TestPeopleSoftPlugin_Run_Negative(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	plugin := &PeopleSoftPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

// TestPeopleSoftPlugin_Run_PathReflectionDoesNotTrigger verifies the fix for
// the false positive where a catch-all app that echoes the requested URL back
// in a non-404 response body was misidentified as PeopleSoft merely because
// the /psp/ and /psc/ path tokens (which the plugin itself probes) appeared in
// the body. Without a genuine PeopleSoft marker (PeopleSoft/PeopleTools string
// or PS_TOKEN) and without the PS_TOKEN cookie or sign-in title, Run must
// return nil even though both /psp/ and /psc/ respond non-404.
func TestPeopleSoftPlugin_Run_PathReflectionDoesNotTrigger(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Catch-all: echo the requested path back in the body for any path,
		// with no PeopleSoft-specific marker and no PS_TOKEN cookie.
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<html><body>You requested: %s</body></html>`, r.URL.Path)
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

	plugin := &PeopleSoftPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service, "path-reflecting catch-all with no genuine PeopleSoft marker must not be detected as PeopleSoft")
}

// TestPeopleSoftPlugin_Run_AppPSTokenCookieDoesNotTrigger verifies that a
// cookie whose name merely embeds "PS_TOKEN" mid-token (e.g. a hypothetical
// "APP_PS_TOKEN" cookie set by some unrelated app) is not mistaken for the
// genuine PeopleSoft PS_TOKEN cookie. cookieContains requires the name at a
// cookie boundary, so with no other PeopleSoft evidence present, Run must
// return nil.
func TestPeopleSoftPlugin_Run_AppPSTokenCookieDoesNotTrigger(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Set-Cookie", "APP_PS_TOKEN=abc123; Path=/")
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

	plugin := &PeopleSoftPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service, "APP_PS_TOKEN cookie alone (no other PeopleSoft evidence) must not be detected as PeopleSoft")
}

func TestPeopleSoftPlugin_Metadata(t *testing.T) {
	plugin := &PeopleSoftPlugin{}
	assert.Equal(t, PeopleSoft, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(8000))
	assert.False(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(80))
}

func TestPeopleSoftTLSPlugin_Run_PositiveViaTitleOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Oracle PeopleSoft Sign-in</title></head></html>`)
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

	plugin := &PeopleSoftTLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var psService plugins.ServicePeopleSoft
	err = json.Unmarshal(service.Raw, &psService)
	require.NoError(t, err)
	require.Len(t, psService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:peoplesoft_enterprise:*:*:*:*:*:*:*:*", psService.CPEs[0])
}

func TestPeopleSoftTLSPlugin_Metadata(t *testing.T) {
	plugin := &PeopleSoftTLSPlugin{}
	assert.Equal(t, PeopleSoft, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(8000))
}

func TestPeopleSoftSecurityFindings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Oracle PeopleSoft Sign-in</title></head></html>`)
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

		plugin := &PeopleSoftPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "oracle-peoplesoft-login-exposed", service.SecurityFindings[0].ID)
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

		plugin := &PeopleSoftPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}

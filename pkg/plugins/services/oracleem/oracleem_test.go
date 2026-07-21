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

package oracleem

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

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "simple title",
			body:     `<html><head><title>Database Express</title></head></html>`,
			expected: "Database Express",
		},
		{
			name:     "no title element",
			body:     `<html><body>hi</body></html>`,
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractTitle(tt.body))
		})
	}
}

func TestContainsAny(t *testing.T) {
	assert.True(t, containsAny("Oracle ENTERPRISE MANAGER Cloud Control", []string{"Oracle Enterprise Manager"}))
	assert.False(t, containsAny("generic page", []string{"Database Express"}))
}

func TestLocationPath(t *testing.T) {
	tests := []struct {
		name     string
		location string
		expected string
	}{
		{
			name:     "simple path",
			location: "/em/faces/logon/logon.jspx",
			expected: "/em/faces/logon/logon.jspx",
		},
		{
			name:     "path with query string reflecting logon path",
			location: "/foo?next=/em/faces/logon",
			expected: "/foo",
		},
		{
			name:     "no location header",
			location: "",
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}
			if tt.location != "" {
				header.Set("Location", tt.location)
			}
			resp := &http.Response{Header: header}
			assert.Equal(t, tt.expected, locationPath(resp))
		})
	}
}

func TestExtractAgentVersion(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "agentVersion marker",
			body:     `<EMResponse agentVersion="13.5.0.0.0"></EMResponse>`,
			expected: "13.5.0.0.0",
		},
		{
			name:     "emdVersion marker",
			body:     `emdVersion: v12.1.0.5.0`,
			expected: "12.1.0.5.0",
		},
		{
			name:     "no version marker",
			body:     `<EMResponse><AgentState>up</AgentState></EMResponse>`,
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractAgentVersion(tt.body))
		})
	}
}

func TestDetectAgent(t *testing.T) {
	tests := []struct {
		name              string
		handler           http.HandlerFunc
		expectedVersion   string
		expectedAnonymous bool
		expectedDetect    bool
	}{
		{
			name: "2xx with agent marker and version",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<EMResponse agentVersion="13.5.0.0.0"><AgentState>up</AgentState></EMResponse>`)
			},
			expectedVersion:   "13.5.0.0.0",
			expectedAnonymous: true,
			expectedDetect:    true,
		},
		{
			name: "non-2xx with agent marker: detected but not anonymous",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(500)
				fmt.Fprint(w, `<EMResponse><AgentState>error</AgentState></EMResponse>`)
			},
			expectedVersion:   "",
			expectedAnonymous: false,
			expectedDetect:    true,
		},
		{
			name: "no agent marker",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<html>not em</html>`)
			},
			expectedVersion:   "",
			expectedAnonymous: false,
			expectedDetect:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			version, anonymous, detected := detectAgent(server.Client(), server.URL, "")
			assert.Equal(t, tt.expectedDetect, detected)
			assert.Equal(t, tt.expectedAnonymous, anonymous)
			assert.Equal(t, tt.expectedVersion, version)
		})
	}
}

func TestDetectConsoleOrExpress(t *testing.T) {
	tests := []struct {
		name              string
		handler           http.HandlerFunc
		expectedComponent string
		expectedDetect    bool
	}{
		{
			name: "Database Express title",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<html><head><title>Database Express</title></head></html>`)
			},
			expectedComponent: "express",
			expectedDetect:    true,
		},
		{
			name: "logon redirect Location path",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/em/faces/logon/logon.jspx")
				w.WriteHeader(302)
			},
			expectedComponent: "console",
			expectedDetect:    true,
		},
		{
			name: "login path reflected only in query string, not real path -> NOT console",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/foo?next=/em/faces/logon")
				w.WriteHeader(302)
				fmt.Fprint(w, `<html><head><title>Generic Redirect</title></head></html>`)
			},
			expectedComponent: "",
			expectedDetect:    false,
		},
		{
			name: "no markers at all",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<html><body>hi</body></html>`)
			},
			expectedComponent: "",
			expectedDetect:    false,
		},
		{
			name: "bare 'Oracle Enterprise Manager' text with no logon redirect or agent XML -> NOT detected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<html><head><title>Welcome</title></head><body>Powered by Oracle Enterprise Manager</body></html>`)
			},
			expectedComponent: "",
			expectedDetect:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			// Mirror production's createHTTPClient: don't follow redirects, so
			// the 3xx Location header stays observable on the response.
			client := server.Client()
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}

			component, detected := detectConsoleOrExpress(client, server.URL, "")
			assert.Equal(t, tt.expectedDetect, detected)
			assert.Equal(t, tt.expectedComponent, component)
		})
	}
}

func TestBuildEMCPE(t *testing.T) {
	assert.Equal(t, "cpe:2.3:a:oracle:enterprise_manager_base_platform:13.5.0.0.0:*:*:*:*:*:*:*", buildEMCPE("13.5.0.0.0"))
	assert.Equal(t, "cpe:2.3:a:oracle:enterprise_manager_base_platform:*:*:*:*:*:*:*:*", buildEMCPE(""))
}

func TestPlugin_Run_AgentDetection_Misconfigs(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<EMResponse agentVersion="13.5.0.0.0"><AgentState>up</AgentState></EMResponse>`)
	})

	t.Run("Misconfigs=true and 2xx yields AnonymousAccess and finding", func(t *testing.T) {
		server := httptest.NewServer(handler)
		defer server.Close()

		conn, target := dialTestServer(t, server.URL)
		defer conn.Close()
		target.Misconfigs = true

		plugin := &Plugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "oracle-em-agent-unauthenticated", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityMedium, service.SecurityFindings[0].Severity)

		var payload plugins.ServiceOracleEM
		require.NoError(t, json.Unmarshal(service.Raw, &payload))
		assert.Equal(t, "agent", payload.Component)
		require.Len(t, payload.CPEs, 1)
		assert.Equal(t, "cpe:2.3:a:oracle:enterprise_manager_base_platform:13.5.0.0.0:*:*:*:*:*:*:*", payload.CPEs[0])
	})

	t.Run("Misconfigs=false yields no AnonymousAccess or findings", func(t *testing.T) {
		server := httptest.NewServer(handler)
		defer server.Close()

		conn, target := dialTestServer(t, server.URL)
		defer conn.Close()
		target.Misconfigs = false

		plugin := &Plugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}

func TestPlugin_Run_AgentDetection_NonAnonymous(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, `<EMResponse><AgentState>error</AgentState></EMResponse>`)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()
	target.Misconfigs = true

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	assert.False(t, service.AnonymousAccess)
	assert.Empty(t, service.SecurityFindings)
}

func TestPlugin_Run_ConsoleDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/em/faces/logon/logon.jspx")
		w.WriteHeader(302)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()
	target.Misconfigs = true

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	assert.False(t, service.AnonymousAccess)
	assert.Empty(t, service.SecurityFindings)

	var payload plugins.ServiceOracleEM
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "console", payload.Component)
}

func TestPlugin_Run_ExpressDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><title>Database Express</title></head></html>`)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	var payload plugins.ServiceOracleEM
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "express", payload.Component)
}

func TestPlugin_Run_NotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>generic server</body></html>`)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestPlugin_Run_GenericMarkerTextNotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><title>Welcome</title></head><body>Powered by Oracle Enterprise Manager</body></html>`)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestTLSPlugin_Run_AgentDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<EMResponse agentVersion="13.5.0.0.0"><AgentState>up</AgentState></EMResponse>`)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()
	target.Misconfigs = true

	plugin := &TLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	assert.True(t, service.AnonymousAccess)
	require.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "oracle-em-agent-unauthenticated", service.SecurityFindings[0].ID)
}

func TestTLSPlugin_Run_NotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>generic server</body></html>`)
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
		{3872, true},
		// 7803 (Cloud Control console) and 5500 (EM Express) are HTTPS and now
		// belong exclusively to the TLS variant.
		{7803, false},
		{5500, false},
		{443, false},
		{80, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, plugin.PortPriority(tt.port))
	}
}

func TestTLSPlugin_PortPriority(t *testing.T) {
	plugin := &TLSPlugin{}
	tests := []struct {
		port     uint16
		expected bool
	}{
		{7803, true},
		{5500, true},
		{443, true},
		{3872, false},
		{8080, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, plugin.PortPriority(tt.port))
	}
}

func TestPlugin_Metadata(t *testing.T) {
	plugin := &Plugin{}
	assert.Equal(t, EM, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
}

func TestTLSPlugin_Metadata(t *testing.T) {
	plugin := &TLSPlugin{}
	assert.Equal(t, EM, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
}

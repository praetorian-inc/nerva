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

package oraclesoa

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
	assert.Equal(t, "Service Bus Console", extractTitle(`<html><head><title>Service Bus Console</title></head></html>`))
	assert.Equal(t, "", extractTitle(`<html><body>hi</body></html>`))
}

func TestContainsAny(t *testing.T) {
	assert.True(t, containsAny("Welcome to the ORACLE SOA platform", []string{"Welcome to the Oracle SOA"}))
	assert.False(t, containsAny("generic page", []string{"Oracle Service Bus"}))
}

func TestDetectSOAInfra(t *testing.T) {
	tests := []struct {
		name              string
		handler           http.HandlerFunc
		expectedAnonymous bool
		expectedDetect    bool
	}{
		{
			name: "2xx with soa-infra marker",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "Welcome to the Oracle SOA Platform")
			},
			expectedAnonymous: true,
			expectedDetect:    true,
		},
		{
			name: "non-2xx with marker: detected but not anonymous",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(403)
				fmt.Fprint(w, "soa-infra forbidden")
			},
			expectedAnonymous: false,
			expectedDetect:    true,
		},
		{
			name: "no marker",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "generic response")
			},
			expectedAnonymous: false,
			expectedDetect:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			anonymous, detected := detectSOAInfra(server.Client(), server.URL, "")
			assert.Equal(t, tt.expectedDetect, detected)
			assert.Equal(t, tt.expectedAnonymous, anonymous)
		})
	}
}

func TestDetectSOA(t *testing.T) {
	tests := []struct {
		name            string
		handler         http.HandlerFunc
		expectedProduct string
		expectedDetect  bool
	}{
		{
			name: "soa via /soa-infra",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/soa-infra":
					fmt.Fprint(w, "Welcome to the Oracle SOA Platform")
				default:
					w.WriteHeader(404)
				}
			},
			expectedProduct: "soa",
			expectedDetect:  true,
		},
		{
			name: "osb via /sbconsole",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/sbconsole":
					fmt.Fprint(w, "Oracle Service Bus Console")
				default:
					w.WriteHeader(404)
				}
			},
			expectedProduct: "osb",
			expectedDetect:  true,
		},
		{
			name: "soa via /soa/composer",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/soa/composer":
					fmt.Fprint(w, "Oracle SOA Composer")
				default:
					w.WriteHeader(404)
				}
			},
			expectedProduct: "soa",
			expectedDetect:  true,
		},
		{
			name: "soa via /bpm/workspace",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/bpm/workspace":
					fmt.Fprint(w, "Business Process Workspace")
				default:
					w.WriteHeader(404)
				}
			},
			expectedProduct: "soa",
			expectedDetect:  true,
		},
		{
			name: "bare WebLogic auth cookie with no product marker -> NOT detected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.SetCookie(w, &http.Cookie{Name: "_WL_AUTHCOOKIE_JSESSIONID", Value: "abc123"})
				fmt.Fprint(w, "generic weblogic response")
			},
			expectedProduct: "",
			expectedDetect:  false,
		},
		{
			name: "no match at all",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
			},
			expectedProduct: "",
			expectedDetect:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			product, _, detected := detectSOA(server.Client(), server.URL, "")
			assert.Equal(t, tt.expectedDetect, detected)
			assert.Equal(t, tt.expectedProduct, product)
		})
	}
}

func TestBuildSOACPE(t *testing.T) {
	assert.Equal(t, "cpe:2.3:a:oracle:soa_suite:*:*:*:*:*:*:*:*", buildSOACPE("soa"))
	assert.Equal(t, "cpe:2.3:a:oracle:service_bus:*:*:*:*:*:*:*:*", buildSOACPE("osb"))
}

func TestPlugin_Run_SOAInfraDetection_Misconfigs(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/soa-infra":
			fmt.Fprint(w, "Welcome to the Oracle SOA Platform")
		default:
			w.WriteHeader(404)
		}
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
		assert.Equal(t, "oracle-soa-infra-unauthenticated", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityMedium, service.SecurityFindings[0].Severity)

		var payload plugins.ServiceOracleSOA
		require.NoError(t, json.Unmarshal(service.Raw, &payload))
		assert.Equal(t, "soa", payload.Product)
		require.Len(t, payload.CPEs, 1)
		assert.Equal(t, "cpe:2.3:a:oracle:soa_suite:*:*:*:*:*:*:*:*", payload.CPEs[0])
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

func TestPlugin_Run_OSBDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sbconsole":
			fmt.Fprint(w, "Oracle Service Bus Console")
		default:
			w.WriteHeader(404)
		}
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

	var payload plugins.ServiceOracleSOA
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "osb", payload.Product)
	assert.Equal(t, "cpe:2.3:a:oracle:service_bus:*:*:*:*:*:*:*:*", payload.CPEs[0])
}

func TestPlugin_Run_WeblogicCookieOnly_NotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "_WL_AUTHCOOKIE_JSESSIONID", Value: "abc123"})
		fmt.Fprint(w, "generic weblogic response")
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
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
		case "/soa-infra":
			fmt.Fprint(w, "Welcome to the Oracle SOA Platform")
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

	var payload plugins.ServiceOracleSOA
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "soa", payload.Product)
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
		{8001, true},
		{7001, true},
		{443, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, plugin.PortPriority(tt.port))
	}
}

func TestTLSPlugin_PortPriority(t *testing.T) {
	plugin := &TLSPlugin{}
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(8001))
}

func TestPlugin_Metadata(t *testing.T) {
	plugin := &Plugin{}
	assert.Equal(t, SOA, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
}

func TestTLSPlugin_Metadata(t *testing.T) {
	plugin := &TLSPlugin{}
	assert.Equal(t, SOA, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
}

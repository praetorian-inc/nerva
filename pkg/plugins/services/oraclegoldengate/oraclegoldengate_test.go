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

package oraclegoldengate

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

// startRawTCPServer starts a raw (non-HTTP) TCP listener that writes banner to
// every accepted connection, and returns a net.Conn dialed to it plus the
// corresponding Target. Used for the ClassicPlugin, which performs a passive
// read rather than issuing HTTP requests.
func startRawTCPServer(t *testing.T, banner []byte) (net.Conn, plugins.Target) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if len(banner) > 0 {
			_, _ = conn.Write(banner)
		}
		// Keep the connection open briefly so the client's read has data
		// available before the deadline; then let it close naturally.
		time.Sleep(100 * time.Millisecond)
	}()

	addrPort := listener.Addr().(*net.TCPAddr)
	target := plugins.Target{
		Host:    addrPort.IP.String(),
		Address: netip.MustParseAddrPort(addrPort.String()),
	}

	conn, err := net.DialTimeout("tcp", addrPort.String(), 5*time.Second)
	require.NoError(t, err)
	return conn, target
}

func TestContainsAny(t *testing.T) {
	assert.True(t, containsAny("Welcome to Oracle GoldenGate Studio", []string{"Oracle GoldenGate"}))
	assert.False(t, containsAny("generic response", []string{"Oracle GoldenGate", "GoldenGate"}))
}

func TestBodyOf(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello world")
	}))
	defer server.Close()

	body, ok := bodyOf(server.Client(), server.URL, "/anything", "")
	require.True(t, ok)
	assert.Equal(t, "hello world", body)
}

func TestExtractVersion(t *testing.T) {
	tests := []struct {
		name     string
		handler  http.HandlerFunc
		expected string
	}{
		{
			name: "version present in health JSON",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `{"version":"21.3.0.0.0","status":"up"}`)
			},
			expected: "21.3.0.0.0",
		},
		{
			name: "no version present",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `{"status":"up"}`)
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			assert.Equal(t, tt.expected, extractVersion(server.Client(), server.URL, ""))
		})
	}
}

func TestDetectMicroservices(t *testing.T) {
	tests := []struct {
		name            string
		handler         http.HandlerFunc
		expectedVersion string
		expectedDetect  bool
	}{
		{
			name: "REST deployments endpoint with marker and version enrichment",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/services/v2/deployments":
					fmt.Fprint(w, `{"name":"Oracle GoldenGate Deployment"}`)
				case "/services/":
					fmt.Fprint(w, `{"version":"21.3.0.0.0"}`)
				default:
					w.WriteHeader(404)
				}
			},
			expectedVersion: "21.3.0.0.0",
			expectedDetect:  true,
		},
		{
			name: "falls back to SPA login UI on /",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/":
					fmt.Fprint(w, `<html><body>Oracle GoldenGate Login</body></html>`)
				default:
					w.WriteHeader(404)
				}
			},
			expectedVersion: "",
			expectedDetect:  true,
		},
		{
			name: "no marker anywhere",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
			},
			expectedVersion: "",
			expectedDetect:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			version, detected := detectMicroservices(server.Client(), server.URL, "")
			assert.Equal(t, tt.expectedDetect, detected)
			assert.Equal(t, tt.expectedVersion, version)
		})
	}
}

func TestBuildGoldenGateCPE(t *testing.T) {
	assert.Equal(t, "cpe:2.3:a:oracle:goldengate:21.3.0.0.0:*:*:*:*:*:*:*", buildGoldenGateCPE("21.3.0.0.0"))
	assert.Equal(t, "cpe:2.3:a:oracle:goldengate:*:*:*:*:*:*:*:*", buildGoldenGateCPE(""))
}

func TestPlugin_Run_MicroservicesDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/services/v2/deployments":
			fmt.Fprint(w, `{"name":"Oracle GoldenGate Deployment"}`)
		case "/services/":
			fmt.Fprint(w, `{"version":"21.3.0.0.0"}`)
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

	var payload plugins.ServiceOracleGoldenGate
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "microservices", payload.Edition)
	require.Len(t, payload.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:goldengate:21.3.0.0.0:*:*:*:*:*:*:*", payload.CPEs[0])
	assert.Equal(t, "21.3.0.0.0", service.Version)
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
		case "/":
			fmt.Fprint(w, `<html><body>Oracle GoldenGate Login</body></html>`)
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

	var payload plugins.ServiceOracleGoldenGate
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "microservices", payload.Edition)
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

func TestClassicPlugin_Run_PositiveDetection(t *testing.T) {
	conn, target := startRawTCPServer(t, []byte("Oracle GoldenGate Manager\n"))
	defer conn.Close()

	plugin := &ClassicPlugin{}
	service, err := plugin.Run(conn, 2*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	var payload plugins.ServiceOracleGoldenGate
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "classic", payload.Edition)
	require.Len(t, payload.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:goldengate:*:*:*:*:*:*:*:*", payload.CPEs[0])
}

func TestClassicPlugin_Run_NonGoldenGateBanner_NotDetected(t *testing.T) {
	conn, target := startRawTCPServer(t, []byte("SSH-2.0-OpenSSH_8.4\n"))
	defer conn.Close()

	plugin := &ClassicPlugin{}
	service, err := plugin.Run(conn, 2*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestClassicPlugin_Run_NoBanner_NotDetected(t *testing.T) {
	conn, target := startRawTCPServer(t, nil)
	defer conn.Close()

	plugin := &ClassicPlugin{}
	service, err := plugin.Run(conn, 500*time.Millisecond, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestPlugin_PortPriority(t *testing.T) {
	plugin := &Plugin{}
	assert.True(t, plugin.PortPriority(9011))
	assert.True(t, plugin.PortPriority(9100))
	assert.False(t, plugin.PortPriority(443))
}

func TestTLSPlugin_PortPriority(t *testing.T) {
	plugin := &TLSPlugin{}
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(9011))
}

func TestClassicPlugin_PortPriority(t *testing.T) {
	plugin := &ClassicPlugin{}
	assert.True(t, plugin.PortPriority(7809))
	assert.False(t, plugin.PortPriority(9011))
}

func TestPlugin_Metadata(t *testing.T) {
	plugin := &Plugin{}
	assert.Equal(t, GOLDENGATE, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
}

func TestTLSPlugin_Metadata(t *testing.T) {
	plugin := &TLSPlugin{}
	assert.Equal(t, GOLDENGATE, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
}

func TestClassicPlugin_Metadata(t *testing.T) {
	plugin := &ClassicPlugin{}
	assert.Equal(t, GOLDENGATE_MANAGER, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
}

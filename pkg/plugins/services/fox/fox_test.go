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

package fox

import (
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	readData  []byte
	readPos   int
	writeData []byte
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readPos >= len(m.readData) {
		return 0, nil
	}
	n = copy(b, m.readData[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// TestFoxPlugin_ValidResponse tests successful Fox protocol detection with metadata extraction
func TestFoxPlugin_ValidResponse(t *testing.T) {
	// Valid Fox hello response with metadata
	response := "fox a 0 -1 fox hello\n" +
		"{\n" +
		"fox.version=s:1.0\n" +
		"hostName=s:JACE-001\n" +
		"hostAddress=s:192.168.1.100\n" +
		"app.name=s:Station\n" +
		"app.version=s:4.10.0.123\n" +
		"vm.name=s:Java HotSpot\n" +
		"vm.version=s:1.8.0_181\n" +
		"os.name=s:QNX\n" +
		"station.name=s:MyBuilding\n" +
		"brandId=s:vykon\n" +
		"}\n"

	conn := &mockConn{readData: []byte(response)}
	plugin := &FOXPlugin{}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.100:1911"),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	// Unmarshal service metadata
	var metadata plugins.ServiceFox
	err = json.Unmarshal(service.Raw, &metadata)
	require.NoError(t, err)

	// Verify extracted metadata
	assert.Equal(t, "1.0", metadata.Version)
	assert.Equal(t, "JACE-001", metadata.HostName)
	assert.Equal(t, "192.168.1.100", metadata.HostAddress)
	assert.Equal(t, "Station", metadata.AppName)
	assert.Equal(t, "4.10.0.123", metadata.AppVersion)
	assert.Equal(t, "Java HotSpot", metadata.VMName)
	assert.Equal(t, "1.8.0_181", metadata.VMVersion)
	assert.Equal(t, "QNX", metadata.OSName)
	assert.Equal(t, "MyBuilding", metadata.StationName)
	assert.Equal(t, "vykon", metadata.BrandId)

	// Verify CPE generation
	require.Len(t, metadata.CPEs, 1, "Should generate exactly one CPE")
	assert.Equal(t, "cpe:2.3:a:vykon:station:4_10_0_123:*:*:*:*:*:*:*", metadata.CPEs[0])
}

// TestFoxPlugin_InvalidResponse tests rejection of non-Fox protocol responses
func TestFoxPlugin_InvalidResponse(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{
			name:     "HTTP response",
			response: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
		},
		{
			name:     "SSH banner",
			response: "SSH-2.0-OpenSSH_7.4\r\n",
		},
		{
			name:     "Wrong Fox response code",
			response: "fox a 1 -1 fox hello\n{\nfox.version=s:1.0\n}\n", // Should be 0, not 1
		},
		{
			name:     "Random data",
			response: "random garbage data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{readData: []byte(tt.response)}
			plugin := &FOXPlugin{}

			target := plugins.Target{
				Address: netip.MustParseAddrPort("192.168.1.100:1911"),
			}

			service, err := plugin.Run(conn, 5*time.Second, target)

			require.NoError(t, err)
			assert.Nil(t, service, "Non-Fox response should return nil service")
		})
	}
}

// TestFoxPlugin_TruncatedResponse tests handling of incomplete Fox responses
func TestFoxPlugin_TruncatedResponse(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{
			name:     "Missing header",
			response: "fox",
		},
		{
			name:     "Incomplete header",
			response: "fox a 0",
		},
		{
			name:     "Missing body",
			response: "fox a 0 -1 fox hello\n",
		},
		{
			name:     "Incomplete key-value",
			response: "fox a 0 -1 fox hello\n{\nfox.version=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{readData: []byte(tt.response)}
			plugin := &FOXPlugin{}

			target := plugins.Target{
				Address: netip.MustParseAddrPort("192.168.1.100:1911"),
			}

			service, err := plugin.Run(conn, 5*time.Second, target)

			// Should either error or return nil service, not crash
			if err == nil {
				assert.Nil(t, service)
			}
		})
	}
}

// TestFoxPlugin_MinimalResponse tests Fox detection with minimal valid response
func TestFoxPlugin_MinimalResponse(t *testing.T) {
	// Minimal valid Fox response (just the hello ack, no metadata)
	response := "fox a 0 -1 fox hello\n{\n}\n"

	conn := &mockConn{readData: []byte(response)}
	plugin := &FOXPlugin{}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.100:1911"),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service, "Minimal valid Fox response should be detected")

	// Unmarshal and verify empty/default metadata
	var metadata plugins.ServiceFox
	err = json.Unmarshal(service.Raw, &metadata)
	require.NoError(t, err)
}

// TestFoxPlugin_PortPriority tests port priority detection
func TestFoxPlugin_PortPriority(t *testing.T) {
	plugin := &FOXPlugin{}

	assert.True(t, plugin.PortPriority(1911), "Should prioritize default Fox port 1911")
	assert.False(t, plugin.PortPriority(80), "Should not prioritize non-Fox ports")
	assert.False(t, plugin.PortPriority(443), "Should not prioritize non-Fox ports")
}

// TestFoxPlugin_Metadata tests plugin metadata methods
func TestFoxPlugin_Metadata(t *testing.T) {
	plugin := &FOXPlugin{}

	assert.Equal(t, "fox", plugin.Name(), "Plugin name should be 'fox'")
	assert.Equal(t, plugins.TCP, plugin.Type(), "Fox should be TCP protocol")
	assert.Equal(t, 400, plugin.Priority(), "Fox should have ICS protocol priority (400)")
}

// TestFoxPlugin_RequestFormat tests that correct Fox hello request is sent
func TestFoxPlugin_RequestFormat(t *testing.T) {
	response := "fox a 0 -1 fox hello\n{\n}\n"
	conn := &mockConn{readData: []byte(response)}
	plugin := &FOXPlugin{}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.100:1911"),
	}

	_, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)

	// Verify the correct request was sent (zgrab2-compatible with full system info)
	expectedRequest := "fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\nhostName=s:scanner\nhostAddress=s:192.168.1.1\napp.name=s:Workbench\napp.version=s:3.8.0\nvm.name=s:Java HotSpot(TM) Server VM\nvm.version=s:11.0\nos.name=s:Linux\nos.version=s:5.4\nlang=s:en\nhostId=s:scanner-001\nvmUuid=s:00000000-0000-0000-0000-000000000000\nbrandId=s:vykon\n};;\n"
	assert.Equal(t, expectedRequest, string(conn.writeData), "Should send correct Fox hello request")
}

// TestFoxPlugin_EmptyResponse tests handling of empty/no response
func TestFoxPlugin_EmptyResponse(t *testing.T) {
	conn := &mockConn{readData: []byte{}}
	plugin := &FOXPlugin{}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.100:1911"),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service, "Empty response should return nil service")
}

// TestFoxPlugin_CPEGeneration tests CPE generation from BrandId, AppName, and AppVersion
func TestFoxPlugin_CPEGeneration(t *testing.T) {
	tests := []struct {
		name        string
		brandId     string
		appName     string
		appVersion  string
		expectedCPE string
	}{
		{
			name:        "Tridium Niagara",
			brandId:     "tridium",
			appName:     "Niagara",
			appVersion:  "4.10.0.123",
			expectedCPE: "cpe:2.3:a:tridium:niagara:4_10_0_123:*:*:*:*:*:*:*",
		},
		{
			name:        "Honeywell WEBS",
			brandId:     "honeywell",
			appName:     "WEBS",
			appVersion:  "4.8.0",
			expectedCPE: "cpe:2.3:a:honeywell:webs:4_8_0:*:*:*:*:*:*:*",
		},
		{
			name:        "Vykon Station",
			brandId:     "vykon",
			appName:     "Station",
			appVersion:  "3.8.45",
			expectedCPE: "cpe:2.3:a:vykon:station:3_8_45:*:*:*:*:*:*:*",
		},
		{
			name:        "Missing AppVersion",
			brandId:     "tridium",
			appName:     "Niagara",
			appVersion:  "",
			expectedCPE: "cpe:2.3:a:tridium:niagara:*:*:*:*:*:*:*:*",
		},
		{
			name:        "Missing AppName",
			brandId:     "tridium",
			appName:     "",
			appVersion:  "4.10.0.123",
			expectedCPE: "cpe:2.3:a:tridium:*:4_10_0_123:*:*:*:*:*:*:*",
		},
		{
			name:        "Unknown BrandId",
			brandId:     "unknown-vendor",
			appName:     "Station",
			appVersion:  "1.0",
			expectedCPE: "", // No CPE for unknown vendor
		},
		{
			name:        "Empty BrandId",
			brandId:     "",
			appName:     "Station",
			appVersion:  "1.0",
			expectedCPE: "", // No CPE without vendor
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build Fox response with test data
			response := "fox a 0 -1 fox hello\n{\n"
			if tt.brandId != "" {
				response += "brandId=s:" + tt.brandId + "\n"
			}
			if tt.appName != "" {
				response += "app.name=s:" + tt.appName + "\n"
			}
			if tt.appVersion != "" {
				response += "app.version=s:" + tt.appVersion + "\n"
			}
			response += "}\n"

			conn := &mockConn{readData: []byte(response)}
			plugin := &FOXPlugin{}

			target := plugins.Target{
				Address: netip.MustParseAddrPort("192.168.1.100:1911"),
			}

			service, err := plugin.Run(conn, 5*time.Second, target)
			require.NoError(t, err)

			if tt.expectedCPE == "" {
				// Unknown/empty vendor should still return service, but with no CPEs
				require.NotNil(t, service)
				var metadata plugins.ServiceFox
				err = json.Unmarshal(service.Raw, &metadata)
				require.NoError(t, err)
				assert.Empty(t, metadata.CPEs, "Unknown vendor should have empty CPEs")
			} else {
				require.NotNil(t, service)

				// Unmarshal and verify CPE
				var metadata plugins.ServiceFox
				err = json.Unmarshal(service.Raw, &metadata)
				require.NoError(t, err)

				require.Len(t, metadata.CPEs, 1, "Should generate exactly one CPE")
				assert.Equal(t, tt.expectedCPE, metadata.CPEs[0])
			}
		})
	}
}

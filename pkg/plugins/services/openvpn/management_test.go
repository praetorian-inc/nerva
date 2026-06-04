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

package openvpn

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
)

// mockConn implements net.Conn for testing. It returns readData on Read calls.
type mockConn struct {
	readData  []byte
	readIndex int
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readIndex >= len(m.readData) {
		return 0, nil
	}
	n = copy(b, m.readData[m.readIndex:])
	m.readIndex += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

const validMgmtBanner = ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more information\r\n"

func TestManagementPlugin_Run_ValidBanner(t *testing.T) {
	conn := &mockConn{readData: []byte(validMgmtBanner)}

	plugin := &ManagementPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:7505"),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)

	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "openvpn-management", service.Protocol)

	metadata := service.Metadata()
	meta, ok := metadata.(plugins.ServiceOpenVPNManagement)
	assert.True(t, ok, "metadata should be ServiceOpenVPNManagement")
	assert.Equal(t, "5", meta.Version)
	assert.True(t, strings.Contains(meta.Banner, ">INFO:OpenVPN"), "Banner should contain >INFO:OpenVPN")
	assert.Equal(t, []string{"cpe:2.3:a:openvpn:openvpn:*:*:*:*:*:*:*:*"}, meta.CPEs)
}

func TestManagementPlugin_Run_SecurityFinding_MisconfigsTrue(t *testing.T) {
	conn := &mockConn{readData: []byte(validMgmtBanner)}

	plugin := &ManagementPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("192.168.1.1:7505"),
		Misconfigs: true,
	}

	service, err := plugin.Run(conn, 5*time.Second, target)

	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "openvpn-management-exposed", service.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityHigh, service.SecurityFindings[0].Severity)
	assert.True(t, strings.Contains(service.SecurityFindings[0].Evidence, ">INFO:OpenVPN"),
		"Evidence should contain the banner text")
}

func TestManagementPlugin_Run_SecurityFinding_MisconfigsFalse(t *testing.T) {
	conn := &mockConn{readData: []byte(validMgmtBanner)}

	plugin := &ManagementPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("192.168.1.1:7505"),
		Misconfigs: false,
	}

	service, err := plugin.Run(conn, 5*time.Second, target)

	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Empty(t, service.SecurityFindings)
}

func TestManagementPlugin_Run_NonManagementBanner(t *testing.T) {
	conn := &mockConn{readData: []byte("SSH-2.0-OpenSSH_8.9\r\n")}

	plugin := &ManagementPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:7505"),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)

	assert.NoError(t, err)
	assert.Nil(t, service)
}

func TestManagementPlugin_Run_EmptyResponse(t *testing.T) {
	conn := &mockConn{readData: []byte{}}

	plugin := &ManagementPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:7505"),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)

	assert.NoError(t, err)
	assert.Nil(t, service)
}

func TestManagementPlugin_Metadata(t *testing.T) {
	p := &ManagementPlugin{}
	assert.Equal(t, "openvpn-management", p.Name())
	assert.Equal(t, plugins.TCP, p.Type())
	assert.Equal(t, 100, p.Priority())
	assert.True(t, p.PortPriority(7505))
	assert.True(t, p.PortPriority(1195))
	assert.False(t, p.PortPriority(1194))
}

func TestBuildOpenVPNCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:openvpn:openvpn:*:*:*:*:*:*:*:*",
		},
		{
			name:    "known version",
			version: "5",
			want:    "cpe:2.3:a:openvpn:openvpn:5:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildOpenVPNCPE(tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestManagementPlugin_Run_MaxLengthBanner(t *testing.T) {
	// Banner that starts with valid prefix but is padded to 4096 bytes.
	prefix := ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more information\r\n"
	padding := strings.Repeat("x", 4096-len(prefix))
	banner := prefix + padding

	conn := &mockConn{readData: []byte(banner)}
	plugin := &ManagementPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:7505"),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)

	assert.NoError(t, err)
	assert.NotNil(t, service)

	metadata := service.Metadata()
	meta, ok := metadata.(plugins.ServiceOpenVPNManagement)
	assert.True(t, ok)
	assert.Equal(t, "5", meta.Version)
}

func TestManagementPlugin_Run_BannerWithControlChars(t *testing.T) {
	// Banner with embedded null bytes and control characters.
	banner := ">INFO:OpenVPN Management Interface Version 5\x00\x01\x1B -- type 'help'\r\n"

	conn := &mockConn{readData: []byte(banner)}
	plugin := &ManagementPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:7505"),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)

	assert.NoError(t, err)
	assert.NotNil(t, service, "should detect even with control chars")

	metadata := service.Metadata()
	meta, ok := metadata.(plugins.ServiceOpenVPNManagement)
	assert.True(t, ok)
	// Sanitized banner must not contain control characters
	for i := 0; i < len(meta.Banner); i++ {
		b := meta.Banner[i]
		assert.True(t, b >= 0x20 && b < 0x7F, "banner byte 0x%02x is not printable ASCII", b)
	}
}

func TestManagementPlugin_Run_ValidPrefixNoVersion(t *testing.T) {
	// Banner with valid prefix but no version number.
	banner := ">INFO:OpenVPN Management Interface\r\n"

	conn := &mockConn{readData: []byte(banner)}
	plugin := &ManagementPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:7505"),
	}

	service, err := plugin.Run(conn, 5*time.Second, target)

	assert.NoError(t, err)
	assert.NotNil(t, service, "should detect even without version number")

	metadata := service.Metadata()
	meta, ok := metadata.(plugins.ServiceOpenVPNManagement)
	assert.True(t, ok)
	assert.Equal(t, "", meta.Version, "version should be empty when not present in banner")
	assert.Equal(t, "cpe:2.3:a:openvpn:openvpn:*:*:*:*:*:*:*:*", meta.CPEs[0], "CPE should use wildcard")
}

func TestSanitizePrintable(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "normal ASCII unchanged",
			input: "hello world",
			want:  "hello world",
		},
		{
			name:  "embedded null bytes stripped",
			input: "hello\x00world",
			want:  "helloworld",
		},
		{
			name:  "control chars stripped",
			input: "hello\x01\x1Bworld",
			want:  "helloworld",
		},
		{
			name:  "printable range 0x20-0x7E preserved",
			input: " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
			want:  " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
		},
		{
			name:  "DEL (0x7F) stripped",
			input: "hello\x7Fworld",
			want:  "helloworld",
		},
		{
			name:  "empty string unchanged",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizePrintable(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMgmtBannerRegex(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantVersion string
		wantMatch   bool
	}{
		{
			name:        "version 5",
			input:       ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more information",
			wantVersion: "5",
			wantMatch:   true,
		},
		{
			name:        "version 3",
			input:       ">INFO:OpenVPN Management Interface Version 3 -- type 'help' for more information",
			wantVersion: "3",
			wantMatch:   true,
		},
		{
			name:      "no version number",
			input:     ">INFO:OpenVPN Management Interface",
			wantMatch: false,
		},
		{
			name:      "unrelated text",
			input:     "Some other text",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := mgmtBannerRegex.FindStringSubmatch(tt.input)
			if tt.wantMatch {
				assert.True(t, len(matches) >= 2, "expected regex to match")
				assert.Equal(t, tt.wantVersion, matches[1])
			} else {
				assert.True(t, len(matches) < 2, "expected regex not to match")
			}
		})
	}
}

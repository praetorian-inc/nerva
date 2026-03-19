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

package teamviewer

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
)

// mockConn implements net.Conn for testing
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

func TestCheckTeamViewer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid CMD_PINGOK response",
			data:    []byte{0x17, 0x24, 0x11, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "valid secondary magic",
			data:    []byte{0x11, 0x30, 0x11, 0x04, 0x00},
			wantErr: false,
		},
		{
			name:    "valid primary magic with different command",
			data:    []byte{0x17, 0x24, 0x16, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "minimum valid response (3 bytes)",
			data:    []byte{0x17, 0x24, 0x11},
			wantErr: false,
		},
		{
			name:    "invalid magic bytes",
			data:    []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "response too short (2 bytes)",
			data:    []byte{0x17, 0x24},
			wantErr: true,
		},
		{
			name:    "response too short (1 byte)",
			data:    []byte{0x17},
			wantErr: true,
		},
		{
			name:    "empty response",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "HTTP response (not TeamViewer)",
			data:    []byte("HTTP/1.1 200 OK"),
			wantErr: true,
		},
		{
			name:    "partial magic match (first byte only)",
			data:    []byte{0x17, 0x00, 0x11},
			wantErr: true,
		},
		{
			name:    "nil input",
			data:    nil,
			wantErr: true,
		},
		{
			name:    "large response starting with valid magic bytes",
			data:    append([]byte{0x17, 0x24, 0x11}, bytes.Repeat([]byte{0xAB}, 64*1024-3)...),
			wantErr: false,
		},
		{
			name:    "all 0xFF bytes",
			data:    []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			wantErr: true,
		},
		{
			name:    "magic bytes reversed",
			data:    []byte{0x24, 0x17, 0x11},
			wantErr: true,
		},
		{
			name:    "secondary magic with minimum bytes",
			data:    []byte{0x11, 0x30, 0x10},
			wantErr: false,
		},
		{
			name:    "binary data after valid magic",
			data:    []byte{0x17, 0x24, 0x10, 0xFF, 0xFF, 0xFF, 0xFF},
			wantErr: false,
		},
		{
			name:    "valid magic but unknown command byte",
			data:    []byte{0x17, 0x24, 0xFF, 0x04, 0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := checkTeamViewer(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCmdPingProbe(t *testing.T) {
	// Verify probe is exactly 9 bytes
	assert.Equal(t, 9, len(cmdPingProbe))
	// Verify magic bytes
	assert.Equal(t, byte(0x17), cmdPingProbe[0])
	assert.Equal(t, byte(0x24), cmdPingProbe[1])
	// Verify CMD_PING command
	assert.Equal(t, byte(0x10), cmdPingProbe[2])
}

func TestPluginMetadata(t *testing.T) {
	p := &TeamViewerPlugin{}
	assert.Equal(t, "TeamViewer", p.Name())
	assert.Equal(t, plugins.TCP, p.Type())
	assert.Equal(t, 100, p.Priority())
	assert.True(t, p.PortPriority(5938))
	assert.False(t, p.PortPriority(80))
	assert.False(t, p.PortPriority(443))
	assert.False(t, p.PortPriority(5900))
}

func TestTeamViewerPlugin_Run_ValidPrimaryMagic(t *testing.T) {
	// CMD_PINGOK response with primary magic
	conn := &mockConn{
		readData: []byte{0x17, 0x24, 0x11, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00},
	}

	plugin := &TeamViewerPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:5938"),
		Host:    "test-host",
	}

	service, err := plugin.Run(conn, time.Second*5, target)

	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "teamviewer", service.Protocol)
	assert.Equal(t, "192.168.1.1", service.IP)
	assert.Equal(t, 5938, service.Port)
	assert.Equal(t, "test-host", service.Host)

	// Verify metadata has CPEs
	metadata := service.Metadata()
	tvMeta, ok := metadata.(plugins.ServiceTeamViewer)
	assert.True(t, ok)
	assert.Contains(t, tvMeta.CPEs, "cpe:2.3:a:teamviewer:teamviewer:*:*:*:*:*:*:*:*")
}

func TestTeamViewerPlugin_Run_ValidSecondaryMagic(t *testing.T) {
	conn := &mockConn{
		readData: []byte{0x11, 0x30, 0x11, 0x04, 0x00},
	}

	plugin := &TeamViewerPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("10.0.0.1:5938"),
		Host:    "tv-server",
	}

	service, err := plugin.Run(conn, time.Second*5, target)

	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "teamviewer", service.Protocol)
}

func TestTeamViewerPlugin_Run_NonTeamViewerResponse(t *testing.T) {
	conn := &mockConn{
		readData: []byte("HTTP/1.1 200 OK\r\n"),
	}

	plugin := &TeamViewerPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.2:5938"),
		Host:    "test-host",
	}

	service, err := plugin.Run(conn, time.Second*5, target)

	assert.NoError(t, err) // non-match returns nil, nil (not an error)
	assert.Nil(t, service)
}

func TestTeamViewerPlugin_Run_EmptyResponse(t *testing.T) {
	conn := &mockConn{
		readData: []byte{},
	}

	plugin := &TeamViewerPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.3:5938"),
		Host:    "test-host",
	}

	service, err := plugin.Run(conn, time.Second*5, target)

	assert.NoError(t, err)
	assert.Nil(t, service)
}

func TestTeamViewerPlugin_Run_TooShortResponse(t *testing.T) {
	conn := &mockConn{
		readData: []byte{0x17, 0x24}, // only 2 bytes, need 3
	}

	plugin := &TeamViewerPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.4:5938"),
		Host:    "test-host",
	}

	service, err := plugin.Run(conn, time.Second*5, target)

	assert.NoError(t, err)
	assert.Nil(t, service)
}

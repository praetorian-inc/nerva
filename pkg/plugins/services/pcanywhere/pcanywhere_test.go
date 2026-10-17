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

package pcanywhere

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
)

// Recorded TCP handshake: GIAC "ST" host reply.
var fixtureST = []byte{'S', 'T', 0x00, 0x00}

// Recorded TCP banner: nmap match pcanywheredata.
var fixtureNmapBanner = []byte{0x00, 'X', 0x08, 0x00, '}', 0x08, '\r', '\n', 0x00, '.', 0x08, '.', '.', '.', '\r', '\n'}

// Recorded UDP status: nmap Probe UDP pc-anywhere match.
var fixtureUDP = []byte("NRHOST____AHM_3___\x00")

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

func TestCheckPcAnywhereTCP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "ST handshake", data: fixtureST, wantErr: false},
		{name: "nmap Please press Enter", data: []byte("Please press <Enter>"), wantErr: false},
		{name: "nmap pcanywheredata banner", data: fixtureNmapBanner, wantErr: false},
		{name: "ST prefix false positive", data: []byte("STATUS OK\r\n"), wantErr: true},
		{name: "HTTP banner fake", data: []byte("HTTP/1.1 200 OK"), wantErr: true},
		{name: "empty", data: []byte{}, wantErr: true},
		{name: "too short", data: []byte{0x00}, wantErr: true},
		{name: "unrelated TCP", data: []byte{0x17, 0x24, 0x11}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkPcAnywhereTCP(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckPcAnywhereUDP(t *testing.T) {
	t.Parallel()
	assert.NoError(t, checkPcAnywhereUDP(fixtureUDP))
	assert.Error(t, checkPcAnywhereUDP([]byte("NQ")))
	assert.Error(t, checkPcAnywhereUDP([]byte("NRHOST")))
	assert.Error(t, checkPcAnywhereUDP([]byte("NRHOSTAHM_3___X")))
	assert.Error(t, checkPcAnywhereUDP([]byte("NRHOST_AHM_3___JUNK\x00")))
	assert.Error(t, checkPcAnywhereUDP([]byte("HTTP/1.1 200 OK")))
}

func TestPcAnywherePlugin_Run_HandshakeSuccess_EmitsFinding(t *testing.T) {
	conn := &mockConn{readData: fixtureST}
	plugin := &PcAnywherePlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("192.0.2.1:5631"),
		Misconfigs: true,
	}
	service, err := plugin.Run(conn, time.Second, target)
	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, plugins.ProtoPcAnywhere, service.Protocol)
	assert.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "pcanywhere-exposed", service.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityLow, service.SecurityFindings[0].Severity)
}

func TestPcAnywherePlugin_Run_NmapBanner_IdentifiesProtocol(t *testing.T) {
	conn := &mockConn{readData: fixtureNmapBanner}
	plugin := &PcAnywherePlugin{}
	target := plugins.Target{Address: netip.MustParseAddrPort("192.0.2.1:5631")}
	service, err := plugin.Run(conn, time.Second, target)
	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, plugins.ProtoPcAnywhere, service.Protocol)
	assert.Empty(t, service.SecurityFindings)
}

func TestPcAnywherePlugin_Run_HTTPBanner_NoFinding(t *testing.T) {
	conn := &mockConn{readData: []byte("HTTP/1.1 200 OK")}
	plugin := &PcAnywherePlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("192.0.2.1:5631"),
		Misconfigs: true,
	}
	service, err := plugin.Run(conn, time.Second, target)
	assert.NoError(t, err)
	assert.Nil(t, service)
}

func TestPcAnywherePlugin_Run_EmptyResponse(t *testing.T) {
	conn := &mockConn{readData: []byte{}}
	plugin := &PcAnywherePlugin{}
	target := plugins.Target{Address: netip.MustParseAddrPort("192.0.2.1:5631")}
	service, err := plugin.Run(conn, time.Second, target)
	assert.NoError(t, err)
	assert.Nil(t, service)
}

func TestPcAnywhereUDPPlugin_Run_StatusHandshake(t *testing.T) {
	conn := &mockConn{readData: fixtureUDP}
	plugin := &PcAnywhereUDPPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("192.0.2.1:5632"),
		Misconfigs: true,
	}
	service, err := plugin.Run(conn, time.Second, target)
	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, plugins.ProtoPcAnywhere, service.Protocol)
	assert.Equal(t, "pcanywhere-exposed", service.SecurityFindings[0].ID)
}

func TestPcAnywherePlugin_PortPriority(t *testing.T) {
	p := &PcAnywherePlugin{}
	assert.True(t, p.PortPriority(5631))
	assert.False(t, p.PortPriority(80))
	u := &PcAnywhereUDPPlugin{}
	assert.True(t, u.PortPriority(5632))
	assert.False(t, u.PortPriority(5631))
}

func TestPcAnywherePlugin_NameAndType(t *testing.T) {
	p := &PcAnywherePlugin{}
	assert.Equal(t, PCANYWHERE, p.Name())
	assert.Equal(t, plugins.TCP, p.Type())
	u := &PcAnywhereUDPPlugin{}
	assert.Equal(t, PCANYWHERE, u.Name())
	assert.Equal(t, plugins.UDP, u.Type())
}

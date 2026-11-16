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

package vnc

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

var fixtureRFB = []byte("RFB 003.008\n")

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

func TestVNCPlugin_Run_RFBAnyPort_EmitsExposure(t *testing.T) {
	t.Parallel()
	conn := &mockConn{readData: fixtureRFB}
	plugin := &VNCPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("192.0.2.1:12345"),
		Misconfigs: true,
	}
	service, err := plugin.Run(conn, time.Second, target)
	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, plugins.ProtoVNC, service.Protocol)
	assert.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "vnc-exposed", service.SecurityFindings[0].ID)
}

func TestVNCPlugin_Run_HTTPBanner_NoFinding(t *testing.T) {
	t.Parallel()
	conn := &mockConn{readData: []byte("HTTP/1.1 200 OK\r\n")}
	plugin := &VNCPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("192.0.2.1:5900"),
		Misconfigs: true,
	}
	service, err := plugin.Run(conn, time.Second, target)
	assert.NoError(t, err)
	assert.Nil(t, service)
}

func TestVNCPlugin_Run_MisconfigsFalse_IdentifiesWithoutFinding(t *testing.T) {
	t.Parallel()
	conn := &mockConn{readData: fixtureRFB}
	plugin := &VNCPlugin{}
	target := plugins.Target{Address: netip.MustParseAddrPort("192.0.2.1:5900")}
	service, err := plugin.Run(conn, time.Second, target)
	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Empty(t, service.SecurityFindings)
}

func TestVNC(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "vnc",
			Port:        5901,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "consol/centos-xfce-vnc",
			},
		},
	}

	p := &VNCPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

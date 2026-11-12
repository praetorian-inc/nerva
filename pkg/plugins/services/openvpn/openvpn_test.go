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
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
	"github.com/stretchr/testify/assert"
)

type echoResetConn struct {
	written  []byte
	readOnce bool
}

func (m *echoResetConn) Read(b []byte) (n int, err error) {
	if m.readOnce || len(m.written) < 9 {
		return 0, nil
	}
	m.readOnce = true
	resp := make([]byte, 14)
	resp[0] = 8 << 3 // PControlHardResetServerV2
	copy(resp[1:9], m.written[1:9])
	return copy(b, resp), nil
}

func (m *echoResetConn) Write(b []byte) (n int, err error) {
	m.written = append([]byte(nil), b...)
	return len(b), nil
}
func (m *echoResetConn) Close() error                       { return nil }
func (m *echoResetConn) LocalAddr() net.Addr                { return nil }
func (m *echoResetConn) RemoteAddr() net.Addr               { return nil }
func (m *echoResetConn) SetDeadline(t time.Time) error      { return nil }
func (m *echoResetConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *echoResetConn) SetWriteDeadline(t time.Time) error { return nil }

func TestOpenVPNPlugin_Run_CLIENT_RESET_UDP_EmitsExposure(t *testing.T) {
	t.Parallel()
	conn := &echoResetConn{}
	plugin := &Plugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("192.0.2.1:1194"),
		Misconfigs: true,
	}
	service, err := plugin.Run(conn, time.Second, target)
	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "udp", service.Transport)
	assert.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "openvpn-exposed", service.SecurityFindings[0].ID)
	assert.NotEqual(t, "openvpn-management-exposed", service.SecurityFindings[0].ID)
}

func TestOpenVPNTCPPlugin_Run_CLIENT_RESET_TCP_EmitsExposure(t *testing.T) {
	t.Parallel()
	conn := &echoResetConn{}
	plugin := &TCPPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("192.0.2.1:1194"),
		Misconfigs: true,
	}
	service, err := plugin.Run(conn, time.Second, target)
	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "tcp", service.Transport)
	assert.Equal(t, "openvpn-exposed", service.SecurityFindings[0].ID)
	assert.Equal(t, plugins.TCP, plugin.Type())
}

func TestOpenVPNPlugin_Run_HTTPBanner_NoFinding(t *testing.T) {
	t.Parallel()
	httpConn := &httpBannerConn{body: []byte("HTTP/1.1 200 OK")}
	plugin := &Plugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("192.0.2.1:1194"),
		Misconfigs: true,
	}
	service, err := plugin.Run(httpConn, time.Second, target)
	assert.NoError(t, err)
	assert.Nil(t, service)
}

type httpBannerConn struct {
	body     []byte
	readOnce bool
}

func (m *httpBannerConn) Read(b []byte) (n int, err error) {
	if m.readOnce {
		return 0, nil
	}
	m.readOnce = true
	return copy(b, m.body), nil
}
func (m *httpBannerConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *httpBannerConn) Close() error                       { return nil }
func (m *httpBannerConn) LocalAddr() net.Addr                { return nil }
func (m *httpBannerConn) RemoteAddr() net.Addr               { return nil }
func (m *httpBannerConn) SetDeadline(t time.Time) error      { return nil }
func (m *httpBannerConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *httpBannerConn) SetWriteDeadline(t time.Time) error { return nil }

func TestOpenVPN(t *testing.T) {
	// the Privileged container does not run on Github actions -- but this test passes locally
	testcases := []test.Testcase{
		// 	{
		// 		Description: "openvpn",
		// 		Port:        1194,
		// 		Protocol:    plugins.UDP,
		// 		Expected: func(res *plugins.PluginResults) bool {
		// 			return res != nil
		// 		},
		// 		RunConfig: dockertest.RunOptions{
		// 			Repository: "jpetazzo/dockvpn",
		// 			Privileged: true,
		// 		},
		// 	},
	}

	var p *Plugin

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

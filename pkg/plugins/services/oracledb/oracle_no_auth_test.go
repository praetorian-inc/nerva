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

package oracledb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func tnsPacket(typ byte, payload []byte) []byte {
	pkt := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(pkt[0:2], uint16(len(pkt)))
	pkt[4] = typ
	copy(pkt[8:], payload)
	return pkt
}

func fingerprintRefusePacket() []byte {
	return tnsPacket(4, []byte("(DESCRIPTION=(TMP=)(VSNNUM=318767104)(ERR=1189)(ERROR_STACK=(ERROR=(CODE=1189)(EMFI=4))))"))
}

func tnsAcceptPacket() []byte {
	return tnsPacket(2, []byte("(DESCRIPTION=(TMP=)(VSNNUM=318767104))"))
}

func authSesskeyDataPacket() []byte {
	return tnsDataPacket([]byte("AUTH_SESSKEY=deadbeef"))
}

func authRequiredDataPacket() []byte {
	return tnsDataPacket([]byte("ORA-01017: invalid username/password"))
}

func startOracleMock(t *testing.T, reply func(request []byte, seq int) []byte) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				seq := 0
				for {
					buf := make([]byte, 4096)
					n, err := c.Read(buf)
					if err != nil || n == 0 {
						return
					}
					seq++
					if _, err := c.Write(reply(buf[:n], seq)); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func runOraclePlugin(t *testing.T, port int, misconfigs bool) *plugins.Service {
	t.Helper()
	addrStr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", addrStr, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	plugin := &ORACLEPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, plugins.Target{
		Host:       "127.0.0.1",
		Address:    netip.MustParseAddrPort(addrStr),
		Misconfigs: misconfigs,
	})
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want fingerprinted Oracle service")
	}
	return service
}

func TestOracleNoAuthSecurityFindings(t *testing.T) {
	tests := []struct {
		name         string
		misconfigs   bool
		login        func(request []byte, seq int) []byte
		wantAnon     bool
		wantFindings int
	}{
		{
			name:       "empty-user PreAuth AUTH_SESSKEY emits oracle-no-auth",
			misconfigs: true,
			login: func(request []byte, seq int) []byte {
				if bytes.Contains(request, []byte("non-abc-existent")) {
					return fingerprintRefusePacket()
				}
				if seq == 1 {
					return tnsAcceptPacket()
				}
				return authSesskeyDataPacket()
			},
			wantAnon:     true,
			wantFindings: 1,
		},
		{
			name:       "Accept then ORA-01017 does not emit",
			misconfigs: true,
			login: func(request []byte, seq int) []byte {
				if bytes.Contains(request, []byte("non-abc-existent")) {
					return fingerprintRefusePacket()
				}
				if seq == 1 {
					return tnsAcceptPacket()
				}
				return authRequiredDataPacket()
			},
			wantAnon:     false,
			wantFindings: 0,
		},
		{
			name:       "TNS Accept without AUTH_SESSKEY does not emit",
			misconfigs: true,
			login: func(request []byte, seq int) []byte {
				if bytes.Contains(request, []byte("non-abc-existent")) {
					return fingerprintRefusePacket()
				}
				return tnsAcceptPacket()
			},
			wantAnon:     false,
			wantFindings: 0,
		},
		{
			name:       "TNS-only refuse on login probe does not emit",
			misconfigs: true,
			login: func(request []byte, seq int) []byte {
				return fingerprintRefusePacket()
			},
			wantAnon:     false,
			wantFindings: 0,
		},
		{
			name:       "Misconfigs false does not emit even if AUTH_SESSKEY would follow",
			misconfigs: false,
			login: func(request []byte, seq int) []byte {
				if bytes.Contains(request, []byte("non-abc-existent")) {
					return fingerprintRefusePacket()
				}
				if seq == 1 {
					return tnsAcceptPacket()
				}
				return authSesskeyDataPacket()
			},
			wantAnon:     false,
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := startOracleMock(t, tt.login)
			service := runOraclePlugin(t, port, tt.misconfigs)
			assert.Equal(t, tt.wantAnon, service.AnonymousAccess)
			assert.Len(t, service.SecurityFindings, tt.wantFindings)
			if tt.wantFindings > 0 {
				assert.Equal(t, "oracle-no-auth", service.SecurityFindings[0].ID)
				assert.Equal(t, plugins.SeverityCritical, service.SecurityFindings[0].Severity)
			}
		})
	}
}

func TestEmptyCredentialSessionSucceeded(t *testing.T) {
	assert.True(t, emptyCredentialSessionSucceeded(authSesskeyDataPacket()))
	assert.False(t, emptyCredentialSessionSucceeded(tnsAcceptPacket()))
	assert.False(t, emptyCredentialSessionSucceeded(fingerprintRefusePacket()))
	assert.False(t, emptyCredentialSessionSucceeded(authRequiredDataPacket()))
	assert.False(t, emptyCredentialSessionSucceeded(nil))
}

func TestCanSelfDialOracle(t *testing.T) {
	assert.False(t, canSelfDialOracle(plugins.Target{}))
	unspec, err := netip.ParseAddrPort("0.0.0.0:1521")
	if err != nil {
		t.Fatal(err)
	}
	assert.False(t, canSelfDialOracle(plugins.Target{Address: unspec}))
	ok, err := netip.ParseAddrPort("127.0.0.1:1521")
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, canSelfDialOracle(plugins.Target{Address: ok}))
}

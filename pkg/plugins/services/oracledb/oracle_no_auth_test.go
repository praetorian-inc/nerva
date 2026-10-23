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

func authSessionIDDataPacket() []byte {
	return tnsDataPacket([]byte("AUTH_SESSION_ID=1\x00AUTH_SERIAL_NUM=1"))
}

func authRequiredDataPacket() []byte {
	return tnsDataPacket([]byte("ORA-01017: invalid username/password"))
}

func nullPasswordDataPacket() []byte {
	return tnsDataPacket([]byte("ORA-01005: null password given"))
}

func negoDataPacket() []byte {
	return tnsDataPacket([]byte{0x01, 0x06})
}

func isFingerprintConnect(request []byte) bool {
	return bytes.Contains(request, []byte("non-abc-existent"))
}

func isTNSConnect(request []byte) bool {
	return tnsPacketType(request) == 1
}

func isPhase2(request []byte) bool {
	return bytes.Contains(request, []byte("AUTH_PASSWORD"))
}

func isPreAuth(request []byte) bool {
	return bytes.Contains(request, []byte{0x03, 0x76}) ||
		(bytes.Contains(request, []byte("AUTH_")) && !isPhase2(request))
}

func completeLogonReply(phase2 []byte) func([]byte, int) []byte {
	return func(request []byte, seq int) []byte {
		if isFingerprintConnect(request) {
			return fingerprintRefusePacket()
		}
		if isTNSConnect(request) {
			return tnsAcceptPacket()
		}
		if isPhase2(request) {
			return phase2
		}
		if isPreAuth(request) {
			return authSesskeyDataPacket()
		}
		return negoDataPacket()
	}
}

func startOracleMockPerConn(t *testing.T, newHandler func() func(request []byte, seq int) []byte) int {
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
				handler := newHandler()
				seq := 0
				for {
					buf := make([]byte, 4096)
					n, err := c.Read(buf)
					if err != nil || n == 0 {
						return
					}
					seq++
					if _, err := c.Write(handler(buf[:n], seq)); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func startOracleMock(t *testing.T, reply func(request []byte, seq int) []byte) int {
	t.Helper()
	return startOracleMockPerConn(t, func() func([]byte, int) []byte {
		return reply
	})
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
			name:         "completed empty logon AUTH_SESSION_ID emits oracle-no-auth",
			misconfigs:   true,
			login:        completeLogonReply(authSessionIDDataPacket()),
			wantAnon:     true,
			wantFindings: 1,
		},
		{
			name:         "phase-1 AUTH_SESSKEY without AUTH_SESSION_ID does not emit",
			misconfigs:   true,
			login:        completeLogonReply(authSesskeyDataPacket()),
			wantAnon:     false,
			wantFindings: 0,
		},
		{
			name:         "Accept then ORA-01017 on phase-2 does not emit",
			misconfigs:   true,
			login:        completeLogonReply(authRequiredDataPacket()),
			wantAnon:     false,
			wantFindings: 0,
		},
		{
			name:         "ORA-01005 on phase-2 does not emit",
			misconfigs:   true,
			login:        completeLogonReply(nullPasswordDataPacket()),
			wantAnon:     false,
			wantFindings: 0,
		},
		{
			name:       "TNS Accept without AUTH_SESSKEY does not emit",
			misconfigs: true,
			login: func(request []byte, seq int) []byte {
				if isFingerprintConnect(request) {
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
			name:         "Misconfigs false does not emit even if AUTH_SESSION_ID would follow",
			misconfigs:   false,
			login:        completeLogonReply(authSessionIDDataPacket()),
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
				assert.Equal(t, plugins.SeverityMedium, service.SecurityFindings[0].Severity)
			}
		})
	}
}

func TestOracleNoAuthContinuesAfterAuthRequiredService(t *testing.T) {
	port := startOracleMockPerConn(t, func() func([]byte, int) []byte {
		service := ""
		return func(request []byte, seq int) []byte {
			if isFingerprintConnect(request) {
				return fingerprintRefusePacket()
			}
			if isTNSConnect(request) {
				switch {
				case bytes.Contains(request, []byte("SERVICE_NAME=XE")):
					service = "XE"
					return tnsAcceptPacket()
				case bytes.Contains(request, []byte("SERVICE_NAME=ORCL")):
					service = "ORCL"
					return tnsAcceptPacket()
				default:
					return fingerprintRefusePacket()
				}
			}
			if service == "XE" {
				if isPreAuth(request) || isPhase2(request) {
					return authRequiredDataPacket()
				}
				return negoDataPacket()
			}
			if service == "ORCL" {
				if isPhase2(request) {
					return authSessionIDDataPacket()
				}
				if isPreAuth(request) {
					return authSesskeyDataPacket()
				}
				return negoDataPacket()
			}
			return fingerprintRefusePacket()
		}
	})
	service := runOraclePlugin(t, port, true)
	assert.True(t, service.AnonymousAccess)
	assert.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "oracle-no-auth", service.SecurityFindings[0].ID)
}

func TestOracleNoAuthUsesEngineDialer(t *testing.T) {
	port := startOracleMock(t, completeLogonReply(authSessionIDDataPacket()))
	mockAddr := fmt.Sprintf("127.0.0.1:%d", port)
	fpConn, err := net.DialTimeout("tcp", mockAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	t.Cleanup(func() { _ = fpConn.Close() })

	// TEST-NET-1: net.DialTimeout to this address must not reach the mock.
	bogus := netip.MustParseAddrPort("192.0.2.1:1521")
	service, err := (&ORACLEPlugin{}).Run(fpConn, 5*time.Second, plugins.Target{
		Host:       "192.0.2.1",
		Address:    bogus,
		Misconfigs: true,
		DialTCP: func(address string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("tcp", mockAddr, timeout)
		},
	})
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want fingerprinted Oracle service")
	}
	assert.True(t, service.AnonymousAccess)
	assert.Len(t, service.SecurityFindings, 1)
}

func TestEmptyCredentialSessionSucceeded(t *testing.T) {
	assert.True(t, emptyCredentialSessionSucceeded(authSessionIDDataPacket()))
	assert.False(t, emptyCredentialSessionSucceeded(authSesskeyDataPacket()))
	assert.False(t, emptyCredentialSessionSucceeded(tnsAcceptPacket()))
	assert.False(t, emptyCredentialSessionSucceeded(fingerprintRefusePacket()))
	assert.False(t, emptyCredentialSessionSucceeded(authRequiredDataPacket()))
	assert.False(t, emptyCredentialSessionSucceeded(nullPasswordDataPacket()))
	assert.False(t, emptyCredentialSessionSucceeded(nil))
}

func TestLoginIndicatesAuthRequired(t *testing.T) {
	assert.True(t, loginIndicatesAuthRequired(authRequiredDataPacket()))
	assert.True(t, loginIndicatesAuthRequired(nullPasswordDataPacket()))
	assert.True(t, loginIndicatesAuthRequired([]byte("ORA-01004: default username feature not supported")))
	assert.True(t, loginIndicatesAuthRequired([]byte("ORA-28218: password too simple")))
	assert.False(t, loginIndicatesAuthRequired(authSesskeyDataPacket()))
	assert.False(t, loginIndicatesAuthRequired(authSessionIDDataPacket()))
}

func TestEmptyUserPreAuthIsComplete(t *testing.T) {
	pkt := emptyUserPreAuth()
	assert.True(t, bytes.Contains(pkt, []byte{0x03, 0x76}))
	assert.True(t, bytes.Contains(pkt, []byte("AUTH_TERMINAL")))
	assert.False(t, bytes.Contains(pkt, []byte("AUTH_PASSWORD")))
	assert.Greater(t, len(pkt), 16)
}

func TestEmptyUserAuthPasswordIsPhase2(t *testing.T) {
	pkt := emptyUserAuthPassword()
	assert.True(t, bytes.Contains(pkt, []byte{0x03, 0x73}))
	assert.True(t, bytes.Contains(pkt, []byte("AUTH_PASSWORD")))
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
	assert.Nil(t, oracleDialTCP(plugins.Target{Address: unspec}))
	assert.NotNil(t, oracleDialTCP(plugins.Target{Address: ok}))
}

func TestRecvTNSReadsSplitFrame(t *testing.T) {
	pkt := authSessionIDDataPacket()
	if len(pkt) < 10 {
		t.Fatalf("session packet too short: %d", len(pkt))
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = server.Write(pkt[:5])
		_, _ = server.Write(pkt[5:])
	}()
	got, err := recvTNS(client, 2*time.Second)
	if err != nil {
		t.Fatalf("recvTNS: %v", err)
	}
	assert.True(t, emptyCredentialSessionSucceeded(got))
}

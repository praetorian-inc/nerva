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

package mssql

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// TestBuildMSSQLCPE_WithVersion tests CPE generation with a known version
func TestBuildMSSQLCPE_WithVersion(t *testing.T) {
	testcases := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "SQL Server 2019",
			version:  "15.0.2000",
			expected: "cpe:2.3:a:microsoft:sql_server:15.0.2000:*:*:*:*:*:*:*",
		},
		{
			name:     "SQL Server 2017",
			version:  "14.0.1000",
			expected: "cpe:2.3:a:microsoft:sql_server:14.0.1000:*:*:*:*:*:*:*",
		},
		{
			name:     "SQL Server 2016",
			version:  "13.0.5026",
			expected: "cpe:2.3:a:microsoft:sql_server:13.0.5026:*:*:*:*:*:*:*",
		},
		{
			name:     "SQL Server 2014",
			version:  "12.0.6024",
			expected: "cpe:2.3:a:microsoft:sql_server:12.0.6024:*:*:*:*:*:*:*",
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := buildMSSQLCPE(tc.version)

			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

// TestBuildMSSQLCPE_WithoutVersion tests CPE generation with unknown version (wildcard)
func TestBuildMSSQLCPE_WithoutVersion(t *testing.T) {
	version := ""
	expected := "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*"

	result := buildMSSQLCPE(version)

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestMSSQL(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "mssql",
			Port:        1433,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "mcr.microsoft.com/mssql/server",
				Tag:        "2019-latest",
				Env: []string{
					"ACCEPT_EULA=Y",
					"SA_PASSWORD=yourStrong(!)Password",
				},
			},
		},
	}

	p := &MSSQLPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("%s", err.Error())
			}
		})
	}
}

func buildMockPreloginResponse(encryption byte) []byte {
	return []byte{
		0x04, 0x01, 0x00, 0x30, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x1F, 0x00, 0x06,
		0x01, 0x00, 0x25, 0x00, 0x01,
		0x02, 0x00, 0x26, 0x00, 0x01,
		0x03, 0x00, 0x27, 0x00, 0x00,
		0x04, 0x00, 0x27, 0x00, 0x01,
		0x05, 0x00, 0x28, 0x00, 0x00,
		0xFF,
		0x0F, 0x00, 0x07, 0xD0, 0x00, 0x00,
		encryption,
		0x00,
		0x00,
	}
}

func generateMockTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}
}

func readMockTDSPacket(r io.Reader) error {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return err
	}
	length := int(binary.BigEndian.Uint16(hdr[2:4]))
	if length < 8 {
		return io.ErrUnexpectedEOF
	}
	body := make([]byte, length-8)
	_, err := io.ReadFull(r, body)
	return err
}

func buildMockLoginAck() []byte {
	return []byte{
		0x04, 0x01, 0x00, 0x15, 0x00, 0x00, 0x01, 0x00,
		0xAD, 0x0A, 0x00,
		0x01,
		0x04, 0x00, 0x00, 0x74,
		0x00,
		0x0F, 0x00, 0x07, 0xD0,
	}
}

func buildMockLoginError() []byte {
	return []byte{
		0x04, 0x01, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00,
		0xAA,
	}
}

func startMockTDS(t *testing.T, unauth bool, expectLogin bool, encryption byte) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var cert tls.Certificate
	if encryption != encryptNotSup {
		cert = generateMockTLSCert(t)
	}

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		if _, err := conn.Write(buildMockPreloginResponse(encryption)); err != nil {
			return
		}
		if !expectLogin {
			return
		}

		loginSrc := net.Conn(conn)
		replyDst := net.Conn(conn)
		if encryption != encryptNotSup {
			prep := &tdsHandshakeConn{Conn: conn, wrap: true}
			tln := tls.Server(prep, &tls.Config{Certificates: []tls.Certificate{cert}})
			if err := tln.Handshake(); err != nil {
				return
			}
			prep.wrap = false
			loginSrc = tln
			if encryption != encryptOff {
				replyDst = tln
			}
		}
		if err := readMockTDSPacket(loginSrc); err != nil {
			return
		}
		reply := buildMockLoginError()
		if unauth {
			reply = buildMockLoginAck()
		}
		_, _ = replyDst.Write(reply)
	}()

	return listener.Addr().String(), func() { _ = listener.Close() }
}

func TestMSSQLSecurityFindings(t *testing.T) {
	tests := []struct {
		name         string
		misconfigs   bool
		unauth       bool
		encryption   byte
		wantAnon     bool
		wantFinding  bool
		wantFindings int
	}{
		{
			name:         "ENCRYPT_NOT_SUP LOGINACK emits mssql-default-creds",
			misconfigs:   true,
			unauth:       true,
			encryption:   encryptNotSup,
			wantAnon:     false,
			wantFinding:  true,
			wantFindings: 1,
		},
		{
			name:         "ENCRYPT_NOT_SUP ERROR does not emit mssql-default-creds",
			misconfigs:   true,
			unauth:       false,
			encryption:   encryptNotSup,
			wantAnon:     false,
			wantFinding:  false,
			wantFindings: 0,
		},
		{
			name:         "Misconfigs=false does not emit finding",
			misconfigs:   false,
			unauth:       true,
			encryption:   encryptNotSup,
			wantAnon:     false,
			wantFinding:  false,
			wantFindings: 0,
		},
		{
			name:         "ENCRYPT_OFF LOGINACK emits mssql-default-creds",
			misconfigs:   true,
			unauth:       true,
			encryption:   encryptOff,
			wantAnon:     false,
			wantFinding:  true,
			wantFindings: 1,
		},
		{
			name:         "ENCRYPT_ON LOGINACK emits mssql-default-creds",
			misconfigs:   true,
			unauth:       true,
			encryption:   encryptOn,
			wantAnon:     false,
			wantFinding:  true,
			wantFindings: 1,
		},
		{
			name:         "ENCRYPT_REQ LOGINACK emits mssql-default-creds",
			misconfigs:   true,
			unauth:       true,
			encryption:   encryptReq,
			wantAnon:     false,
			wantFinding:  true,
			wantFindings: 1,
		},
		{
			name:         "ENCRYPT_OFF ERROR does not emit mssql-default-creds",
			misconfigs:   true,
			unauth:       false,
			encryption:   encryptOff,
			wantAnon:     false,
			wantFinding:  false,
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, cleanup := startMockTDS(t, tt.unauth, tt.misconfigs, tt.encryption)
			defer cleanup()

			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			require.NoError(t, err)
			defer conn.Close()

			addrPort := netip.MustParseAddrPort(addr)
			target := plugins.Target{
				Host:       "127.0.0.1",
				Address:    addrPort,
				Misconfigs: tt.misconfigs,
			}

			plugin := &MSSQLPlugin{}
			service, err := plugin.Run(conn, 5*time.Second, target)
			require.NoError(t, err)
			require.NotNil(t, service, "fingerprint must succeed")

			assert.Equal(t, tt.wantAnon, service.AnonymousAccess, "AnonymousAccess mismatch")
			assert.Len(t, service.SecurityFindings, tt.wantFindings, "SecurityFindings count mismatch")

			hasID := false
			for _, f := range service.SecurityFindings {
				if f.ID == "mssql-default-creds" {
					hasID = true
					assert.Equal(t, plugins.SeverityMedium, f.Severity)
					assert.NotContains(t, strings.ToLower(f.Evidence), "password")
					assert.NotContains(t, strings.ToLower(f.Evidence), "sa")
					assert.NotContains(t, strings.ToLower(f.Evidence), "anonymous")
					assert.NotContains(t, f.Evidence, "@")
				}
			}
			assert.Equal(t, tt.wantFinding, hasID, "mssql-default-creds presence mismatch")
		})
	}
}

func TestRecvTDSResponseConcatenatesPackets(t *testing.T) {
	ack := buildMockLoginAck()
	body := ack[8:]
	split := 3
	require.Greater(t, len(body), split)

	pkt1 := make([]byte, 8+split)
	pkt1[0] = 0x04
	binary.BigEndian.PutUint16(pkt1[2:4], uint16(8+split))
	pkt1[6] = 0x01
	copy(pkt1[8:], body[:split])

	rest := body[split:]
	pkt2 := make([]byte, 8+len(rest))
	pkt2[0] = 0x04
	pkt2[1] = 0x01
	binary.BigEndian.PutUint16(pkt2[2:4], uint16(8+len(rest)))
	pkt2[6] = 0x01
	copy(pkt2[8:], rest)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = server.Write(pkt1)
		_, _ = server.Write(pkt2)
	}()

	resp, err := recvTDSResponse(client, 2*time.Second)
	require.NoError(t, err)
	require.True(t, hasLoginAck(resp), "concatenated packets must yield LOGINACK")
}

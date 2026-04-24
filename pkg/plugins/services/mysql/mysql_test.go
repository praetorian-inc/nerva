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

package mysql

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

func TestMySQL(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "mysql",
			Port:        3306,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "mysql",
				Tag:        "5.7.39",
				Env: []string{
					"MYSQL_ROOT_PASSWORD=my-secret-pw",
				},
			},
		},
	}

	p := &MYSQLPlugin{}

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

// TestParseVersionString tests the parseVersionString function for various MySQL-family version strings.
func TestParseVersionString(t *testing.T) {
	tests := []struct {
		name           string
		versionStr     string
		wantServerType string
		wantVersion    string
	}{
		// MySQL (Oracle)
		{"MySQL 8.0.28", "8.0.28", "mysql", "8.0.28"},
		{"MySQL 5.7.40", "5.7.40", "mysql", "5.7.40"},
		{"MySQL 8.0.28 with distro", "8.0.28-0ubuntu0.20.04.3", "mysql", "8.0.28"},
		{"MySQL 5.6.51", "5.6.51", "mysql", "5.6.51"},

		// MariaDB
		{"MariaDB 10.5.12", "10.5.12-MariaDB", "mariadb", "10.5.12"},
		{"MariaDB 11.0.3", "11.0.3-MariaDB-1:11.0.3+maria~ubu2204", "mariadb", "11.0.3"},
		{"MariaDB with legacy prefix", "5.5.5-10.5.12-MariaDB", "mariadb", "10.5.12"},
		{"MariaDB 10.4.7", "10.4.7-MariaDB", "mariadb", "10.4.7"},
		{"MariaDB 10.5.19 with distro", "10.5.19-MariaDB-0+deb11u2", "mariadb", "10.5.19"},

		// Percona Server
		{"Percona 8.0.28-19", "8.0.28-19-Percona", "percona", "8.0.28-19"},
		{"Percona 5.7.40-43", "5.7.40-43-Percona", "percona", "5.7.40-43"},
		{"Percona 8.0.28-20", "8.0.28-20-Percona Server", "percona", "8.0.28-20"},

		// Amazon Aurora MySQL
		{"Aurora MySQL 3.x", "8.0.mysql_aurora.3.11.0", "aurora", "3.11.0"},
		{"Aurora MySQL 2.x", "5.7.mysql_aurora.2.11.0", "aurora", "2.11.0"},

		// Edge cases
		{"Empty string", "", "unknown", ""},
		{"Invalid format", "not-a-version", "unknown", ""},
		{"Random text", "random text without version", "unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverType, version := parseVersionString(tt.versionStr)
			assert.Equal(t, tt.wantServerType, serverType, "server type mismatch")
			assert.Equal(t, tt.wantVersion, version, "version mismatch")
		})
	}
}

// TestBuildMySQLCPE tests the buildMySQLCPE function for generating correct CPE strings.
func TestBuildMySQLCPE(t *testing.T) {
	tests := []struct {
		name       string
		serverType string
		version    string
		wantCPE    string
	}{
		// MySQL
		{"MySQL with version", "mysql", "8.0.28", "cpe:2.3:a:oracle:mysql:8.0.28:*:*:*:*:*:*:*"},
		{"MySQL 5.7.40", "mysql", "5.7.40", "cpe:2.3:a:oracle:mysql:5.7.40:*:*:*:*:*:*:*"},
		{"MySQL wildcard version", "mysql", "", "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"},

		// MariaDB
		{"MariaDB with version", "mariadb", "10.5.12", "cpe:2.3:a:mariadb:mariadb:10.5.12:*:*:*:*:*:*:*"},
		{"MariaDB 11.0.3", "mariadb", "11.0.3", "cpe:2.3:a:mariadb:mariadb:11.0.3:*:*:*:*:*:*:*"},
		{"MariaDB wildcard version", "mariadb", "", "cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*"},

		// Percona
		{"Percona with version", "percona", "8.0.28-19", "cpe:2.3:a:percona:percona_server:8.0.28-19:*:*:*:*:*:*:*"},
		{"Percona 5.7.40-43", "percona", "5.7.40-43", "cpe:2.3:a:percona:percona_server:5.7.40-43:*:*:*:*:*:*:*"},
		{"Percona wildcard version", "percona", "", "cpe:2.3:a:percona:percona_server:*:*:*:*:*:*:*:*"},

		// Aurora
		{"Aurora with version", "aurora", "3.11.0", "cpe:2.3:a:amazon:aurora:3.11.0:*:*:*:*:*:*:*"},
		{"Aurora 2.11.0", "aurora", "2.11.0", "cpe:2.3:a:amazon:aurora:2.11.0:*:*:*:*:*:*:*"},
		{"Aurora wildcard version", "aurora", "", "cpe:2.3:a:amazon:aurora:*:*:*:*:*:*:*:*"},

		// Unknown
		{"Unknown with version", "unknown", "1.0.0", "cpe:2.3:a:oracle:mysql:1.0.0:*:*:*:*:*:*:*"},
		{"Unknown wildcard version", "unknown", "", "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"},

		// Empty server type
		{"Empty server empty version", "", "", "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"},
		{"Empty server with version", "", "1.0.0", "cpe:2.3:a:oracle:mysql:1.0.0:*:*:*:*:*:*:*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildMySQLCPE(tt.serverType, tt.version)
			assert.Equal(t, tt.wantCPE, cpe, "CPE mismatch")
		})
	}
}

// buildTestHandshake constructs a valid MySQL initial handshake packet for testing.
// version is the server version string (e.g. "8.0.28"), authPlugin is the plugin name
// (e.g. "mysql_native_password"), and caps is the capability flags bitmask.
func buildTestHandshake(version string, authPlugin string, caps uint32) []byte {
	payload := []byte{}

	// Protocol version: 10
	payload = append(payload, 0x0a)

	// Server version string (null-terminated)
	payload = append(payload, []byte(version)...)
	payload = append(payload, 0x00)

	// Connection ID (4 bytes)
	payload = append(payload, 0x01, 0x00, 0x00, 0x00)

	// Auth-plugin-data-part-1 (8 bytes)
	payload = append(payload, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08)

	// Filler (must be 0x00)
	payload = append(payload, 0x00)

	// Capability flags lower 2 bytes (little-endian)
	capsLow := uint16(caps & 0xFFFF)
	payload = append(payload, byte(capsLow), byte(capsLow>>8))

	// Character set: utf8mb4 (0x21 = 33)
	payload = append(payload, 0x21)

	// Status flags (2 bytes)
	payload = append(payload, 0x02, 0x00)

	// Capability flags upper 2 bytes (little-endian)
	capsHigh := uint16(caps >> 16)
	payload = append(payload, byte(capsHigh), byte(capsHigh>>8))

	// Auth plugin data length: 21 (8 + 13)
	if caps&uint32(clientSecureConnection) != 0 {
		payload = append(payload, 21)
	} else {
		payload = append(payload, 0x00)
	}

	// Reserved (10 bytes)
	payload = append(payload, make([]byte, 10)...)

	// Auth-plugin-data-part-2 (13 bytes if CLIENT_SECURE_CONNECTION)
	if caps&uint32(clientSecureConnection) != 0 {
		payload = append(payload, make([]byte, 12)...)
		payload = append(payload, 0x00) // null terminator for part2
	}

	// Auth plugin name (null-terminated) if CLIENT_PLUGIN_AUTH
	if caps&uint32(clientPluginAuth) != 0 {
		payload = append(payload, []byte(authPlugin)...)
		payload = append(payload, 0x00)
	}

	// Wrap in MySQL packet header: 3-byte length + sequence 0
	pktLen := len(payload)
	packet := []byte{byte(pktLen), byte(pktLen >> 8), byte(pktLen >> 16), 0x00}
	packet = append(packet, payload...)
	return packet
}

// TestParseHandshake tests parseHandshake with various packet shapes.
func TestParseHandshake(t *testing.T) {
	standardCaps := uint32(clientProtocol41 | clientSecureConnection | clientPluginAuth)

	tests := []struct {
		name           string
		packet         []byte
		wantNil        bool
		wantPlugin     string
		wantCharSet    byte
	}{
		{
			name:        "valid mysql_native_password",
			packet:      buildTestHandshake("8.0.28", "mysql_native_password", standardCaps),
			wantPlugin:  "mysql_native_password",
			wantCharSet: 0x21,
		},
		{
			name:        "valid caching_sha2_password",
			packet:      buildTestHandshake("8.0.28", "caching_sha2_password", standardCaps),
			wantPlugin:  "caching_sha2_password",
			wantCharSet: 0x21,
		},
		{
			name:        "without CLIENT_PLUGIN_AUTH",
			packet:      buildTestHandshake("8.0.28", "", uint32(clientProtocol41|clientSecureConnection)),
			wantPlugin:  "",
			wantCharSet: 0x21,
		},
		{
			name:    "too short packet",
			packet:  []byte{0x01, 0x00, 0x00, 0x00, 0x0a},
			wantNil: true,
		},
		{
			name:    "invalid protocol version",
			packet:  buildTestHandshake("8.0.28", "mysql_native_password", standardCaps),
			wantNil: true,
		},
	}

	// Patch the invalid protocol version test
	for i := range tests {
		if tests[i].name == "invalid protocol version" {
			pkt := buildTestHandshake("8.0.28", "mysql_native_password", standardCaps)
			pkt[4] = 0x09 // change protocol version from 10 to 9
			tests[i].packet = pkt
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hs := parseHandshake(tt.packet)
			if tt.wantNil {
				assert.Nil(t, hs)
				return
			}
			assert.NotNil(t, hs)
			assert.Equal(t, tt.wantPlugin, hs.authPluginName)
			assert.Equal(t, tt.wantCharSet, hs.characterSet)
		})
	}
}

// TestBuildHandshakeResponse41 verifies the structure of the built response packet.
func TestBuildHandshakeResponse41(t *testing.T) {
	standardCaps := uint32(clientProtocol41 | clientSecureConnection | clientPluginAuth)
	hs := &handshakeInfo{
		capabilityFlags: standardCaps,
		characterSet:    0x21,
		authPluginName:  "mysql_native_password",
	}

	pkt := buildHandshakeResponse41(hs)

	// Must have at least 4-byte header
	assert.Greater(t, len(pkt), 4, "packet too short")

	// Payload length field must match actual payload length
	payloadLen := int(pkt[0]) | int(pkt[1])<<8 | int(pkt[2])<<16
	assert.Equal(t, len(pkt)-4, payloadLen, "payload length field mismatch")

	// Sequence number must be 1
	assert.Equal(t, byte(0x01), pkt[3], "sequence number must be 1")

	// Client capability flags (bytes 4-7 of packet = bytes 0-3 of payload)
	clientCaps := uint32(pkt[4]) | uint32(pkt[5])<<8 | uint32(pkt[6])<<16 | uint32(pkt[7])<<24
	assert.NotZero(t, clientCaps&uint32(clientProtocol41), "CLIENT_PROTOCOL_41 must be set")
	assert.NotZero(t, clientCaps&uint32(clientSecureConnection), "CLIENT_SECURE_CONNECTION must be set")

	// Username at offset 4+4+4+1+23 = 36 from start of pkt (byte 4 is payload start)
	// payload layout: caps(4) + maxpkt(4) + charset(1) + reserved(23) + username_null(1) + ...
	usernameOffset := 4 + 4 + 4 + 1 + 23 // = 36
	assert.Less(t, usernameOffset, len(pkt), "packet too short to contain username")
	assert.Equal(t, byte(0x00), pkt[usernameOffset], "username must be empty (null terminator)")

	// Auth response length byte must be 0x00
	authResponseOffset := usernameOffset + 1
	assert.Less(t, authResponseOffset, len(pkt), "packet too short to contain auth response")
	assert.Equal(t, byte(0x00), pkt[authResponseOffset], "auth response length must be 0")
}

// TestMySQLSecurityFindings tests that anonymous access is detected via mock server.
func TestMySQLSecurityFindings(t *testing.T) {
	standardCaps := uint32(clientProtocol41 | clientSecureConnection | clientPluginAuth)
	handshakePkt := buildTestHandshake("8.0.28", "mysql_native_password", standardCaps)

	// OK packet: header=0x00, affected_rows=0, last_insert_id=0
	okPkt := []byte{0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer listener.Close()

	serverPort := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Send handshake
		_, _ = conn.Write(handshakePkt)
		// Read HandshakeResponse41
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		// Send OK
		_, _ = conn.Write(okPkt)
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &MYSQLPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	assert.True(t, service.AnonymousAccess, "expected AnonymousAccess to be true")
	assert.Len(t, service.SecurityFindings, 1, "expected 1 security finding")
	if len(service.SecurityFindings) == 1 {
		assert.Equal(t, "mysql-no-auth", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityCritical, service.SecurityFindings[0].Severity)
	}
}

// TestMySQLSecurityFindingsAuthRequired tests that no findings are set when auth is required.
func TestMySQLSecurityFindingsAuthRequired(t *testing.T) {
	standardCaps := uint32(clientProtocol41 | clientSecureConnection | clientPluginAuth)
	handshakePkt := buildTestHandshake("8.0.28", "mysql_native_password", standardCaps)

	// ERR packet: Access denied
	errPkt := []byte{
		0x1c, 0x00, 0x00, 0x02, // 28-byte payload, seq 2
		0xff,       // ERR header
		0x15, 0x04, // error code 1045 (ER_ACCESS_DENIED_ERROR)
		0x23,                                                                                     // '#' SQL state marker
		0x32, 0x38, 0x30, 0x30, 0x30,                                                            // "28000"
		0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x64, 0x65, 0x6e, 0x69, 0x65, 0x64, 0x2e, 0x2e, 0x2e, // "Access denied..."
		0x00,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer listener.Close()

	serverPort := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write(handshakePkt)
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(errPkt)
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &MYSQLPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	assert.False(t, service.AnonymousAccess, "expected AnonymousAccess to be false")
	assert.Empty(t, service.SecurityFindings, "expected no security findings")
}

// TestMySQLAuthSwitchAnonymousAccess tests the AuthSwitch flow where the server sends
// handshake → client sends auth response → server sends AuthSwitch (0xFE) → client sends
// empty auth → server sends OK. Should detect anonymous access.
func TestMySQLAuthSwitchAnonymousAccess(t *testing.T) {
	standardCaps := uint32(clientProtocol41 | clientSecureConnection | clientPluginAuth)
	handshakePkt := buildTestHandshake("8.0.28", "mysql_native_password", standardCaps)

	// AuthSwitch packet: 4-byte header + 0xFE type + plugin name + null + data + null
	authSwitchPkt := []byte{
		0x07, 0x00, 0x00, 0x02, // 7-byte payload, seq 2
		packetAuthSwitch,                              // 0xFE
		'm', 'y', 's', 'q', 'l', '_', 'n', 'a', 't', 'i', 'v', 'e', '_', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0x00, // plugin name
		0x00, // auth data (empty)
	}
	// Fix length: payload after header is 1 + 21 + 1 = 23 bytes, seq 2
	authSwitchPkt = []byte{
		0x17, 0x00, 0x00, 0x02, // 23-byte payload, seq 2
		packetAuthSwitch,
		'm', 'y', 's', 'q', 'l', '_', 'n', 'a', 't', 'i', 'v', 'e', '_', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0x00,
		0x00,
	}

	// OK packet
	okPkt := []byte{0x03, 0x00, 0x00, 0x04, packetOK, 0x00, 0x00}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer listener.Close()

	serverPort := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Send initial handshake
		_, _ = conn.Write(handshakePkt)
		// Read HandshakeResponse41
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		// Send AuthSwitch
		_, _ = conn.Write(authSwitchPkt)
		// Read empty auth response
		_, _ = conn.Read(buf)
		// Send OK
		_, _ = conn.Write(okPkt)
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &MYSQLPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	assert.True(t, service.AnonymousAccess, "expected AnonymousAccess to be true after AuthSwitch OK")
	assert.Len(t, service.SecurityFindings, 1, "expected 1 security finding")
	if len(service.SecurityFindings) == 1 {
		assert.Equal(t, "mysql-no-auth", service.SecurityFindings[0].ID)
	}
}

// TestMySQLAuthSwitchWithERR tests that no anonymous access is detected when the server
// sends AuthSwitch followed by ERR.
func TestMySQLAuthSwitchWithERR(t *testing.T) {
	standardCaps := uint32(clientProtocol41 | clientSecureConnection | clientPluginAuth)
	handshakePkt := buildTestHandshake("8.0.28", "mysql_native_password", standardCaps)

	authSwitchPkt := []byte{
		0x17, 0x00, 0x00, 0x02,
		packetAuthSwitch,
		'm', 'y', 's', 'q', 'l', '_', 'n', 'a', 't', 'i', 'v', 'e', '_', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0x00,
		0x00,
	}

	// ERR packet after auth switch
	errPkt := []byte{
		0x1c, 0x00, 0x00, 0x04,
		packetERR,
		0x15, 0x04, // error code 1045
		0x23,
		0x32, 0x38, 0x30, 0x30, 0x30,
		0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x64, 0x65, 0x6e, 0x69, 0x65, 0x64, 0x2e, 0x2e, 0x2e,
		0x00,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer listener.Close()

	serverPort := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write(handshakePkt)
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(authSwitchPkt)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(errPkt)
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &MYSQLPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	assert.False(t, service.AnonymousAccess, "expected AnonymousAccess to be false after AuthSwitch ERR")
	assert.Empty(t, service.SecurityFindings, "expected no security findings")
}

// TestMySQLCachingSha2FastAuth tests the caching_sha2_password fast-auth flow where
// the server sends 0x01 0x03 (fast auth success) followed by OK.
func TestMySQLCachingSha2FastAuth(t *testing.T) {
	standardCaps := uint32(clientProtocol41 | clientSecureConnection | clientPluginAuth)
	handshakePkt := buildTestHandshake("8.0.28", "caching_sha2_password", standardCaps)

	// caching_sha2_password fast auth success packet: type=0x01, data=0x03
	fastAuthPkt := []byte{0x02, 0x00, 0x00, 0x02, 0x01, 0x03}

	// OK packet
	okPkt := []byte{0x03, 0x00, 0x00, 0x03, packetOK, 0x00, 0x00}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer listener.Close()

	serverPort := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write(handshakePkt)
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		// Send fast auth success packet, then pause to let the client consume it
		// before sending the OK, preventing TCP coalescing into a single read.
		_, _ = conn.Write(fastAuthPkt)
		time.Sleep(20 * time.Millisecond)
		_, _ = conn.Write(okPkt)
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &MYSQLPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	assert.True(t, service.AnonymousAccess, "expected AnonymousAccess to be true after caching_sha2 fast auth OK")
	assert.Len(t, service.SecurityFindings, 1, "expected 1 security finding")
	if len(service.SecurityFindings) == 1 {
		assert.Equal(t, "mysql-no-auth", service.SecurityFindings[0].ID)
	}
}

// TestMySQLShortAuthResponse tests that a too-short response during the auth check
// does not panic and does not produce a false positive.
func TestMySQLShortAuthResponse(t *testing.T) {
	standardCaps := uint32(clientProtocol41 | clientSecureConnection | clientPluginAuth)
	handshakePkt := buildTestHandshake("8.0.28", "mysql_native_password", standardCaps)

	// A response shorter than 5 bytes — not enough to read the packet type byte at offset 4.
	shortPkt := []byte{0x01, 0x00, 0x00} // only 3 bytes

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer listener.Close()

	serverPort := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write(handshakePkt)
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		// Send a truncated response and close
		_, _ = conn.Write(shortPkt)
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &MYSQLPlugin{}
	// Must not panic
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	assert.False(t, service.AnonymousAccess, "expected AnonymousAccess to be false for short auth response")
	assert.Empty(t, service.SecurityFindings, "expected no security findings for short auth response")
}

// TestMySQLDockerMisconfigAnonymousUser is a Docker integration test that verifies
// anonymous access detection against a real MySQL container with an anonymous user.
// Uses mysql_native_password for the anonymous user so the server sends an AuthSwitch
// from the default caching_sha2_password, exercising that code path end-to-end.
func TestMySQLDockerMisconfigAnonymousUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	// Create init SQL that adds an anonymous user with mysql_native_password.
	// MySQL 8.0 defaults to caching_sha2_password, so the server will AuthSwitch
	// when the anonymous user connects, testing our AuthSwitch handler.
	initSQL, err := os.CreateTemp("", "mysql-anon-*.sql")
	if err != nil {
		t.Fatalf("could not create init SQL: %s", err)
	}
	defer os.Remove(initSQL.Name())
	if _, err := initSQL.WriteString("CREATE USER ''@'%' IDENTIFIED WITH mysql_native_password BY '';\nFLUSH PRIVILEGES;\n"); err != nil {
		t.Fatalf("could not write init SQL: %s", err)
	}
	initSQL.Close()

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mysql",
		Tag:        "8.0",
		Env: []string{
			"MYSQL_ALLOW_EMPTY_PASSWORD=yes",
		},
		Mounts: []string{
			initSQL.Name() + ":/docker-entrypoint-initdb.d/create-anon-user.sql",
		},
	})
	if err != nil {
		t.Fatalf("could not start mysql container: %s", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	port := resource.GetPort("3306/tcp")
	addr := fmt.Sprintf("127.0.0.1:%s", port)

	// Wait for MySQL to be ready before running the plugin.
	var service *plugins.Service
	retryErr := pool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", addr, 5*time.Second)
		if dialErr != nil {
			return dialErr
		}
		defer conn.Close()

		addrPort := netip.MustParseAddrPort(addr)
		target := plugins.Target{
			Host:       "127.0.0.1",
			Address:    addrPort,
			Misconfigs: true,
		}

		svc, runErr := (&MYSQLPlugin{}).Run(conn, 5*time.Second, target)
		if runErr != nil {
			return runErr
		}
		if svc == nil {
			return fmt.Errorf("mysql not yet ready")
		}
		service = svc
		return nil
	})
	if retryErr != nil {
		t.Fatalf("mysql plugin never connected: %s", retryErr)
	}

	assert.True(t, service.AnonymousAccess, "expected AnonymousAccess=true for anonymous-user MySQL")
	assert.NotEmpty(t, service.SecurityFindings, "expected SecurityFindings for anonymous-user MySQL")
	if len(service.SecurityFindings) > 0 {
		assert.Equal(t, "mysql-no-auth", service.SecurityFindings[0].ID)
	}
}

// TestMySQLDockerMisconfigWithPassword is a Docker integration test that verifies
// no anonymous access is detected against a real MySQL container that requires a password.
func TestMySQLDockerMisconfigWithPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mysql",
		Tag:        "8.0",
		Env: []string{
			"MYSQL_ROOT_PASSWORD=secret",
		},
	})
	if err != nil {
		t.Fatalf("could not start mysql container: %s", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	port := resource.GetPort("3306/tcp")
	addr := fmt.Sprintf("127.0.0.1:%s", port)

	var service *plugins.Service
	retryErr := pool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", addr, 5*time.Second)
		if dialErr != nil {
			return dialErr
		}
		defer conn.Close()

		addrPort := netip.MustParseAddrPort(addr)
		target := plugins.Target{
			Host:       "127.0.0.1",
			Address:    addrPort,
			Misconfigs: true,
		}

		svc, runErr := (&MYSQLPlugin{}).Run(conn, 5*time.Second, target)
		if runErr != nil {
			return runErr
		}
		if svc == nil {
			return fmt.Errorf("mysql not yet ready")
		}
		service = svc
		return nil
	})
	if retryErr != nil {
		t.Fatalf("mysql plugin never connected: %s", retryErr)
	}

	assert.False(t, service.AnonymousAccess, "expected AnonymousAccess=false for password-protected MySQL")
	assert.Empty(t, service.SecurityFindings, "expected no SecurityFindings for password-protected MySQL")
}

// TestMySQLNoFindingsWithoutMisconfigFlag verifies no auth check runs when Misconfigs is false.
func TestMySQLNoFindingsWithoutMisconfigFlag(t *testing.T) {
	standardCaps := uint32(clientProtocol41 | clientSecureConnection | clientPluginAuth)
	handshakePkt := buildTestHandshake("8.0.28", "mysql_native_password", standardCaps)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer listener.Close()

	serverPort := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Send handshake only - no auth exchange expected
		_, _ = conn.Write(handshakePkt)
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: false,
	}

	plugin := &MYSQLPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	assert.False(t, service.AnonymousAccess, "expected AnonymousAccess to be false")
	assert.Empty(t, service.SecurityFindings, "expected no security findings")
}

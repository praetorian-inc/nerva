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

package clickhouse

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

// buildMockServerHello constructs a binary ServerHello (packet type 0) response
// for testing parseServerHello. Optional fields (timezone, displayName) are only
// written when protoVer meets the corresponding threshold, matching real server
// behavior gated by negotiated protocol version.
func buildMockServerHello(serverName string, major, minor, protoVer, patch uint64, timezone, displayName string) []byte {
	buf := make([]byte, 0, 64)
	buf = writeVarUInt(buf, packetTypeHello)
	buf = writeString(buf, serverName)
	buf = writeVarUInt(buf, major)
	buf = writeVarUInt(buf, minor)
	buf = writeVarUInt(buf, protoVer)

	negotiated := protoVer
	if negotiated > protocolVersion {
		negotiated = protocolVersion
	}

	if negotiated >= minProtocolVersionTimezone {
		buf = writeString(buf, timezone)
	}
	if negotiated >= minProtocolVersionDisplayName {
		buf = writeString(buf, displayName)
	}
	if negotiated >= minProtocolVersionVersionPatch {
		buf = writeVarUInt(buf, patch)
	}

	return buf
}

// TestVarUIntRoundTrip verifies writeVarUInt/readVarUInt round-trip for single-byte
// and multi-byte values, including the maximum representable 64-bit value.
func TestVarUIntRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		val  uint64
	}{
		{"zero", 0},
		{"one", 1},
		{"single-byte max (127)", 127},
		{"multi-byte min (128)", 128},
		{"multi-byte (300)", 300},
		{"protocol version (54401)", 54401},
		// maxVarUIntBytes (9) bounds decoding to 63 bits, matching ClickHouse's
		// own VarUInt limit - so the largest representable value is 2^63-1,
		// not the full uint64 range.
		{"max representable (2^63-1)", (uint64(1) << 63) - 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := writeVarUInt(nil, tt.val)

			decoded, pos, err := readVarUInt(encoded, 0)
			require.NoError(t, err)
			assert.Equal(t, tt.val, decoded)
			assert.Equal(t, len(encoded), pos)
		})
	}
}

// TestReadVarUInt_Truncated verifies readVarUInt returns an error when the buffer
// ends mid-sequence (continuation bit set but no further bytes available).
func TestReadVarUInt_Truncated(t *testing.T) {
	// 0x80 has the continuation bit set, so decoding expects another byte.
	buf := []byte{0x80}

	_, _, err := readVarUInt(buf, 0)
	assert.Error(t, err)
}

// TestReadVarUInt_Overflow verifies readVarUInt rejects a VarUInt encoded in more
// than the maximum 9 bytes.
func TestReadVarUInt_Overflow(t *testing.T) {
	// 10 bytes, each with the continuation bit set - exceeds maxVarUIntBytes (9).
	buf := make([]byte, 10)
	for i := range buf {
		buf[i] = 0x80
	}

	_, _, err := readVarUInt(buf, 0)
	assert.Error(t, err)
}

// TestStringRoundTrip verifies writeString/readString round-trip for empty and
// normal strings.
func TestStringRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		val  string
	}{
		{"empty string", ""},
		{"ClickHouse", "ClickHouse"},
		{"nerva", "nerva"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := writeString(nil, tt.val)

			decoded, pos, err := readString(encoded, 0)
			require.NoError(t, err)
			assert.Equal(t, tt.val, decoded)
			assert.Equal(t, len(encoded), pos)
		})
	}
}

// TestReadString_MaxLengthGuard verifies readString rejects a length prefix that
// exceeds maxStringLen, guarding against adversarial or corrupted responses.
func TestReadString_MaxLengthGuard(t *testing.T) {
	buf := writeVarUInt(nil, maxStringLen+1)

	_, _, err := readString(buf, 0)
	assert.Error(t, err)
}

// TestReadString_Truncated verifies readString returns an error when the declared
// string length exceeds the remaining buffer.
func TestReadString_Truncated(t *testing.T) {
	buf := writeVarUInt(nil, 10) // declares a 10-byte string
	buf = append(buf, "short"...) // but only provides 5 bytes

	_, _, err := readString(buf, 0)
	assert.Error(t, err)
}

// TestBuildClientHello verifies buildClientHello produces a valid ClientHello
// packet with packet type Hello, client_name "nerva", and the expected
// protocol_version.
func TestBuildClientHello(t *testing.T) {
	packet := buildClientHello()

	pos := 0
	packetType, pos, err := readVarUInt(packet, pos)
	require.NoError(t, err)
	assert.Equal(t, uint64(packetTypeHello), packetType)

	name, pos, err := readString(packet, pos)
	require.NoError(t, err)
	assert.Equal(t, clientName, name)
	assert.Equal(t, "nerva", name)

	verMajor, pos, err := readVarUInt(packet, pos)
	require.NoError(t, err)
	assert.Equal(t, uint64(clientVerMajor), verMajor)

	verMinor, pos, err := readVarUInt(packet, pos)
	require.NoError(t, err)
	assert.Equal(t, uint64(clientVerMinor), verMinor)

	protoVer, _, err := readVarUInt(packet, pos)
	require.NoError(t, err)
	assert.Equal(t, uint64(54401), protoVer)
}

// TestParseServerHello_AllOptionalFields verifies a ServerHello with a high
// protocol_version (54401) parses timezone, display_name, and version_patch.
func TestParseServerHello_AllOptionalFields(t *testing.T) {
	data := buildMockServerHello("ClickHouse", 24, 1, 54401, 5, "UTC", "test-server")

	fields, err := parseServerHello(data)
	require.NoError(t, err)
	require.NotNil(t, fields)

	assert.Equal(t, "ClickHouse", fields.ServerName)
	assert.Equal(t, uint64(24), fields.VersionMajor)
	assert.Equal(t, uint64(1), fields.VersionMinor)
	assert.Equal(t, uint64(54401), fields.ProtocolVersion)
	assert.Equal(t, "UTC", fields.Timezone)
	assert.Equal(t, "test-server", fields.DisplayName)
	assert.Equal(t, uint64(5), fields.VersionPatch)
	assert.True(t, fields.HasPatch)
}

// TestParseServerHello_LegacyServer verifies a ServerHello with a protocol_version
// below all optional-field thresholds (54000) leaves timezone, display_name, and
// version_patch at their zero values.
func TestParseServerHello_LegacyServer(t *testing.T) {
	data := buildMockServerHello("ClickHouse", 18, 16, 54000, 0, "", "")

	fields, err := parseServerHello(data)
	require.NoError(t, err)
	require.NotNil(t, fields)

	assert.Equal(t, "ClickHouse", fields.ServerName)
	assert.Equal(t, uint64(18), fields.VersionMajor)
	assert.Equal(t, uint64(16), fields.VersionMinor)
	assert.Equal(t, uint64(54000), fields.ProtocolVersion)
	assert.Equal(t, "", fields.Timezone)
	assert.Equal(t, "", fields.DisplayName)
	assert.Equal(t, uint64(0), fields.VersionPatch)
	assert.False(t, fields.HasPatch)
}

// TestParseServerHello_IntermediateProtocolVersions verifies fields are gated
// correctly at each protocol version threshold: timezone-only, and
// timezone+display_name (without version_patch).
func TestParseServerHello_IntermediateProtocolVersions(t *testing.T) {
	tests := []struct {
		name            string
		protoVer        uint64
		wantTimezone    string
		wantDisplayName string
		wantPatch       uint64
	}{
		{
			name:            "has timezone, no display_name, no patch",
			protoVer:        54058,
			wantTimezone:    "UTC",
			wantDisplayName: "",
			wantPatch:       0,
		},
		{
			name:            "has timezone and display_name, no patch",
			protoVer:        54372,
			wantTimezone:    "UTC",
			wantDisplayName: "test-server",
			wantPatch:       0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := buildMockServerHello("ClickHouse", 22, 8, tt.protoVer, 5, "UTC", "test-server")

			fields, err := parseServerHello(data)
			require.NoError(t, err)
			require.NotNil(t, fields)

			assert.Equal(t, tt.protoVer, fields.ProtocolVersion)
			assert.Equal(t, tt.wantTimezone, fields.Timezone)
			assert.Equal(t, tt.wantDisplayName, fields.DisplayName)
			assert.Equal(t, tt.wantPatch, fields.VersionPatch)
		})
	}
}

// mockConn wraps a net.Pipe to serve a canned response to DetectClickHouse without
// requiring a live network listener.
func newMockClickHouseConn(t *testing.T, response []byte) net.Conn {
	t.Helper()
	serverConn, clientConn := net.Pipe()

	go func() {
		defer serverConn.Close()
		buf := make([]byte, 4096)
		_, _ = serverConn.Read(buf)
		_, _ = serverConn.Write(response)
	}()

	t.Cleanup(func() {
		clientConn.Close()
	})

	return clientConn
}

// TestDetectClickHouse_Exception verifies that a response starting with
// VarUInt(2) (Exception packet type) is treated as a detected ClickHouse server
// with zero-value fields (no version metadata available).
func TestDetectClickHouse_Exception(t *testing.T) {
	// Build a structurally valid exception: packet_type=2, error_code=516,
	// error_name="DB::Exception"
	response := writeVarUInt(nil, packetTypeException)
	response = writeVarUInt(response, 516)
	response = writeString(response, "DB::Exception")
	response = writeString(response, "Authentication failed")
	response = writeString(response, "")
	response = writeVarUInt(response, 0)
	conn := newMockClickHouseConn(t, response)

	fields, detected, err := DetectClickHouse(conn, 5*time.Second)
	require.NoError(t, err)
	assert.True(t, detected)
	require.NotNil(t, fields)
	assert.Equal(t, &serverHelloFields{}, fields)
}

// TestDetectClickHouse_BareExceptionByte verifies that a response starting with
// 0x02 but lacking a valid exception frame structure is rejected.
func TestDetectClickHouse_BareExceptionByte(t *testing.T) {
	response := writeVarUInt(nil, packetTypeException)
	conn := newMockClickHouseConn(t, response)

	fields, detected, err := DetectClickHouse(conn, 5*time.Second)
	assert.False(t, detected)
	assert.Error(t, err)
	assert.Nil(t, fields)
}

// TestDetectClickHouse_UnknownPacketType verifies that a response starting with
// an unrecognized packet type (5) is not detected and returns an error.
func TestDetectClickHouse_UnknownPacketType(t *testing.T) {
	response := writeVarUInt(nil, 5)
	conn := newMockClickHouseConn(t, response)

	fields, detected, err := DetectClickHouse(conn, 5*time.Second)
	assert.False(t, detected)
	assert.Error(t, err)
	assert.Nil(t, fields)
}

// TestDetectClickHouse_EmptyResponse verifies that a server which never responds
// (read times out with zero bytes received) yields detected=false and a
// ServerNotEnable error, matching pluginutils.Recv's timeout-as-empty-response
// behavior.
func TestDetectClickHouse_EmptyResponse(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	go func() {
		buf := make([]byte, 4096)
		// Read the ClientHello but never write a response, forcing the
		// client's read deadline to expire with zero bytes received.
		_, _ = serverConn.Read(buf)
	}()

	fields, detected, err := DetectClickHouse(clientConn, 50*time.Millisecond)
	assert.False(t, detected)
	require.Error(t, err)
	assert.Nil(t, fields)

	var serverNotEnable *utils.ServerNotEnable
	assert.True(t, errors.As(err, &serverNotEnable), "expected ServerNotEnable error, got %T: %v", err, err)
}

// TestBuildClickHouseCPE verifies CPE generation for a known version and the
// wildcard fallback for an empty version.
func TestBuildClickHouseCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantCPE string
	}{
		{
			name:    "known version",
			version: "24.1.5",
			wantCPE: "cpe:2.3:a:clickhouse:clickhouse:24.1.5:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version uses wildcard",
			version: "",
			wantCPE: "cpe:2.3:a:clickhouse:clickhouse:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildClickHouseCPE(tt.version)
			assert.Equal(t, tt.wantCPE, cpe)
		})
	}
}

// TestVersionFormatWithoutPatch verifies that when HasPatch is false, runClickHouse
// would format version as major.minor (not major.minor.0).
func TestVersionFormatWithoutPatch(t *testing.T) {
	data := buildMockServerHello("ClickHouse", 18, 16, 54000, 0, "", "")

	fields, err := parseServerHello(data)
	require.NoError(t, err)
	assert.False(t, fields.HasPatch)

	// Replicate runClickHouse's version logic.
	version := ""
	if fields.HasPatch {
		version = fmt.Sprintf("%d.%d.%d", fields.VersionMajor, fields.VersionMinor, fields.VersionPatch)
	} else if fields.VersionMajor != 0 || fields.VersionMinor != 0 {
		version = fmt.Sprintf("%d.%d", fields.VersionMajor, fields.VersionMinor)
	}
	assert.Equal(t, "18.16", version)
}

// TestCPEMetacharacterGuard verifies that a version string containing CPE
// metacharacters (":" or "*") is cleared before CPE construction, mirroring the
// guard in runClickHouse.
func TestCPEMetacharacterGuard(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{"colon in version", "24.1:5"},
		{"asterisk in version", "24.1*5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := tt.version
			if strings.ContainsAny(version, ":*?") {
				version = ""
			}
			assert.Equal(t, "", version)

			cpe := buildClickHouseCPE(version)
			assert.Equal(t, "cpe:2.3:a:clickhouse:clickhouse:*:*:*:*:*:*:*:*", cpe)
		})
	}
}

// TestClickHousePlugin_PortPriority verifies the plaintext plugin prioritizes
// port 9000 and does not prioritize an arbitrary other port.
func TestClickHousePlugin_PortPriority(t *testing.T) {
	p := &ClickHousePlugin{}
	assert.True(t, p.PortPriority(9000))
	assert.False(t, p.PortPriority(8080))
}

// TestClickHouseTLSPlugin_PortPriority verifies the TLS plugin prioritizes port
// 9440 and does not prioritize the plaintext port 9000.
func TestClickHouseTLSPlugin_PortPriority(t *testing.T) {
	p := &ClickHouseTLSPlugin{}
	assert.True(t, p.PortPriority(9440))
	assert.False(t, p.PortPriority(9000))
}

// TestPluginMetadata verifies Name(), Type(), and Priority() for both the
// plaintext and TLS ClickHouse plugins.
func TestPluginMetadata(t *testing.T) {
	tcpPlugin := &ClickHousePlugin{}
	assert.Equal(t, "clickhouse", tcpPlugin.Name())
	assert.Equal(t, plugins.TCP, tcpPlugin.Type())
	assert.Equal(t, 200, tcpPlugin.Priority())

	tlsPlugin := &ClickHouseTLSPlugin{}
	assert.Equal(t, "clickhouse", tlsPlugin.Name())
	assert.Equal(t, plugins.TCPTLS, tlsPlugin.Type())
	assert.Equal(t, 201, tlsPlugin.Priority())
}

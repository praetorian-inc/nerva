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

package opcua

import (
	"encoding/binary"
	"math"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	response []byte
	err      error
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}
	copy(b, m.response)
	return len(m.response), nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestOPCUAPlugin_ValidACK(t *testing.T) {
	plugin := &OPCUAPlugin{}

	// Valid ACK response (8 bytes minimum)
	// "ACK" + "F" (final) + 4-byte message size
	validACK := []byte{'A', 'C', 'K', 'F', 0x00, 0x00, 0x00, 0x08}

	conn := &mockConn{response: validACK}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:4840"),
		Host:    "localhost",
	}

	service, err := plugin.Run(conn, time.Second, target)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if service == nil {
		t.Fatal("Expected service to be detected, got nil")
	}

	if service.Protocol != "opcua" {
		t.Errorf("Expected protocol 'opcua', got '%s'", service.Protocol)
	}

	if service.Port != 4840 {
		t.Errorf("Expected port 4840, got %d", service.Port)
	}
}

func TestOPCUAPlugin_InvalidResponse(t *testing.T) {
	plugin := &OPCUAPlugin{}

	// Invalid response (not ACK)
	invalidResponse := []byte{'E', 'R', 'R', 'F', 0x00, 0x00, 0x00, 0x08}

	conn := &mockConn{response: invalidResponse}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:4840"),
		Host:    "localhost",
	}

	service, err := plugin.Run(conn, time.Second, target)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if service != nil {
		t.Errorf("Expected nil service for invalid response, got %+v", service)
	}
}

func TestOPCUAPlugin_MalformedResponse(t *testing.T) {
	plugin := &OPCUAPlugin{}

	// Response too short (less than 8 bytes)
	shortResponse := []byte{'A', 'C', 'K', 'F'}

	conn := &mockConn{response: shortResponse}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:4840"),
		Host:    "localhost",
	}

	service, err := plugin.Run(conn, time.Second, target)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if service != nil {
		t.Errorf("Expected nil service for malformed response, got %+v", service)
	}
}

func TestOPCUAPlugin_EmptyResponse(t *testing.T) {
	plugin := &OPCUAPlugin{}

	// Empty response
	emptyResponse := []byte{}

	conn := &mockConn{response: emptyResponse}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:4840"),
		Host:    "localhost",
	}

	service, err := plugin.Run(conn, time.Second, target)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if service != nil {
		t.Errorf("Expected nil service for empty response, got %+v", service)
	}
}

func TestOPCUAPlugin_PortPriority(t *testing.T) {
	plugin := &OPCUAPlugin{}

	if !plugin.PortPriority(4840) {
		t.Error("Expected port 4840 to have priority")
	}

	if plugin.PortPriority(8080) {
		t.Error("Expected port 8080 to not have priority")
	}
}

func TestOPCUAPlugin_Name(t *testing.T) {
	plugin := &OPCUAPlugin{}

	if plugin.Name() != OPCUA {
		t.Errorf("Expected name %s, got %s", OPCUA, plugin.Name())
	}
}

func TestOPCUAPlugin_Type(t *testing.T) {
	plugin := &OPCUAPlugin{}

	if plugin.Type() != plugins.TCP {
		t.Errorf("Expected type TCP, got %v", plugin.Type())
	}
}

func TestOPCUAPlugin_Priority(t *testing.T) {
	plugin := &OPCUAPlugin{}

	if plugin.Priority() != 400 {
		t.Errorf("Expected priority 400, got %d", plugin.Priority())
	}
}

// ---- checkSecurityModes ----

func TestCheckSecurityModes(t *testing.T) {
	tests := []struct {
		name              string
		modes             []string
		wantCount         int
		wantID            string
		wantSeverity      plugins.Severity
		wantEvidenceContains string
	}{
		{
			name:                 "only None",
			modes:                []string{"None"},
			wantCount:            1,
			wantID:               "opcua-no-security",
			wantSeverity:         plugins.SeverityHigh,
			wantEvidenceContains: "security_modes=None",
		},
		{
			name:                 "None among multiple",
			modes:                []string{"None", "Sign", "SignAndEncrypt"},
			wantCount:            1,
			wantID:               "opcua-weak-security",
			wantSeverity:         plugins.SeverityMedium,
			wantEvidenceContains: "security_modes=None,Sign,SignAndEncrypt",
		},
		{
			name:                 "None and Sign only",
			modes:                []string{"None", "Sign"},
			wantCount:            1,
			wantID:               "opcua-weak-security",
			wantSeverity:         plugins.SeverityMedium,
			wantEvidenceContains: "security_modes=None,Sign",
		},
		{
			name:      "Sign and SignAndEncrypt only",
			modes:     []string{"Sign", "SignAndEncrypt"},
			wantCount: 0,
		},
		{
			name:      "only Sign",
			modes:     []string{"Sign"},
			wantCount: 0,
		},
		{
			name:      "only SignAndEncrypt",
			modes:     []string{"SignAndEncrypt"},
			wantCount: 0,
		},
		{
			name:      "empty slice",
			modes:     []string{},
			wantCount: 0,
		},
		{
			name:      "nil slice",
			modes:     nil,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := checkSecurityModes(tt.modes)
			require.Len(t, findings, tt.wantCount)
			if tt.wantCount == 0 {
				return
			}
			assert.Equal(t, tt.wantID, findings[0].ID)
			assert.Equal(t, tt.wantSeverity, findings[0].Severity)
			assert.Contains(t, findings[0].Evidence, tt.wantEvidenceContains)
		})
	}
}

// ---- deduplicateModes ----

func TestDeduplicateModes(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "duplicates",
			input:    []string{"None", "Sign", "None", "SignAndEncrypt", "Sign"},
			expected: []string{"None", "Sign", "SignAndEncrypt"},
		},
		{
			name:     "already unique",
			input:    []string{"Sign", "SignAndEncrypt"},
			expected: []string{"Sign", "SignAndEncrypt"},
		},
		{
			name:     "single None",
			input:    []string{"None"},
			expected: []string{"None"},
		},
		{
			name:     "empty",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "all same",
			input:    []string{"Sign", "Sign", "Sign"},
			expected: []string{"Sign"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deduplicateModes(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---- buildOpenSecureChannel ----

func TestBuildOpenSecureChannel(t *testing.T) {
	msg := buildOpenSecureChannel()

	require.GreaterOrEqual(t, len(msg), 12, "OPN message must be at least 12 bytes")

	// Header starts with "OPNF"
	assert.Equal(t, []byte("OPN"), msg[0:3], "message type must be OPN")
	assert.Equal(t, byte('F'), msg[3], "chunk type must be F (final)")

	// Bytes 4-7: total message size (uint32 LE) must equal actual length
	msgSize := binary.LittleEndian.Uint32(msg[4:8])
	assert.Equal(t, uint32(len(msg)), msgSize, "declared size must match actual length")

	// Bytes 8-11: channelID must be 0 (initial request)
	channelID := binary.LittleEndian.Uint32(msg[8:12])
	assert.Equal(t, uint32(0), channelID, "channelID must be 0 in initial OPN request")
}

// ---- buildGetEndpoints ----

func TestBuildGetEndpoints(t *testing.T) {
	const wantChannelID = uint32(42)
	msg := buildGetEndpoints(wantChannelID, 7, "opc.tcp://127.0.0.1:4840")

	require.GreaterOrEqual(t, len(msg), 12, "MSG message must be at least 12 bytes")

	// Header starts with "MSGF"
	assert.Equal(t, []byte("MSG"), msg[0:3], "message type must be MSG")
	assert.Equal(t, byte('F'), msg[3], "chunk type must be F (final)")

	// Bytes 4-7: total message size must equal actual length
	msgSize := binary.LittleEndian.Uint32(msg[4:8])
	assert.Equal(t, uint32(len(msg)), msgSize, "declared size must match actual length")

	// Bytes 8-11: channelID must match the input
	channelID := binary.LittleEndian.Uint32(msg[8:12])
	assert.Equal(t, wantChannelID, channelID, "channelID must match the supplied value")
}

// ---- helpers to build minimal valid OPN/MSG responses ----

// buildMinimalOPNResponse constructs a minimal, parseable OPN response with the given
// channelID (in the transport header) and tokenID (in the SecurityToken body).
//
// Layout (all integers are little-endian):
//
//	[0-2]   "OPN"
//	[3]     'F'
//	[4-7]   totalSize (uint32)
//	[8-11]  channelID (uint32)
//	-- Asymmetric security header --
//	PolicyURI: int32(-1) = null string
//	SenderCert: int32(-1) = null
//	ReceiverThumb: int32(-1) = null
//	-- Sequence header --
//	seqNum: uint32(1)
//	requestId: uint32(1)
//	-- Body --
//	TypeId: TwoByte NodeId encoding=0x00, id=0x00  (2 bytes)
//	ResponseHeader:
//	  Timestamp(8) + RequestHandle(4) + ServiceResult(4) + DiagnosticInfo mask(1=0x00) +
//	  StringTable count int32(-1) + ExtensionObject TwoByte NodeId(1) + encoding(1)
//	ServerProtocolVersion: uint32(0)
//	SecurityToken:
//	  ChannelId: uint32(channelID)
//	  TokenId:   uint32(tokenID)
func buildMinimalOPNResponse(channelID, tokenID uint32) []byte {
	body := make([]byte, 0, 128)

	// Asymmetric security header: all three fields null
	body = appendInt32(body, -1) // PolicyURI: null string
	body = appendInt32(body, -1) // SenderCert: null
	body = appendInt32(body, -1) // ReceiverThumb: null

	// Sequence header
	body = appendUint32(body, 1) // seqNum
	body = appendUint32(body, 1) // requestId

	// TypeId: TwoByte NodeId (encoding=0x00, id=0x00)
	body = append(body, 0x00) // encoding TwoByte
	body = append(body, 0x00) // identifier

	// ResponseHeader:
	//   Timestamp (int64 = 0)
	body = appendInt64(body, 0)
	//   RequestHandle (uint32 = 0)
	body = appendUint32(body, 0)
	//   ServiceResult (uint32 = 0)
	body = appendUint32(body, 0)
	//   DiagnosticInfo mask (0x00 = no flags)
	body = append(body, 0x00)
	//   StringTable: int32(-1) = null array
	body = appendInt32(body, -1)
	//   AdditionalHeader ExtensionObject: TwoByte NodeId + encoding=0x00
	body = append(body, 0x00) // TwoByte NodeId encoding
	body = append(body, 0x00) // identifier
	body = append(body, 0x00) // ExtensionObject encoding = no body

	// ServerProtocolVersion
	body = appendUint32(body, 0)

	// SecurityToken
	body = appendUint32(body, channelID) // ChannelId
	body = appendUint32(body, tokenID)   // TokenId
	// (we don't need CreatedAt or RevisedLifetime — parser stops after reading TokenId)

	// OPN transport header
	totalSize := 4 + 4 + 4 + len(body) // "OPN"+'F' + size(4) + channelID(4) + body
	msg := make([]byte, 0, totalSize)
	msg = append(msg, []byte("OPN")...)
	msg = append(msg, 'F')
	msg = appendUint32(msg, uint32(totalSize))
	msg = appendUint32(msg, channelID)
	msg = append(msg, body...)
	return msg
}

// buildMinimalEndpoint builds a single EndpointDescription byte sequence with the given
// MessageSecurityMode value (1=None, 2=Sign, 3=SignAndEncrypt).
func buildMinimalEndpoint(mode uint32) []byte {
	ep := make([]byte, 0, 64)

	// EndpointUrl: null string
	ep = appendInt32(ep, -1)

	// Server (ApplicationDescription):
	//   ApplicationUri: null
	ep = appendInt32(ep, -1)
	//   ProductUri: null
	ep = appendInt32(ep, -1)
	//   ApplicationName: LocalizedText mask=0x00 (empty)
	ep = append(ep, 0x00)
	//   ApplicationType: uint32 = 0
	ep = appendUint32(ep, 0)
	//   GatewayServerUri: null
	ep = appendInt32(ep, -1)
	//   DiscoveryProfileUri: null
	ep = appendInt32(ep, -1)
	//   DiscoveryUrls: null array (int32=-1)
	ep = appendInt32(ep, -1)

	// ServerCertificate: null
	ep = appendInt32(ep, -1)

	// MessageSecurityMode: uint32
	ep = appendUint32(ep, mode)

	// SecurityPolicyUri: null
	ep = appendInt32(ep, -1)

	// UserIdentityTokens: null array
	ep = appendInt32(ep, -1)

	// TransportProfileUri: null
	ep = appendInt32(ep, -1)

	// SecurityLevel: byte
	ep = append(ep, 0x00)

	return ep
}

// buildMinimalMSGResponse constructs a minimal, parseable GetEndpoints MSG response
// containing endpoints with the given security mode values.
func buildMinimalMSGResponse(channelID, tokenID uint32, modes []uint32) []byte {
	body := make([]byte, 0, 256)

	// Symmetric security header: tokenID(4)
	body = appendUint32(body, tokenID)

	// Sequence header
	body = appendUint32(body, 2) // seqNum
	body = appendUint32(body, 2) // requestId

	// TypeId: TwoByte NodeId
	body = append(body, 0x00) // encoding TwoByte
	body = append(body, 0x00) // identifier

	// ResponseHeader (same minimal layout as OPN)
	body = appendInt64(body, 0)  // Timestamp
	body = appendUint32(body, 0) // RequestHandle
	body = appendUint32(body, 0) // ServiceResult
	body = append(body, 0x00)    // DiagnosticInfo mask
	body = appendInt32(body, -1) // StringTable: null
	body = append(body, 0x00)    // ExtensionObject TwoByte NodeId
	body = append(body, 0x00)    // ExtensionObject identifier
	body = append(body, 0x00)    // ExtensionObject encoding

	// Endpoints array count
	body = appendInt32(body, int32(len(modes)))
	for _, m := range modes {
		body = append(body, buildMinimalEndpoint(m)...)
	}

	// MSG transport header: "MSG"+'F' + totalSize(4) + channelID(4)
	totalSize := 4 + 4 + 4 + len(body)
	msg := make([]byte, 0, totalSize)
	msg = append(msg, []byte("MSG")...)
	msg = append(msg, 'F')
	msg = appendUint32(msg, uint32(totalSize))
	msg = appendUint32(msg, channelID)
	msg = append(msg, body...)
	return msg
}

// ---- parseOpenSecureChannelResponse ----

func TestParseOpenSecureChannelResponse(t *testing.T) {
	t.Run("valid response extracts channelID and tokenID", func(t *testing.T) {
		const wantChannelID = uint32(1)
		const wantTokenID = uint32(99)

		data := buildMinimalOPNResponse(wantChannelID, wantTokenID)
		channelID, tokenID, err := parseOpenSecureChannelResponse(data)

		require.NoError(t, err)
		assert.Equal(t, wantChannelID, channelID)
		assert.Equal(t, wantTokenID, tokenID)
	})

	t.Run("too-short data returns error", func(t *testing.T) {
		_, _, err := parseOpenSecureChannelResponse([]byte("OPN\x00\x00\x00"))
		assert.Error(t, err)
	})

	t.Run("wrong message type returns error", func(t *testing.T) {
		data := buildMinimalOPNResponse(1, 1)
		// Overwrite message type with "MSG"
		copy(data[0:3], []byte("MSG"))
		_, _, err := parseOpenSecureChannelResponse(data)
		assert.Error(t, err)
	})
}

// ---- parseGetEndpointsResponse ----

func TestParseGetEndpointsResponse(t *testing.T) {
	t.Run("endpoints with known modes", func(t *testing.T) {
		// modes: None(1), Sign(2), SignAndEncrypt(3)
		data := buildMinimalMSGResponse(1, 1, []uint32{1, 2, 3})
		modes, err := parseGetEndpointsResponse(data)

		require.NoError(t, err)
		require.Len(t, modes, 3)
		assert.Equal(t, "None", modes[0])
		assert.Equal(t, "Sign", modes[1])
		assert.Equal(t, "SignAndEncrypt", modes[2])
	})

	t.Run("null array returns nil", func(t *testing.T) {
		// Build a MSG with count=-1 (null array)
		body := make([]byte, 0, 64)
		body = appendUint32(body, 1)    // tokenID
		body = appendUint32(body, 2)    // seqNum
		body = appendUint32(body, 2)    // requestId
		body = append(body, 0x00, 0x00) // TwoByte NodeId
		body = appendInt64(body, 0)     // Timestamp
		body = appendUint32(body, 0)    // RequestHandle
		body = appendUint32(body, 0)    // ServiceResult
		body = append(body, 0x00)       // DiagnosticInfo mask
		body = appendInt32(body, -1)    // StringTable null
		body = append(body, 0x00, 0x00, 0x00) // ExtensionObject
		body = appendInt32(body, -1)    // null array count

		totalSize := 4 + 4 + 4 + len(body)
		msg := make([]byte, 0, totalSize)
		msg = append(msg, []byte("MSG")...)
		msg = append(msg, 'F')
		msg = appendUint32(msg, uint32(totalSize))
		msg = appendUint32(msg, 1)
		msg = append(msg, body...)

		modes, err := parseGetEndpointsResponse(msg)
		require.NoError(t, err)
		assert.Nil(t, modes)
	})

	t.Run("too-short data returns error", func(t *testing.T) {
		_, err := parseGetEndpointsResponse([]byte("MSG\x00\x00\x00"))
		assert.Error(t, err)
	})

	t.Run("wrong message type returns error", func(t *testing.T) {
		data := buildMinimalMSGResponse(1, 1, []uint32{1})
		copy(data[0:3], []byte("OPN"))
		_, err := parseGetEndpointsResponse(data)
		assert.Error(t, err)
	})
}

// ---- integration tests via Run() with net.Pipe() ----

// buildServerHandshake writes an ACK response, then reads OPN and writes a
// minimal OPN response, then reads MSG and writes a minimal MSG response.
// It runs in a goroutine. modes contains the MessageSecurityMode values to
// include in the GetEndpoints response.
func runMockOPCUAServer(t *testing.T, server net.Conn, modes []uint32) {
	t.Helper()
	defer server.Close()

	buf := make([]byte, 4096)

	// 1. Read HEL → send ACK
	n, err := server.Read(buf)
	if err != nil || n == 0 {
		return
	}
	ack := []byte{'A', 'C', 'K', 'F', 0x08, 0x00, 0x00, 0x00}
	if _, err = server.Write(ack); err != nil {
		return
	}

	// 2. Read OPN → send OPN response (channelID=1, tokenID=1)
	opnResp := buildMinimalOPNResponse(1, 1)
	// Prefix with the 8-byte readOPCUAMessage header fields already embedded.
	// readOPCUAMessage reads the header then the body; our builder embeds it all.
	n, err = server.Read(buf)
	if err != nil || n == 0 {
		return
	}
	if _, err = server.Write(opnResp); err != nil {
		return
	}

	// 3. Read MSG (GetEndpoints) → send MSG response
	n, err = server.Read(buf)
	if err != nil || n == 0 {
		return
	}
	msgResp := buildMinimalMSGResponse(1, 1, modes)
	_, _ = server.Write(msgResp)
}

func TestOPCUASecurityFindingsMisconfigs(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	// modes: None(1), Sign(2), SignAndEncrypt(3) → expect opcua-weak-security
	go runMockOPCUAServer(t, server, []uint32{1, 2, 3})

	plugin := &OPCUAPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:4840"),
		Host:       "localhost",
		Misconfigs: true,
	}

	service, err := plugin.Run(client, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)
	require.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "opcua-weak-security", service.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityMedium, service.SecurityFindings[0].Severity)
}

func TestOPCUASecurityFindingsDisabled(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	// Server just needs to ACK; Misconfigs=false means no GetEndpoints exchange.
	go func() {
		defer server.Close()
		buf := make([]byte, 1024)
		n, _ := server.Read(buf)
		if n == 0 {
			return
		}
		ack := []byte{'A', 'C', 'K', 'F', 0x08, 0x00, 0x00, 0x00}
		_, _ = server.Write(ack)
	}()

	plugin := &OPCUAPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:4840"),
		Host:       "localhost",
		Misconfigs: false,
	}

	service, err := plugin.Run(client, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)
	assert.Empty(t, service.SecurityFindings)
}

// TestOPCUASecurityFindingsNoneOnly uses net.Pipe integration to verify that
// a server advertising only SecurityMode None produces the "opcua-no-security"
// high-severity finding.
func TestOPCUASecurityFindingsNoneOnly(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	// modes: None(1) only → expect opcua-no-security
	go runMockOPCUAServer(t, server, []uint32{1})

	plugin := &OPCUAPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:4840"),
		Host:       "localhost",
		Misconfigs: true,
	}

	service, err := plugin.Run(client, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)
	require.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "opcua-no-security", service.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityHigh, service.SecurityFindings[0].Severity)
}

// TestReadOPCUAMessageErrors tests readOPCUAMessage error paths using net.Pipe.
func TestReadOPCUAMessageErrors(t *testing.T) {
	tests := []struct {
		name        string
		header      []byte
		errContains string
	}{
		{
			name: "message exceeds size limit",
			// size field = 1MiB + 1 (exceeds limit)
			header: func() []byte {
				h := make([]byte, 8)
				copy(h[0:4], []byte("OPN\x46")) // "OPNF"
				// 1<<20 + 1 = 1048577
				h[4] = 0x01
				h[5] = 0x00
				h[6] = 0x10
				h[7] = 0x00
				return h
			}(),
			errContains: "exceeds",
		},
		{
			name: "message size smaller than header",
			// size field = 4 (< 8)
			header: func() []byte {
				h := make([]byte, 8)
				copy(h[0:4], []byte("OPN\x46"))
				h[4] = 0x04
				h[5] = 0x00
				h[6] = 0x00
				h[7] = 0x00
				return h
			}(),
			errContains: "smaller than header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()

			go func() {
				defer server.Close()
				_, _ = server.Write(tt.header)
			}()

			_, err := readOPCUAMessage(client, 5*time.Second)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

// TestParseGetEndpointsResponseArrayLimit verifies that an endpoint count
// exceeding maxArrayElements returns an error containing "exceeds limit".
func TestParseGetEndpointsResponseArrayLimit(t *testing.T) {
	// Build a MSG body where the endpoints count = maxArrayElements + 1.
	body := make([]byte, 0, 64)
	body = appendUint32(body, 1)    // tokenID
	body = appendUint32(body, 2)    // seqNum
	body = appendUint32(body, 2)    // requestId
	body = append(body, 0x00, 0x00) // TwoByte NodeId TypeId
	body = appendInt64(body, 0)     // Timestamp
	body = appendUint32(body, 0)    // RequestHandle
	body = appendUint32(body, 0)    // ServiceResult
	body = append(body, 0x00)       // DiagnosticInfo mask (no flags)
	body = appendInt32(body, -1)    // StringTable: null array
	body = append(body, 0x00)       // ExtensionObject: TwoByte NodeId
	body = append(body, 0x00)       // ExtensionObject: identifier
	body = append(body, 0x00)       // ExtensionObject: encoding (no body)
	// Endpoints count = maxArrayElements + 1
	body = appendInt32(body, int32(maxArrayElements+1))

	totalSize := 4 + 4 + 4 + len(body)
	msg := make([]byte, 0, totalSize)
	msg = append(msg, []byte("MSG")...)
	msg = append(msg, 'F')
	msg = appendUint32(msg, uint32(totalSize))
	msg = appendUint32(msg, 1) // channelID
	msg = append(msg, body...)

	_, err := parseGetEndpointsResponse(msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds limit")
}

// TestReadEndpointSecurityModeUnknown verifies that mode value 0 (Invalid) and
// mode value 99 (unknown) both parse successfully and return an empty string.
func TestReadEndpointSecurityModeUnknown(t *testing.T) {
	for _, mode := range []uint32{0, 99} {
		data := buildMinimalEndpoint(mode)
		r := &opcuaReader{data: data, pos: 0}
		m, err := r.readEndpointSecurityMode()
		require.NoError(t, err)
		assert.Equal(t, "", m)
	}
}

// TestSkipNodeIdEncodings tests skipNodeId for each of the 6 valid encoding types
// and for an unknown encoding type.
func TestSkipNodeIdEncodings(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantPos     int
		wantErr     bool
		errContains string
	}{
		{
			name:    "TwoByte (0x00)",
			data:    []byte{0x00, 0x00},
			wantPos: 2,
		},
		{
			name:    "FourByte (0x01)",
			data:    []byte{0x01, 0x00, 0x00, 0x00},
			wantPos: 4,
		},
		{
			name:    "Numeric (0x02)",
			data:    []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantPos: 7,
		},
		{
			name: "String (0x03) with null string",
			// encoding(1) + namespace(2) + length(-1 as 4 bytes LE) = 7
			data:    []byte{0x03, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},
			wantPos: 7,
		},
		{
			name: "GUID (0x04)",
			// encoding(1) + namespace(2) + 16 bytes GUID = 19
			data:    append([]byte{0x04}, make([]byte, 18)...),
			wantPos: 19,
		},
		{
			name: "ByteString (0x05) with null bytestring",
			// encoding(1) + namespace(2) + length(-1 as 4 bytes LE) = 7
			data:    []byte{0x05, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF},
			wantPos: 7,
		},
		{
			name:        "unknown encoding (0x06)",
			data:        []byte{0x06, 0x00},
			wantErr:     true,
			errContains: "unknown NodeId encoding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &opcuaReader{data: tt.data, pos: 0}
			err := r.skipNodeId()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantPos, r.pos)
			}
		})
	}
}

// TestSkipDiagnosticInfoDepthLimit verifies that deeply nested DiagnosticInfo
// structures exceeding maxDiagnosticDepth return an error containing "nesting exceeds limit".
func TestSkipDiagnosticInfoDepthLimit(t *testing.T) {
	// Build 33 bytes each with mask=0x40 (inner diagnostic info flag).
	// skipDiagnosticInfoDepth(0) reads byte 0 (0x40), recurses with depth=1,
	// ...skipDiagnosticInfoDepth(32) reads byte 32 (0x40), recurses with depth=33,
	// which triggers depth > maxDiagnosticDepth (33 > 32) → error.
	data := make([]byte, maxDiagnosticDepth+1)
	for i := range data {
		data[i] = 0x40
	}

	r := &opcuaReader{data: data, pos: 0}
	err := r.skipDiagnosticInfo()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nesting exceeds limit")
}

// buildEndpointWithTokenPolicy builds an EndpointDescription with one UserTokenPolicy entry.
func buildEndpointWithTokenPolicy(mode uint32) []byte {
	ep := make([]byte, 0, 128)

	// EndpointUrl: null string
	ep = appendInt32(ep, -1)

	// Server (ApplicationDescription):
	ep = appendInt32(ep, -1) // ApplicationUri: null
	ep = appendInt32(ep, -1) // ProductUri: null
	ep = append(ep, 0x00)    // ApplicationName: LocalizedText mask=0x00 (empty)
	ep = appendUint32(ep, 0) // ApplicationType: uint32 = 0
	ep = appendInt32(ep, -1) // GatewayServerUri: null
	ep = appendInt32(ep, -1) // DiscoveryProfileUri: null
	ep = appendInt32(ep, -1) // DiscoveryUrls: null array

	// ServerCertificate: null
	ep = appendInt32(ep, -1)

	// MessageSecurityMode: uint32
	ep = appendUint32(ep, mode)

	// SecurityPolicyUri: null
	ep = appendInt32(ep, -1)

	// UserIdentityTokens: array with count=1
	ep = appendInt32(ep, 1)
	// One UserTokenPolicy: PolicyId(null) + TokenType(0) + IssuedTokenType(null) + IssuerEndpointUrl(null) + SecurityPolicyUri(null)
	ep = appendInt32(ep, -1) // PolicyId: null
	ep = appendUint32(ep, 0) // TokenType: 0
	ep = appendInt32(ep, -1) // IssuedTokenType: null
	ep = appendInt32(ep, -1) // IssuerEndpointUrl: null
	ep = appendInt32(ep, -1) // SecurityPolicyUri: null

	// TransportProfileUri: null
	ep = appendInt32(ep, -1)

	// SecurityLevel: byte
	ep = append(ep, 0x00)

	return ep
}

// TestOPCUASecurityFindingsEndpointWithUserTokenPolicies verifies that endpoints
// containing UserTokenPolicy entries are parsed correctly and the security mode
// is extracted accurately.
func TestOPCUASecurityFindingsEndpointWithUserTokenPolicies(t *testing.T) {
	// Build a MSG response using endpoints that have one UserTokenPolicy each.
	modes := []uint32{2, 3} // Sign, SignAndEncrypt

	body := make([]byte, 0, 256)
	body = appendUint32(body, 1)    // tokenID
	body = appendUint32(body, 2)    // seqNum
	body = appendUint32(body, 2)    // requestId
	body = append(body, 0x00, 0x00) // TwoByte NodeId TypeId
	body = appendInt64(body, 0)     // Timestamp
	body = appendUint32(body, 0)    // RequestHandle
	body = appendUint32(body, 0)    // ServiceResult
	body = append(body, 0x00)       // DiagnosticInfo mask
	body = appendInt32(body, -1)    // StringTable: null
	body = append(body, 0x00)       // ExtensionObject TwoByte NodeId
	body = append(body, 0x00)       // ExtensionObject identifier
	body = append(body, 0x00)       // ExtensionObject encoding
	body = appendInt32(body, int32(len(modes)))
	for _, m := range modes {
		body = append(body, buildEndpointWithTokenPolicy(m)...)
	}

	totalSize := 4 + 4 + 4 + len(body)
	msg := make([]byte, 0, totalSize)
	msg = append(msg, []byte("MSG")...)
	msg = append(msg, 'F')
	msg = appendUint32(msg, uint32(totalSize))
	msg = appendUint32(msg, 1) // channelID
	msg = append(msg, body...)

	parsedModes, err := parseGetEndpointsResponse(msg)
	require.NoError(t, err)
	require.Len(t, parsedModes, 2)
	assert.Equal(t, "Sign", parsedModes[0])
	assert.Equal(t, "SignAndEncrypt", parsedModes[1])
}

// TestSkipByteStringWithBody verifies skipByteString reads a non-null byte string correctly.
func TestSkipByteStringWithBody(t *testing.T) {
	// 4-byte length (3) + 3 bytes of content
	data := []byte{0x03, 0x00, 0x00, 0x00, 'a', 'b', 'c'}
	r := &opcuaReader{data: data, pos: 0}
	err := r.skipByteString()
	require.NoError(t, err)
	assert.Equal(t, 7, r.pos)
}

// TestSkipLocalizedTextWithLocaleAndText exercises the locale and text branches of skipLocalizedText.
func TestSkipLocalizedTextWithLocaleAndText(t *testing.T) {
	// mask = 0x03: both locale (bit0) and text (bit1) present.
	// locale: length=2 + "en"; text: length=5 + "hello"
	data := make([]byte, 0, 20)
	data = append(data, 0x03) // mask
	data = appendInt32(data, 2)
	data = append(data, 'e', 'n')
	data = appendInt32(data, 5)
	data = append(data, 'h', 'e', 'l', 'l', 'o')

	r := &opcuaReader{data: data, pos: 0}
	err := r.skipLocalizedText()
	require.NoError(t, err)
	assert.Equal(t, len(data), r.pos)
}

// TestSkipDiagnosticInfoAllFlags exercises all flag branches of skipDiagnosticInfoDepth
// by setting flags 0x01..0x3F (all except the inner-diagnostic 0x40 flag).
func TestSkipDiagnosticInfoAllFlags(t *testing.T) {
	// Flags: symbolic id(0x01) + namespace uri(0x02) + locale(0x04) + localized text(0x08)
	//        + additional info string(0x10) + inner status code(0x20)
	// Each flag 0x01..0x20 adds 4 bytes except 0x10 (skipByteString: 4-byte length).
	// We set mask = 0x3F and provide:
	//   4 bytes (symbolic id) + 4 (namespace) + 4 (locale) + 4 (localized text) + 4+0 (additional info: null) + 4 (inner status)
	mask := byte(0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20)
	data := make([]byte, 0, 32)
	data = append(data, mask)
	data = appendUint32(data, 0) // symbolic id
	data = appendUint32(data, 0) // namespace uri
	data = appendUint32(data, 0) // locale
	data = appendUint32(data, 0) // localized text
	data = appendInt32(data, -1) // additional info: null string
	data = appendUint32(data, 0) // inner status code

	r := &opcuaReader{data: data, pos: 0}
	err := r.skipDiagnosticInfo()
	require.NoError(t, err)
	assert.Equal(t, len(data), r.pos)
}

// TestSkipExtensionObjectWithBody exercises the body-present branch of skipExtensionObject.
func TestSkipExtensionObjectWithBody(t *testing.T) {
	// NodeId: TwoByte (encoding=0x00, id=0x01) + encoding=0x01 (ByteString body) + length=3 + body
	data := make([]byte, 0, 16)
	data = append(data, 0x00) // NodeId: TwoByte encoding
	data = append(data, 0x01) // NodeId: identifier
	data = append(data, 0x01) // ExtensionObject encoding: ByteString body
	data = appendInt32(data, 3)
	data = append(data, 'a', 'b', 'c')

	r := &opcuaReader{data: data, pos: 0}
	err := r.skipExtensionObject()
	require.NoError(t, err)
	assert.Equal(t, len(data), r.pos)
}

// TestParseOPNTruncatedCases covers truncated-data error paths in parseOpenSecureChannelResponse.
func TestParseOPNTruncatedCases(t *testing.T) {
	// Build a valid OPN response and truncate at different points to trigger each error path.
	full := buildMinimalOPNResponse(1, 99)

	// Truncate before TokenId (remove last 4 bytes so TokenId is missing).
	truncated := full[:len(full)-4]
	_, _, err := parseOpenSecureChannelResponse(truncated)
	require.Error(t, err)
}

// TestParseGetEndpointsTruncatedCases covers truncated MSG responses.
func TestParseGetEndpointsTruncatedCases(t *testing.T) {
	full := buildMinimalMSGResponse(1, 1, []uint32{2})

	// Truncate just before the endpoints count field so we hit "MSG truncated before endpoints count".
	// The count field starts after: header(12) + tokenID(4) + seqHdr(8) + TypeId(2) + ResponseHeader.
	// ResponseHeader: Timestamp(8)+RequestHandle(4)+ServiceResult(4)+DiagnosticMask(1)+StringTableCount(4)+ExtObj(3) = 24 bytes.
	// Total before count = 12 + 4 + 8 + 2 + 24 = 50. Truncate to 50.
	if len(full) > 50 {
		truncated := full[:50]
		_, err := parseGetEndpointsResponse(truncated)
		require.Error(t, err)
	}
}

// TestSkipOverflow verifies that skip() with a very large n returns an error
// rather than overflowing or panicking.
func TestSkipOverflow(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	r := &opcuaReader{data: data, pos: 0}
	err := r.skip(math.MaxInt)
	require.Error(t, err)
}

// TestSkipNegative verifies that skip() with a negative n returns an error.
func TestSkipNegative(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03}
	r := &opcuaReader{data: data, pos: 0}
	err := r.skip(-1)
	require.Error(t, err)
}

// TestReadEndpointSecurityModeTruncatedAfterMode verifies that an endpoint
// truncated after MessageSecurityMode (before SecurityPolicyUri) returns an error.
func TestReadEndpointSecurityModeTruncatedAfterMode(t *testing.T) {
	// Build a partial endpoint that stops immediately after the MessageSecurityMode uint32.
	ep := make([]byte, 0, 32)
	ep = appendInt32(ep, -1)  // EndpointUrl: null
	ep = appendInt32(ep, -1)  // ApplicationUri: null
	ep = appendInt32(ep, -1)  // ProductUri: null
	ep = append(ep, 0x00)     // ApplicationName: LocalizedText mask
	ep = appendUint32(ep, 0)  // ApplicationType
	ep = appendInt32(ep, -1)  // GatewayServerUri: null
	ep = appendInt32(ep, -1)  // DiscoveryProfileUri: null
	ep = appendInt32(ep, -1)  // DiscoveryUrls: null array
	ep = appendInt32(ep, -1)  // ServerCertificate: null
	ep = appendUint32(ep, 1)  // MessageSecurityMode = None
	// Truncated here — no SecurityPolicyUri, no UserIdentityTokens, etc.

	r := &opcuaReader{data: ep, pos: 0}
	_, err := r.readEndpointSecurityMode()
	require.Error(t, err)
}

// TestSkipNodeIdNamespaceURIFlag verifies that skipNodeId correctly skips the
// NamespaceURI string when bit 6 (0x40) is set in the encoding byte.
func TestSkipNodeIdNamespaceURIFlag(t *testing.T) {
	// TwoByte base (0x00) | NamespaceURI flag (0x40) = 0x40
	// Layout: encoding(1) + TwoByte id(1) + NamespaceURI null string (int32=-1, 4 bytes) = 6 bytes total
	data := make([]byte, 0, 8)
	data = append(data, 0x40)    // encoding byte: TwoByte + NamespaceURI flag
	data = append(data, 0x00)    // TwoByte identifier
	data = appendInt32(data, -1) // NamespaceURI: null string

	r := &opcuaReader{data: data, pos: 0}
	err := r.skipNodeId()
	require.NoError(t, err)
	assert.Equal(t, 6, r.pos)
}

// TestSkipNodeIdServerIndexFlag verifies that skipNodeId correctly skips the
// ServerIndex uint32 when bit 7 (0x80) is set in the encoding byte.
func TestSkipNodeIdServerIndexFlag(t *testing.T) {
	// TwoByte base (0x00) | ServerIndex flag (0x80) = 0x80
	// Layout: encoding(1) + TwoByte id(1) + ServerIndex uint32(4) = 6 bytes total
	data := make([]byte, 0, 8)
	data = append(data, 0x80)    // encoding byte: TwoByte + ServerIndex flag
	data = append(data, 0x00)    // TwoByte identifier
	data = appendUint32(data, 7) // ServerIndex = 7

	r := &opcuaReader{data: data, pos: 0}
	err := r.skipNodeId()
	require.NoError(t, err)
	assert.Equal(t, 6, r.pos)
}

// TestSkipNodeIdBothFlags verifies that skipNodeId correctly handles both
// NamespaceURI (bit 6) and ServerIndex (bit 7) flags simultaneously.
func TestSkipNodeIdBothFlags(t *testing.T) {
	// TwoByte base (0x00) | both flags (0xC0) = 0xC0
	// Layout: encoding(1) + TwoByte id(1) + NamespaceURI null string(4) + ServerIndex uint32(4) = 10 bytes
	data := make([]byte, 0, 12)
	data = append(data, 0xC0)    // encoding byte: TwoByte + both flags
	data = append(data, 0x00)    // TwoByte identifier
	data = appendInt32(data, -1) // NamespaceURI: null string
	data = appendUint32(data, 5) // ServerIndex = 5

	r := &opcuaReader{data: data, pos: 0}
	err := r.skipNodeId()
	require.NoError(t, err)
	assert.Equal(t, 10, r.pos)
}

// TestBuildCloseSecureChannel verifies that buildCloseSecureChannel produces a
// well-formed CLO message with the correct header fields.
func TestBuildCloseSecureChannel(t *testing.T) {
	const wantChannelID = uint32(42)
	const wantTokenID = uint32(7)
	msg := buildCloseSecureChannel(wantChannelID, wantTokenID)

	require.GreaterOrEqual(t, len(msg), 12, "CLO message must be at least 12 bytes")

	// Header starts with "CLO" + 'F'
	assert.Equal(t, []byte("CLO"), msg[0:3], "message type must be CLO")
	assert.Equal(t, byte('F'), msg[3], "chunk type must be F (final)")

	// Bytes 4-7: total message size must equal actual length
	msgSize := binary.LittleEndian.Uint32(msg[4:8])
	assert.Equal(t, uint32(len(msg)), msgSize, "declared size must match actual length")

	// Bytes 8-11: channelID must match the input
	channelID := binary.LittleEndian.Uint32(msg[8:12])
	assert.Equal(t, wantChannelID, channelID, "channelID must match the supplied value")
}

// TestSkipResponseHeaderWithStringTable exercises the StringTable array branch.
func TestSkipResponseHeaderWithStringTable(t *testing.T) {
	// Build a ResponseHeader with a StringTable containing two non-null strings.
	data := make([]byte, 0, 64)
	data = appendInt64(data, 0)  // Timestamp
	data = appendUint32(data, 0) // RequestHandle
	data = appendUint32(data, 0) // ServiceResult
	data = append(data, 0x00)    // DiagnosticInfo mask (no flags)
	// StringTable: count=2
	data = appendInt32(data, 2)
	data = appendInt32(data, 3)
	data = append(data, 'f', 'o', 'o')
	data = appendInt32(data, 3)
	data = append(data, 'b', 'a', 'r')
	// ExtensionObject: TwoByte NodeId + encoding=0x00
	data = append(data, 0x00, 0x00, 0x00)

	r := &opcuaReader{data: data, pos: 0}
	err := r.skipResponseHeader()
	require.NoError(t, err)
	assert.Equal(t, len(data), r.pos)
}

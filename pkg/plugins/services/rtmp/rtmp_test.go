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

package rtmp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockConn struct {
	data []byte
	pos  int
}

func newMockConn(data []byte) *mockConn {
	return &mockConn{data: data}
}

func (c *mockConn) Read(b []byte) (n int, err error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	n = copy(b, c.data[c.pos:])
	c.pos += n
	return n, nil
}

func (c *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (c *mockConn) Close() error                       { return nil }
func (c *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *mockConn) SetDeadline(t time.Time) error      { return nil }
func (c *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestRTMPPlugin_Name(t *testing.T) {
	p := &RTMPPlugin{}
	assert.Equal(t, "rtmp", p.Name())
}

func TestRTMPPlugin_PortPriority(t *testing.T) {
	p := &RTMPPlugin{}
	assert.True(t, p.PortPriority(1935))
	assert.False(t, p.PortPriority(80))
	assert.False(t, p.PortPriority(443))
}

func TestRTMPPlugin_Detect_FullS0S1(t *testing.T) {
	// S0 (version 3) + S1 (1536 bytes)
	response := make([]byte, 1+1536)
	response[0] = 0x03

	conn := newMockConn(response)
	p := &RTMPPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, "rtmp", svc.Protocol)
}

func TestRTMPPlugin_Detect_PartialS1(t *testing.T) {
	// S0 + partial S1 (only 100 bytes received)
	response := make([]byte, 101)
	response[0] = 0x03

	conn := newMockConn(response)
	p := &RTMPPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, "rtmp", svc.Protocol)
}

func TestRTMPPlugin_Reject_WrongVersion(t *testing.T) {
	response := make([]byte, 1537)
	response[0] = 0x06 // Not version 3

	conn := newMockConn(response)
	p := &RTMPPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestRTMPPlugin_Reject_TooShort(t *testing.T) {
	// Only 5 bytes (need at least 9)
	response := []byte{0x03, 0x00, 0x00, 0x00, 0x00}

	conn := newMockConn(response)
	p := &RTMPPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestRTMPPlugin_Reject_HTTP(t *testing.T) {
	response := []byte("HTTP/1.1 200 OK\r\n")

	conn := newMockConn(response)
	p := &RTMPPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestRTMPPlugin_Reject_SSH(t *testing.T) {
	response := []byte("SSH-2.0-OpenSSH_8.9\r\n")

	conn := newMockConn(response)
	p := &RTMPPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestRTMPPlugin_Reject_Empty(t *testing.T) {
	conn := newMockConn([]byte{})
	p := &RTMPPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestRTMPSecurityFindings(t *testing.T) {
	tests := []struct {
		name             string
		misconfigs       bool
		responseLen      int    // how many bytes to return for initial handshake (0=short)
		connectResponse  []byte // response to C2+connect (nil=close)
		wantService      bool
		wantAnonymous    bool
		wantFindingCount int
		wantFindingID    string
		wantFindingSev   plugins.Severity
	}{
		{
			name:        "misconfigs enabled, connect succeeds => finding",
			misconfigs:  true,
			responseLen: 1537, // full S0+S1
			// Server response containing _result (window ack + _result embedded in RTMP chunks)
			connectResponse: buildMockConnectSuccessResponse(),
			wantService:      true,
			wantAnonymous:    true,
			wantFindingCount: 1,
			wantFindingID:    "rtmp-unauthenticated-stream",
			wantFindingSev:   plugins.SeverityMedium,
		},
		{
			name:            "misconfigs enabled, connect rejected => no finding",
			misconfigs:      true,
			responseLen:     1537,
			connectResponse: nil, // server closes connection (auth rejection)
			wantService:     true,
			wantAnonymous:   false,
			wantFindingCount: 0,
		},
		{
			name:            "misconfigs enabled, short handshake => no probe, no finding",
			misconfigs:      true,
			responseLen:     100, // less than 1537, plugin won't attempt connect
			wantService:     true,
			wantAnonymous:   false,
			wantFindingCount: 0,
		},
		{
			name:            "misconfigs disabled => no finding",
			misconfigs:      false,
			responseLen:     1537,
			wantService:     true,
			wantAnonymous:   false,
			wantFindingCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start a TCP listener
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()

			tcpAddr := listener.Addr().(*net.TCPAddr)
			serverPort := tcpAddr.Port

			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()

				// Read C0+C1 from client
				buf := make([]byte, 4096)
				_, _ = conn.Read(buf)

				// Build S0+S1 response
				resp := make([]byte, tt.responseLen)
				resp[0] = 0x03 // S0 = version 3
				// S1 bytes 4-7 (offsets 5-8) must be zeros for valid RTMP
				// (they already are since make zeros the slice)
				_, _ = conn.Write(resp)

				if !tt.misconfigs || tt.responseLen < 1537 {
					return
				}

				// Read C2 + connect command
				_, _ = conn.Read(buf)

				// Send connect response (or close)
				if tt.connectResponse != nil {
					_, _ = conn.Write(tt.connectResponse)
				}
				// If connectResponse is nil, just close (simulates auth rejection)
			}()

			time.Sleep(10 * time.Millisecond)

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
			require.NoError(t, err)
			defer conn.Close()

			target := plugins.Target{
				Address:    netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", serverPort)),
				Host:       "127.0.0.1",
				Misconfigs: tt.misconfigs,
			}

			p := &RTMPPlugin{}
			svc, err := p.Run(conn, 5*time.Second, target)
			require.NoError(t, err)

			if !tt.wantService {
				assert.Nil(t, svc)
				return
			}

			require.NotNil(t, svc)
			assert.Equal(t, tt.wantAnonymous, svc.AnonymousAccess)
			assert.Len(t, svc.SecurityFindings, tt.wantFindingCount)

			if tt.wantFindingCount > 0 {
				assert.Equal(t, tt.wantFindingID, svc.SecurityFindings[0].ID)
				assert.Equal(t, tt.wantFindingSev, svc.SecurityFindings[0].Severity)
			}
		})
	}
}

// buildMockConnectSuccessResponse builds a minimal RTMP response containing _result.
// In real RTMP, the server sends Window Ack Size, Set Peer Bandwidth, Set Chunk Size,
// and then a _result command. For testing, we just need the response to contain "_result".
func buildMockConnectSuccessResponse() []byte {
	// Minimal RTMP chunk with AMF0 _result string embedded
	// This is enough for bytes.Contains(resp, []byte("_result")) to match
	var amf []byte
	amf = append(amf, 0x02, 0x00, 0x07) // string type + length
	amf = append(amf, []byte("_result")...)
	amf = append(amf, 0x00) // number type
	buf := make([]byte, 8)
	// transaction ID = 1.0
	binary.BigEndian.PutUint64(buf, math.Float64bits(1.0))
	amf = append(amf, buf...)
	amf = append(amf, 0x05) // null (command object)

	msgLen := len(amf)
	header := []byte{
		0x03,
		0x00, 0x00, 0x00,
		byte(msgLen >> 16), byte(msgLen >> 8), byte(msgLen),
		0x14,
		0x00, 0x00, 0x00, 0x00,
	}
	return append(header, amf...)
}

func TestBuildRTMPConnect(t *testing.T) {
	cmd := buildRTMPConnect()
	// Chunk header is 12 bytes, AMF0 payload follows
	assert.True(t, len(cmd) > 12, "connect command should be longer than header")
	// First byte: fmt=0, csid=3
	assert.Equal(t, byte(0x03), cmd[0])
	// Message type at offset 7 should be 0x14 (AMF0 command)
	assert.Equal(t, byte(0x14), cmd[7])
	// AMF0 payload should start with string type (0x02) for "connect"
	assert.Equal(t, byte(0x02), cmd[12])
	// "connect" and "live" app name should be in the payload
	assert.True(t, bytes.Contains(cmd, []byte("connect")))
	assert.True(t, bytes.Contains(cmd, []byte("live")))
}

func TestIsValidRTMPResponse(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Full S0+S1",
			data:     append([]byte{0x03}, make([]byte, 1536)...),
			expected: true,
		},
		{
			name:     "Minimal valid (S0 + 4-byte timestamp + 4 zero bytes)",
			data:     []byte{0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "Wrong version",
			data:     []byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "Non-zero S1 bytes 4-7 (not RTMP)",
			data:     []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04},
			expected: false,
		},
		{
			name:     "Too short (5 bytes, need 9)",
			data:     []byte{0x03, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "Too short (2 bytes)",
			data:     []byte{0x03, 0x00},
			expected: false,
		},
		{
			name:     "Single byte (S0 only)",
			data:     []byte{0x03},
			expected: false,
		},
		{
			name:     "Empty",
			data:     []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isValidRTMPResponse(tt.data))
		})
	}
}

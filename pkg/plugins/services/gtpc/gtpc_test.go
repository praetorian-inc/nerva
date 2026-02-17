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

package gtpc

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	readData  []byte
	readIndex int
	writeData []byte
}

func (m *mockConn) Read(b []byte) (int, error) {
	if m.readIndex >= len(m.readData) {
		return 0, io.EOF
	}
	n := copy(b, m.readData[m.readIndex:])
	m.readIndex += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (int, error) {
	// Reset readIndex on each write to simulate fresh request-response cycle
	m.readIndex = 0
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestGTPCValidResponseV1(t *testing.T) {
	// GTPv1-C Echo Response (12 bytes)
	// Byte 0: 0x32 = Version 1, PT=1, S=1
	// Byte 1: 0x02 = Echo Response
	// Bytes 2-3: Length = 0x0004
	// Bytes 4-7: TEID = 0x00000000
	// Bytes 8-11: Sequence number
	response := []byte{
		0x32, 0x02, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00,
	}

	conn := &mockConn{readData: response}
	plugin := &GTPCPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.0.2.1:2123"),
		Host:    "test.example.com",
	}

	service, err := plugin.Run(conn, 1*time.Second, target)

	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "gtpc", service.Protocol)
	assert.Equal(t, "192.0.2.1", service.IP)
	assert.Equal(t, 2123, service.Port)

	// Verify metadata contains version info
	metadata := service.Metadata()
	gtpcMetadata, ok := metadata.(plugins.ServiceGTPC)
	assert.True(t, ok)
	assert.Equal(t, "GTPv1", gtpcMetadata.Version)
}

func TestGTPCValidResponseV2(t *testing.T) {
	// GTPv2-C Echo Response (8 bytes, no TEID when T=0)
	// Byte 0: 0x40 = Version 2, P=0, T=0
	// Byte 1: 0x02 = Echo Response
	// Bytes 2-3: Length = 0x0004
	// Bytes 4-6: Sequence number
	// Byte 7: Spare
	response := []byte{
		0x40, 0x02, 0x00, 0x04,
		0x00, 0x00, 0x01, 0x00,
	}

	conn := &mockConn{readData: response}
	plugin := &GTPCPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.0.2.1:2123"),
		Host:    "test.example.com",
	}

	service, err := plugin.Run(conn, 1*time.Second, target)

	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "gtpc", service.Protocol)

	// Verify metadata contains version info
	metadata := service.Metadata()
	gtpcMetadata, ok := metadata.(plugins.ServiceGTPC)
	assert.True(t, ok)
	assert.Equal(t, "GTPv2", gtpcMetadata.Version)
}

func TestGTPCInvalidVersion(t *testing.T) {
	// Version 3 (invalid) - bits 7-5 = 011 = 0x60
	response := []byte{
		0x60, 0x02, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00,
	}

	conn := &mockConn{readData: response}
	plugin := &GTPCPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.0.2.1:2123"),
		Host:    "test.example.com",
	}

	service, err := plugin.Run(conn, 1*time.Second, target)

	assert.NoError(t, err)
	assert.Nil(t, service) // Should not detect as GTP-C
}

func TestGTPCPTBitNotSet(t *testing.T) {
	// GTPv1 with PT=0 (GTP Prime, not GTP-C)
	// Byte 0: 0x20 = Version 1, PT=0
	response := []byte{
		0x20, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}

	conn := &mockConn{readData: response}
	plugin := &GTPCPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.0.2.1:2123"),
		Host:    "test.example.com",
	}

	service, err := plugin.Run(conn, 1*time.Second, target)

	assert.NoError(t, err)
	assert.Nil(t, service) // Should reject PT=0 as GTP Prime
}

func TestGTPCWrongMessageType(t *testing.T) {
	// GTPv2-C but with wrong message type (0x01 = Echo Request, not Response)
	response := []byte{
		0x40, 0x01, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00,
	}

	conn := &mockConn{readData: response}
	plugin := &GTPCPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.0.2.1:2123"),
		Host:    "test.example.com",
	}

	service, err := plugin.Run(conn, 1*time.Second, target)

	assert.NoError(t, err)
	assert.Nil(t, service) // Should reject non-Echo-Response
}

func TestGTPCShortResponse(t *testing.T) {
	// Truncated response (only 4 bytes)
	response := []byte{0x40, 0x02, 0x00, 0x04}

	conn := &mockConn{readData: response}
	plugin := &GTPCPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.0.2.1:2123"),
		Host:    "test.example.com",
	}

	service, err := plugin.Run(conn, 1*time.Second, target)

	// Should handle truncated response gracefully (not detected)
	assert.NoError(t, err) // Gracefully handled, not an error condition
	assert.Nil(t, service) // Not detected as GTP-C
}

func TestGTPCPortPriority(t *testing.T) {
	plugin := &GTPCPlugin{}

	// Port 2123 should have priority
	assert.True(t, plugin.PortPriority(2123))

	// Other ports should not have priority
	assert.False(t, plugin.PortPriority(2152)) // GTP-U port
	assert.False(t, plugin.PortPriority(3386)) // GTP Prime port
	assert.False(t, plugin.PortPriority(8080))
}

func TestGTPCName(t *testing.T) {
	plugin := &GTPCPlugin{}
	assert.Equal(t, "gtpc", plugin.Name())
}

func TestGTPCType(t *testing.T) {
	plugin := &GTPCPlugin{}
	assert.Equal(t, plugins.UDP, plugin.Type())
}

func TestGTPCPriority(t *testing.T) {
	plugin := &GTPCPlugin{}
	// Priority 79 (before GTP Prime's 80)
	assert.Equal(t, 79, plugin.Priority())
}

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

package gtpu

import (
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/require"
)

// TestGTPUValidResponse tests detection with valid Echo Response
func TestGTPUValidResponse(t *testing.T) {
	// Valid GTP-U Echo Response: Version=1, PT=1, S=1, Message Type=0x02
	// Flag byte: 0x32 (0011 0010)
	// - Version (bits 7-5): 001 = 1
	// - PT (bit 4): 1 (GTP-U)
	// - Reserved (bit 3): 0
	// - E (bit 2): 0
	// - S (bit 1): 1 (sequence number present)
	// - PN (bit 0): 0
	validResponse := []byte{
		0x32,       // Flags
		0x02,       // Message Type (Echo Response)
		0x00, 0x04, // Length (4 bytes for seq+npdu+next)
		0x00, 0x00, 0x00, 0x00, // TEID
		0x00, 0x01, // Sequence number
		0x00, // N-PDU Number
		0x00, // Next Extension Header
	}

	// Start mock UDP server on random port
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer conn.Close()

	serverAddr := conn.LocalAddr().String()

	// Server goroutine: read request and send valid response
	go func() {
		buffer := make([]byte, 1024)
		_, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		// Send valid GTP-U Echo Response
		_, _ = conn.WriteToUDP(validResponse, clientAddr)
	}()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Connect plugin to mock server
	clientConn, err := net.Dial("udp", serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	plugin := &GTPUPlugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	// Should detect GTP-U successfully
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "gtpu", result.Protocol)
}

// TestGTPUInvalidVersion tests rejection of wrong version
func TestGTPUInvalidVersion(t *testing.T) {
	// Invalid response: Version=2 (bits 7-5 = 010, so 0x52) instead of 1
	invalidResponse := []byte{
		0x52,       // Flags (wrong version)
		0x02,       // Message Type (Echo Response)
		0x00, 0x04, // Length
		0x00, 0x00, 0x00, 0x00, // TEID
		0x00, 0x01, // Sequence number
		0x00, // N-PDU Number
		0x00, // Next Extension Header
	}

	// Start mock UDP server on random port
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer conn.Close()

	serverAddr := conn.LocalAddr().String()

	// Server goroutine: read request and send invalid version response
	go func() {
		buffer := make([]byte, 1024)
		_, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		// Send response with wrong version
		_, _ = conn.WriteToUDP(invalidResponse, clientAddr)
	}()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Connect plugin to mock server
	clientConn, err := net.Dial("udp", serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	plugin := &GTPUPlugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	// Should NOT detect GTP-U (wrong version)
	require.NoError(t, err)
	require.Nil(t, result)
}

// TestGTPUPTBitNotSet tests rejection when PT=0 (GTP', not GTP-U)
func TestGTPUPTBitNotSet(t *testing.T) {
	// Invalid response: PT=0 (bit 4 not set, so 0x22 = 0x32 & ^0x10)
	// This is GTP' format, not GTP-U
	invalidResponse := []byte{
		0x22,       // Flags (PT=0)
		0x02,       // Message Type (Echo Response)
		0x00, 0x04, // Length
		0x00, 0x00, 0x00, 0x00, // TEID
		0x00, 0x01, // Sequence number
		0x00, // N-PDU Number
		0x00, // Next Extension Header
	}

	// Start mock UDP server on random port
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer conn.Close()

	serverAddr := conn.LocalAddr().String()

	// Server goroutine: read request and send PT=0 response
	go func() {
		buffer := make([]byte, 1024)
		_, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		// Send response with PT bit not set
		_, _ = conn.WriteToUDP(invalidResponse, clientAddr)
	}()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Connect plugin to mock server
	clientConn, err := net.Dial("udp", serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	plugin := &GTPUPlugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	// Should NOT detect GTP-U (PT bit not set means GTP')
	require.NoError(t, err)
	require.Nil(t, result)
}

// TestGTPUWrongMessageType tests rejection of non-Echo-Response
func TestGTPUWrongMessageType(t *testing.T) {
	// Invalid response: Message Type = 0x01 (Echo Request) instead of 0x02 (Echo Response)
	invalidResponse := []byte{
		0x32,       // Flags
		0x01,       // Message Type (Echo Request - wrong)
		0x00, 0x04, // Length
		0x00, 0x00, 0x00, 0x00, // TEID
		0x00, 0x01, // Sequence number
		0x00, // N-PDU Number
		0x00, // Next Extension Header
	}

	// Start mock UDP server on random port
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer conn.Close()

	serverAddr := conn.LocalAddr().String()

	// Server goroutine: read request and send wrong message type
	go func() {
		buffer := make([]byte, 1024)
		_, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		// Send response with wrong message type
		_, _ = conn.WriteToUDP(invalidResponse, clientAddr)
	}()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Connect plugin to mock server
	clientConn, err := net.Dial("udp", serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	plugin := &GTPUPlugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	// Should NOT detect GTP-U (wrong message type)
	require.NoError(t, err)
	require.Nil(t, result)
}

// TestGTPUShortResponse tests rejection of truncated response
func TestGTPUShortResponse(t *testing.T) {
	// Invalid response: Only 4 bytes instead of minimum 12 bytes (with S=1)
	invalidResponse := []byte{0x32, 0x02, 0x00, 0x00}

	// Start mock UDP server on random port
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer conn.Close()

	serverAddr := conn.LocalAddr().String()

	// Server goroutine: read request and send truncated response
	go func() {
		buffer := make([]byte, 1024)
		_, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		// Send truncated response
		_, _ = conn.WriteToUDP(invalidResponse, clientAddr)
	}()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Connect plugin to mock server
	clientConn, err := net.Dial("udp", serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	plugin := &GTPUPlugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	// Should NOT detect GTP-U (truncated response causes io.ReadFull to fail)
	// The plugin returns nil, nil when detection fails (no service detected)
	require.Nil(t, result)
	require.NoError(t, err)
}

// TestGTPUPortPriority tests the PortPriority method
func TestGTPUPortPriority(t *testing.T) {
	plugin := &GTPUPlugin{}

	// Port 2152 should have priority
	require.True(t, plugin.PortPriority(2152))

	// Other ports should not have priority
	require.False(t, plugin.PortPriority(80))
	require.False(t, plugin.PortPriority(443))
	require.False(t, plugin.PortPriority(3386))
	require.False(t, plugin.PortPriority(0))
}

// TestGTPUName tests the Name method
func TestGTPUName(t *testing.T) {
	plugin := &GTPUPlugin{}
	require.Equal(t, "gtpu", plugin.Name())
}

// TestGTPUType tests the Type method
func TestGTPUType(t *testing.T) {
	plugin := &GTPUPlugin{}
	require.Equal(t, plugins.UDP, plugin.Type())
}

// TestGTPUPriority tests the Priority method
func TestGTPUPriority(t *testing.T) {
	plugin := &GTPUPlugin{}
	require.Equal(t, 81, plugin.Priority())
}

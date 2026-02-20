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

package gtpprime

import (
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/require"
)

// TestGTPPrimeValidResponse tests detection with valid Echo Response
func TestGTPPrimeValidResponse(t *testing.T) {
	// Valid GTP' Echo Response: Version=1, PT=0, Message Type=0x02
	validResponse := []byte{0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

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
		// Send valid GTP' Echo Response
		_, _ = conn.WriteToUDP(validResponse, clientAddr)
	}()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Connect plugin to mock server
	clientConn, err := net.Dial("udp", serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	plugin := &GTPPrimePlugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	// Should detect GTP Prime successfully
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "gtpprime", result.Protocol)
}

// TestGTPPrimeInvalidVersion tests rejection of wrong version
func TestGTPPrimeInvalidVersion(t *testing.T) {
	// Invalid response: Version=2 (bits 7-5 = 010, so 0x40) instead of 1
	invalidResponse := []byte{0x40, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

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

	plugin := &GTPPrimePlugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	// Should NOT detect GTP Prime (wrong version)
	require.NoError(t, err)
	require.Nil(t, result)
}

// TestGTPPrimePTBitSet tests rejection when PT=1 (GTP-C/GTP-U, not GTP')
func TestGTPPrimePTBitSet(t *testing.T) {
	// Invalid response: PT=1 (bit 4 set, so 0x30 = 0x20 | 0x10)
	// This is GTP-C/GTP-U format, not GTP'
	invalidResponse := []byte{0x30, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// Start mock UDP server on random port
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)
	defer conn.Close()

	serverAddr := conn.LocalAddr().String()

	// Server goroutine: read request and send PT=1 response
	go func() {
		buffer := make([]byte, 1024)
		_, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		// Send response with PT bit set
		_, _ = conn.WriteToUDP(invalidResponse, clientAddr)
	}()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Connect plugin to mock server
	clientConn, err := net.Dial("udp", serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	plugin := &GTPPrimePlugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	// Should NOT detect GTP Prime (PT bit set means GTP-C/GTP-U)
	require.NoError(t, err)
	require.Nil(t, result)
}

// TestGTPPrimeWrongMessageType tests rejection of non-Echo-Response
func TestGTPPrimeWrongMessageType(t *testing.T) {
	// Invalid response: Message Type = 0x01 (Echo Request) instead of 0x02 (Echo Response)
	invalidResponse := []byte{0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

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

	plugin := &GTPPrimePlugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	// Should NOT detect GTP Prime (wrong message type)
	require.NoError(t, err)
	require.Nil(t, result)
}

// TestGTPPrimeShortResponse tests rejection of truncated response
func TestGTPPrimeShortResponse(t *testing.T) {
	// Invalid response: Only 4 bytes instead of minimum 8 bytes
	invalidResponse := []byte{0x20, 0x02, 0x00, 0x00}

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

	plugin := &GTPPrimePlugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	// Should NOT detect GTP Prime (truncated response causes io.ReadFull to fail)
	// The plugin returns nil, nil when detection fails (no service detected)
	require.Nil(t, result)
	require.NoError(t, err)
}

// TestGTPPrimePortPriority tests the PortPriority method
func TestGTPPrimePortPriority(t *testing.T) {
	plugin := &GTPPrimePlugin{}

	// Port 3386 should have priority
	require.True(t, plugin.PortPriority(3386))

	// Other ports should not have priority
	require.False(t, plugin.PortPriority(80))
	require.False(t, plugin.PortPriority(443))
	require.False(t, plugin.PortPriority(3388))
	require.False(t, plugin.PortPriority(0))
}

// TestGTPPrimeName tests the Name method
func TestGTPPrimeName(t *testing.T) {
	plugin := &GTPPrimePlugin{}
	require.Equal(t, "gtpprime", plugin.Name())
}

// TestGTPPrimeType tests the Type method
func TestGTPPrimeType(t *testing.T) {
	plugin := &GTPPrimePlugin{}
	require.Equal(t, plugins.UDP, plugin.Type())
}

// TestGTPPrimePriority tests the Priority method
func TestGTPPrimePriority(t *testing.T) {
	plugin := &GTPPrimePlugin{}
	require.Equal(t, 80, plugin.Priority())
}

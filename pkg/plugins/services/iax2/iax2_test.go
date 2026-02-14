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

package iax2

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIAX2Detection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker-based integration test in short mode")
	}

	pool, err := dockertest.NewPool("")
	require.NoError(t, err, "Could not connect to Docker")

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "andrius/asterisk",
		Tag:          "18",
		ExposedPorts: []string{"4569/udp"},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	require.NoError(t, err, "Could not start Asterisk container")

	defer func() {
		require.NoError(t, pool.Purge(resource), "Could not purge Asterisk container")
	}()

	// Wait for Asterisk to be ready
	time.Sleep(5 * time.Second)

	// Get the mapped port
	port := resource.GetPort("4569/udp")
	require.NotEmpty(t, port, "Could not get mapped port")

	// Create UDP connection
	addr, err := netip.ParseAddrPort("127.0.0.1:" + port)
	require.NoError(t, err)

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   addr.Addr().AsSlice(),
		Port: int(addr.Port()),
	})
	require.NoError(t, err)
	defer conn.Close()

	// Create plugin and target
	plugin := &Plugin{}
	target := plugins.Target{
		Address: addr,
		Host:    "localhost",
	}

	// Run the plugin
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service, "Expected IAX2 service detection")

	// Verify service properties
	assert.Equal(t, "127.0.0.1", service.IP)
	assert.Equal(t, int(addr.Port()), service.Port)
	assert.Equal(t, "iax2", service.Protocol)
	assert.Equal(t, "udp", service.Transport)
	assert.False(t, service.TLS)
}

func TestIAX2PluginInterface(t *testing.T) {
	plugin := &Plugin{}

	// Test Name
	assert.Equal(t, IAX2, plugin.Name())

	// Test Type
	assert.Equal(t, plugins.UDP, plugin.Type())

	// Test Priority
	assert.Greater(t, plugin.Priority(), 0)

	// Test PortPriority
	assert.True(t, plugin.PortPriority(4569), "Should prioritize port 4569")
	assert.False(t, plugin.PortPriority(4570), "Should not prioritize other ports")
}

func TestIAX2ResponseValidation(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		valid    bool
	}{
		{
			name:     "empty response",
			response: []byte{},
			valid:    false,
		},
		{
			name:     "too short response",
			response: make([]byte, 11),
			valid:    false,
		},
		{
			name: "valid PONG response",
			response: []byte{
				0x80, 0x00, // Source call number
				0x00, 0x00, // Dest call number
				0x00, 0x00, 0x00, 0x00, // Timestamp
				0x00, // oseqno
				0x00, // iseqno
				0x06, // Frame type: IAX Control
				0x03, // Subclass: PONG
			},
			valid: true,
		},
		{
			name: "valid ACK response",
			response: []byte{
				0x80, 0x00, // Source call number
				0x00, 0x00, // Dest call number
				0x00, 0x00, 0x00, 0x00, // Timestamp
				0x00, // oseqno
				0x00, // iseqno
				0x06, // Frame type: IAX Control
				0x04, // Subclass: ACK
			},
			valid: true,
		},
		{
			name: "valid CALLTOKEN response",
			response: []byte{
				0x80, 0x00, // Source call number
				0x00, 0x00, // Dest call number
				0x00, 0x00, 0x00, 0x00, // Timestamp
				0x00, // oseqno
				0x00, // iseqno
				0x06, // Frame type: IAX Control
				0x28, // Subclass: CALLTOKEN
			},
			valid: true,
		},
		{
			name: "wrong frame type",
			response: []byte{
				0x80, 0x00, // Source call number
				0x00, 0x00, // Dest call number
				0x00, 0x00, 0x00, 0x00, // Timestamp
				0x00, // oseqno
				0x00, // iseqno
				0x05, // Frame type: NOT IAX Control
				0x03, // Subclass: PONG
			},
			valid: false,
		},
		{
			name: "invalid subclass",
			response: []byte{
				0x80, 0x00, // Source call number
				0x00, 0x00, // Dest call number
				0x00, 0x00, 0x00, 0x00, // Timestamp
				0x00, // oseqno
				0x00, // iseqno
				0x06, // Frame type: IAX Control
				0x99, // Subclass: Invalid
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateIAX2Response(tt.response)
			assert.Equal(t, tt.valid, result)
		})
	}
}

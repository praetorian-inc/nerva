// Copyright 2026 Praetorian Security, Inc.
// Licensed under the Apache License, Version 2.0.
// See LICENSE for license information.

package rat

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestDiscoveryProtocol(t *testing.T) {
	require.Equal(t, []byte{0xb2, 1, 6, 10, 4, 'p', 'i', 'n', 'g'}, discoveryProbe())
	p := &DiscoveryPlugin{}
	require.Equal(t, "rat-detector", p.Name())
	require.Equal(t, plugins.UDP, p.Type())
	require.Equal(t, 90, p.Priority())
	require.True(t, p.PortPriority(21119))
	require.False(t, p.PortPriority(21118))
	service := identifyDiscovery(testTarget(21119, true), discoveryPong())
	require.NotNil(t, service)
	require.Equal(t, plugins.ProtoRustDeskDiscovery, service.Protocol)
	require.Equal(t, "udp", service.Transport)
	require.Empty(t, service.SecurityFindings, "discovery is not remote-control exposure")
	require.Empty(t, service.Version)
	require.IsType(t, plugins.ServiceRemoteAccess{}, service.Metadata())
	encoded, err := json.Marshal(service)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "sensitive-user")
	require.NotContains(t, string(encoded), "test-device")
	require.NotContains(t, string(encoded), "123456789")
}

func TestDiscoveryRejectsInvalidDatagrams(t *testing.T) {
	pong := discoveryPong()
	for i := 0; i < len(pong); i++ {
		require.Nil(t, identifyDiscovery(testTarget(21119, true), pong[:i]))
	}
	for _, invalid := range [][]byte{
		nil, discoveryProbe(), []byte("pong"), []byte("HTTP/1.1 200 OK"),
		wrapDiscovery([]byte("\x0a\x00\x0a\x04pong\x1a\x011\x2a\x01h\x32\x01p")), // duplicate empty cmd before a complete pong
		append(bytes.Clone(pong), 0), bytes.Repeat([]byte{0xff}, 2049),
		wrapDiscovery([]byte{10, 4, 'p', 'o', 'n', 'g'}),                            // missing identity fields
		wrapDiscovery([]byte{10, 4, 'p', 'o', 'n', 'g', 10, 4, 'p', 'o', 'n', 'g'}), // duplicate cmd
		wrapDiscovery([]byte{8, 1}),                                                 // wrong wire type
		wrapDiscovery([]byte{0, 1}),                                                 // invalid field zero
		wrapDiscovery([]byte{10, 0xff, 0xff}),                                       // invalid length
	} {
		require.Nil(t, identifyDiscovery(testTarget(21119, true), invalid), "%x", invalid)
	}
}

func TestDiscoveryReadsOneDatagram(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer server.Close()
	client, err := net.Dial("udp", server.LocalAddr().String())
	require.NoError(t, err)
	defer client.Close()
	done := make(chan []byte, 1)
	go func() {
		server.SetDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 128)
		n, addr, err := server.ReadFrom(buf)
		if err == nil {
			server.WriteTo(discoveryPong(), addr)
		}
		done <- buf[:n]
	}()
	service, err := (&DiscoveryPlugin{}).Run(client, time.Second, testTarget(21119, true))
	require.NoError(t, err)
	require.NotNil(t, service)
	require.Equal(t, discoveryProbe(), <-done)
}

func FuzzDiscovery(f *testing.F) {
	f.Add(discoveryPong())
	f.Add(discoveryProbe())
	f.Fuzz(func(t *testing.T, data []byte) {
		if result := identifyDiscovery(testTarget(21119, true), data); result != nil {
			require.Equal(t, plugins.ProtoRustDeskDiscovery, result.Protocol)
			require.Empty(t, result.SecurityFindings)
		}
	})
}

func discoveryPong() []byte {
	var inner []byte
	for _, field := range []struct {
		number protowire.Number
		value  string
	}{
		{1, "pong"}, {3, "123456789"}, {4, "sensitive-user"}, {5, "test-device"}, {6, "Windows"},
	} {
		inner = protowire.AppendTag(inner, field.number, protowire.BytesType)
		inner = protowire.AppendString(inner, field.value)
	}
	return wrapDiscovery(inner)
}

func wrapDiscovery(inner []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, 22, protowire.BytesType), inner)
}

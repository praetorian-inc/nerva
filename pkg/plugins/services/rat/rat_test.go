// Copyright 2026 Praetorian Security, Inc.
// Licensed under the Apache License, Version 2.0.
// See LICENSE for license information.

package rat

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/require"
)

func TestPluginContract(t *testing.T) {
	p := &Plugin{}
	require.Equal(t, "rat-detector", p.Name())
	require.Equal(t, plugins.TCP, p.Type())
	require.Less(t, p.Priority(), 265, "must run before generic VNC")
	for _, port := range []uint16{5405, 5900, 6129, 6783, 6784, 6785} {
		require.True(t, p.PortPriority(port), "port %d", port)
	}
	// A requested port without a supported fingerprint must not imply coverage.
	for _, port := range []uint16{0, 80, 443, 4000, 4899, 5650, 5931, 5938, 7070, 8000, 8200, 15330, 15400, 21118, 40000, 60000, 65535} {
		require.False(t, p.PortPriority(port), "port %d", port)
	}
}

func TestRunFragmentedResponses(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		port                     uint16
		probe, response, product string
	}{
		{"passive-remapped", 44444, "", "SRS:Ready\x00", plugins.ProtoSplashtop},
		{"nx-probe", 4000, "NXSH-5.6.7\n", "NXD-5.6.7\n", plugins.ProtoNoMachine},
		{"radmin-probe", 4899, "\x01\x00\x00\x00\x01\x00\x00\x00\x08\x08", "\x01\x00\x00\x00\x25\x59\x00\x02\x12\x08\x02\x00\x59\x0a", plugins.ProtoRadmin},
		{"incomplete-at-eof", 6783, "", "SRS:Read", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := runFragmentedExchange(t, tc.port, []byte(tc.probe), []byte(tc.response))
			if tc.product == "" {
				require.Nil(t, service)
				return
			}
			require.NotNil(t, service)
			require.Equal(t, tc.product, service.Protocol)
		})
	}
}

func TestServiceResults(t *testing.T) {
	for _, signature := range fingerprints {
		t.Run(signature.product, func(t *testing.T) {
			service := createService(testTarget(signature.ports[0], true), signature.product, "protocol evidence")
			require.Equal(t, signature.product, service.Protocol)
			require.Equal(t, int(signature.ports[0]), service.Port)
			require.Equal(t, "tcp", service.Transport)
			require.False(t, service.TLS)
			require.False(t, service.AnonymousAccess)
			require.Empty(t, service.Version)
			metadata := service.Metadata().(plugins.ServiceRemoteAccess)
			require.Equal(t, signature.product, metadata.Type())
			require.Equal(t, "protocol evidence", metadata.Evidence)
			require.Empty(t, service.SecurityFindings, "fingerprinting must not generate security findings")
		})
	}
}

func TestRunBoundedRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan int, 1)
	go func() {
		n, _ := server.Write(bytes.Repeat([]byte{'x'}, maxResponseBytes+100))
		done <- n
	}()
	service, err := (&Plugin{}).Run(client, time.Second, testTarget(6783, true))
	require.NoError(t, err)
	require.Nil(t, service)
	client.Close()
	require.Equal(t, maxResponseBytes, <-done)
}

func TestRunSilentListenerAndZeroTimeout(t *testing.T) {
	for _, timeout := range []time.Duration{0, 20 * time.Millisecond} {
		client, server := net.Pipe()
		start := time.Now()
		service, err := (&Plugin{}).Run(client, timeout, testTarget(6783, true))
		client.Close()
		server.Close()
		require.NoError(t, err)
		require.Nil(t, service)
		require.Less(t, time.Since(start), time.Second)
	}
}

func testTarget(port uint16, misconfigs bool) plugins.Target {
	return plugins.Target{Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), Misconfigs: misconfigs}
}

func runFragmentedExchange(t *testing.T, port uint16, probe, response []byte) *plugins.Service {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() {
		defer server.Close()
		server.SetDeadline(time.Now().Add(time.Second))
		if len(probe) > 0 {
			request := make([]byte, len(probe))
			if _, err := io.ReadFull(server, request); err != nil {
				done <- err
				return
			}
			if !bytes.Equal(request, probe) {
				done <- fmt.Errorf("unexpected request %x", request)
				return
			}
		}
		var err error
		for _, b := range response {
			if _, err = server.Write([]byte{b}); err != nil {
				break
			}
		}
		done <- err
	}()
	p := &Plugin{}
	if signature := fingerprintForPort(port); signature != nil && signature.probe != "" {
		p.active = signature
	}
	service, err := p.Run(client, time.Second, testTarget(port, false))
	client.Close()
	require.NoError(t, err)
	require.NoError(t, <-done)
	return service
}

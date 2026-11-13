// Copyright 2026 Praetorian Security, Inc.
// Licensed under the Apache License, Version 2.0.
// See LICENSE for license information.

package scan

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/require"
)

// These services stay silent until their probe arrives. Matcher-only tests cannot
// catch a plugin that incorrectly chooses its request from the destination port.
func TestRATClientFirstOnNonstandardPorts(t *testing.T) {
	for _, tc := range []struct {
		product, probe, response string
		defaultPort              uint16
	}{
		{plugins.ProtoNoMachine, "NXSH-5.6.7\n", "NXD-8.1.2\n", 4000},
		{plugins.ProtoRadmin, "\x01\x00\x00\x00\x01\x00\x00\x00\x08\x08", "\x01\x00\x00\x00\x25\x59\x00\x02\x12\x08\x02\x00\x59\x0a", 4899},
	} {
		t.Run(tc.product, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			done := make(chan struct{})
			var handlers sync.WaitGroup
			t.Cleanup(func() { listener.Close(); <-done; handlers.Wait() })
			go func() {
				defer close(done)
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					handlers.Add(1)
					go func() {
						defer handlers.Done()
						defer conn.Close()
						conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
						request := make([]byte, len(tc.probe))
						if _, err := io.ReadFull(conn, request); err == nil && bytes.Equal(request, []byte(tc.probe)) {
							io.WriteString(conn, tc.response)
						}
					}()
				}
			}()
			address := netip.MustParseAddrPort(listener.Addr().String())
			require.NotEqual(t, tc.defaultPort, address.Port())
			var registered plugins.Plugin
			for _, plugin := range sortedTCPPlugins {
				if plugin.Name() == "rat-detector-"+tc.product {
					registered = plugin
				}
			}
			require.NotNil(t, registered)
			require.True(t, registered.PortPriority(tc.defaultPort))
			require.False(t, registered.PortPriority(address.Port()))
			config := Config{ScanDepth: ScanDepthThorough, DefaultTimeout: 50 * time.Millisecond, Misconfigs: true}
			services, err := config.SimpleScanTarget(plugins.Target{Address: address})
			require.NoError(t, err)
			require.Len(t, services, 1)
			require.Equal(t, tc.product, services[0].Protocol)
			require.Equal(t, int(address.Port()), services[0].Port)
			require.Empty(t, services[0].SecurityFindings)
		})
	}
}

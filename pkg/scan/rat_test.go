// Copyright 2026 Praetorian Security, Inc.
// Licensed under the Apache License, Version 2.0.
// See LICENSE for license information.

package scan

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/require"
)

func TestRATPluginRegisteredBeforeVNC(t *testing.T) {
	ratIndex, vncIndex := -1, -1
	registrations := 0
	for index, plugin := range sortedTCPPlugins {
		switch plugin.Name() {
		case "rat-detector":
			ratIndex = index
			registrations++
		case "VNC":
			vncIndex = index
		}
	}
	require.Equal(t, 1, registrations)
	require.GreaterOrEqual(t, ratIndex, 0)
	require.Greater(t, vncIndex, ratIndex)
}

// Matcher variants live in the plugin tests; this checks scanner precedence
// and fallback, the two behaviors that require the full pipeline.
func TestRATScanPipeline(t *testing.T) {
	tests := []struct {
		name     string
		response string
		protocol string
	}{
		{"realvnc", "RFB 005.000\n", plugins.ProtoRealVNC},
		{"generic-vnc-fallback", "RFB 003.008\n", plugins.ProtoVNC},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			var handlers sync.WaitGroup
			done := make(chan struct{})
			defer func() {
				listener.Close()
				<-done
				handlers.Wait()
			}()
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
						conn.SetDeadline(time.Now().Add(5 * time.Second))
						io.WriteString(conn, tc.response)
						// A VNC server waits for client input after its greeting.
						// Closing immediately would hide the RAT fallback timeout.
						var input [1]byte
						conn.Read(input[:])
					}()
				}
			}()
			config := Config{ScanDepth: ScanDepthThorough, DefaultTimeout: 100 * time.Millisecond, Misconfigs: true}
			services, err := config.SimpleScanTarget(plugins.Target{Address: netip.MustParseAddrPort(listener.Addr().String())})
			require.NoError(t, err)
			require.Len(t, services, 1)
			require.Equal(t, tc.protocol, services[0].Protocol)
			if tc.protocol == plugins.ProtoVNC {
				require.Equal(t, "003.008", services[0].Version)
				require.Len(t, services[0].SecurityFindings, 1)
				require.Equal(t, "vnc-exposed", services[0].SecurityFindings[0].ID)
			} else {
				require.Contains(t, services[0].Metadata().(plugins.ServiceRemoteAccess).Evidence, "RFB 005.000")
				require.Empty(t, services[0].SecurityFindings)
			}
		})
	}
}

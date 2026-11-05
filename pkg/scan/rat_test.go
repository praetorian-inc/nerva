// Copyright 2026 Praetorian Security, Inc.
// Licensed under the Apache License, Version 2.0.
// See LICENSE for license information.

package scan

import (
	"io"
	"net"
	"net/netip"
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
		address  string
		response string
		protocol string
	}{
		{"realvnc", "127.0.0.1:5900", "RFB 005.000\n", plugins.ProtoRealVNC},
		{"generic-vnc-fallback", "127.0.0.1:5900", "RFB 003.008\n", plugins.ProtoVNC},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", tc.address)
			if err != nil {
				t.Fatalf("fixture requires free loopback port %s: %v", tc.address, err)
			}
			defer listener.Close()
			done := make(chan struct{})
			defer func() {
				listener.Close()
				<-done
			}()
			go func() {
				defer close(done)
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					conn.SetDeadline(time.Now().Add(time.Second))
					io.WriteString(conn, tc.response)
					conn.Close()
				}
			}()
			config := Config{FastMode: true, DefaultTimeout: 100 * time.Millisecond, Misconfigs: true}
			services, err := config.SimpleScanTarget(plugins.Target{Address: netip.MustParseAddrPort(tc.address)})
			require.NoError(t, err)
			require.Len(t, services, 1)
			require.Equal(t, tc.protocol, services[0].Protocol)
			require.Empty(t, services[0].SecurityFindings)
		})
	}
}

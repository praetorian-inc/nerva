// Copyright 2026 Praetorian Security, Inc.
// Licensed under the Apache License, Version 2.0.
// See LICENSE for license information.

package scan

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/require"
)

func TestLogMeInHTTPServiceIntegration(t *testing.T) {
	// Header variants are covered in the RAT package; exercise each transport once.
	for _, tc := range []struct {
		name, header, product string
		encrypted             bool
	}{
		{"http", "LogMeIn", "logmein", false},
		{"https", "LogMeIn Web Gateway", "logmein-web-gateway", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, header := tc.encrypted, tc.header
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", header)
				w.WriteHeader(http.StatusUnauthorized)
			}))
			if encrypted {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			address := server.Listener.Addr().String()
			var conn net.Conn
			var err error
			transport, name := plugins.TCP, "http"
			if encrypted {
				conn, err = tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true}) // Local fixture certificate.
				transport, name = plugins.TCPTLS, "https"
			} else {
				conn, err = net.DialTimeout("tcp", address, time.Second)
			}
			require.NoError(t, err)
			defer conn.Close()
			var plugin plugins.Plugin
			for _, candidate := range plugins.Plugins[transport] {
				if candidate.Name() == name {
					plugin = candidate
					break
				}
			}
			require.NotNil(t, plugin)
			service, err := plugin.Run(conn, time.Second, plugins.Target{Address: netip.MustParseAddrPort(address)})
			require.NoError(t, err)
			require.NotNil(t, service)
			expected := tc.product
			if encrypted {
				require.Contains(t, service.Metadata().(plugins.ServiceHTTPS).Technologies, expected)
			} else {
				require.Contains(t, service.Metadata().(plugins.ServiceHTTP).Technologies, expected)
			}
			require.False(t, service.AnonymousAccess)
			require.Empty(t, service.SecurityFindings)
		})
	}
}

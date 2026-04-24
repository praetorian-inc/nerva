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

package mqtt3

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

func TestMqtt3(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "mqtt",
			Port:        1883,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "efrecon/mosquitto",
			},
		},
	}

	p := &MQTT3Plugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

// startMockMQTTServer starts a TCP listener that accepts one connection,
// reads the CONNECT packet, writes connackBytes, and closes.
// Returns the listener (caller must defer Close) and the port.
func startMockMQTTServer(t *testing.T, connackBytes []byte) (net.Listener, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	serverPort := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(connackBytes)
	}()

	return listener, serverPort
}

func TestMQTT3SecurityFindings(t *testing.T) {
	tests := []struct {
		name             string
		connack          []byte
		misconfigs       bool
		wantAnonymous    bool
		wantFindingCount int
		wantFindingID    string
	}{
		{
			name:             "anonymous access detected",
			connack:          []byte{0x20, 0x02, 0x00, 0x00},
			misconfigs:       true,
			wantAnonymous:    true,
			wantFindingCount: 1,
			wantFindingID:    "mqtt-no-auth",
		},
		{
			name:             "auth required",
			connack:          []byte{0x20, 0x02, 0x00, 0x05},
			misconfigs:       true,
			wantAnonymous:    false,
			wantFindingCount: 0,
		},
		{
			name:             "misconfigs disabled",
			connack:          []byte{0x20, 0x02, 0x00, 0x00},
			misconfigs:       false,
			wantAnonymous:    false,
			wantFindingCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, serverPort := startMockMQTTServer(t, tt.connack)
			defer listener.Close()

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
			if err != nil {
				t.Fatalf("failed to connect to mock server: %v", err)
			}
			defer conn.Close()

			addrPort := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", serverPort))
			target := plugins.Target{
				Host:       "127.0.0.1",
				Address:    addrPort,
				Misconfigs: tt.misconfigs,
			}

			service, err := Run(conn, 5*time.Second, false, target)
			if err != nil {
				t.Fatalf("Run() returned unexpected error: %v", err)
			}
			if service == nil {
				t.Fatal("Run() returned nil, want non-nil service")
			}

			assert.Equal(t, tt.wantAnonymous, service.AnonymousAccess)
			assert.Len(t, service.SecurityFindings, tt.wantFindingCount)
			if tt.wantFindingCount > 0 && len(service.SecurityFindings) > 0 {
				assert.Equal(t, tt.wantFindingID, service.SecurityFindings[0].ID)
				assert.Equal(t, plugins.SeverityHigh, service.SecurityFindings[0].Severity)
			}
		})
	}
}

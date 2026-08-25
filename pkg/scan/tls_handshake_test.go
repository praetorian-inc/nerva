// Copyright 2026 Praetorian Security, Inc.
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

package scan

import (
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func startSNIRequiredTLSServer(t *testing.T) (uint16, *atomic.Int64) {
	t.Helper()
	cert := generateBenchmarkTLSCert(t)
	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	config.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		if info.ServerName == "" {
			return nil, errors.New("SNI required")
		}
		return nil, nil
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepts := &atomic.Int64{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
			}(conn)
		}
	}()

	return uint16(listener.Addr().(*net.TCPAddr).Port), accepts
}

func TestSimpleScanTargetSkipsPlaintextSlowLaneAfterTLSAlert(t *testing.T) {
	port, accepts := startSNIRequiredTLSServer(t)
	if anyPluginClaimsPort(port) {
		t.Skipf("ephemeral port %d is claimed by a priority plugin", port)
	}
	config := &Config{DefaultTimeout: 250 * time.Millisecond}
	target := plugins.Target{Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}

	started := time.Now()
	services, err := config.SimpleScanTarget(target)
	if err != nil {
		t.Fatalf("SimpleScanTarget returned error: %v", err)
	}
	if len(services) != 0 {
		t.Fatalf("SimpleScanTarget returned %d services, want none", len(services))
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("SimpleScanTarget took %v after immediate TLS alert", elapsed)
	}
	if got := accepts.Load(); got != 1 {
		t.Fatalf("server accepted %d connections, want only the TLS probe", got)
	}
}

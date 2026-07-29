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

// LAB-5299: benchmarks establishing a baseline for the performance impact of
// the "slow lane". When a service runs on its default port, SimpleScanTarget
// (see simple_scan.go) finds a match in its first PortPriority-based pass
// ("fast lane"). When no plugin's PortPriority claims the port (e.g. SSH
// listening on 9999 instead of 22), and the scan isn't FastMode, every
// registered plugin is dialed and run in priority order until one identifies
// the service or the list is exhausted ("slow lane").
//
// These benchmarks exercise the real Config.SimpleScanTarget / ScanTargets
// code paths (no production code is modified) against local mock TCP/TLS
// servers so results are reproducible and don't depend on external services.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// benchmarkProbeTimeout bounds how long any single plugin will wait for a
// response in these benchmarks. It is far shorter than the CLI's 2s default
// (see pkg/runner/root.go) because the mock servers below always respond or
// close quickly; the bound only guards against an unexpected stall.
const benchmarkProbeTimeout = 200 * time.Millisecond

// mustNoTCPPluginClaims fails the benchmark if any registered TCP or TCPTLS
// plugin's PortPriority claims port, which would invalidate the "non-standard
// port" premise of the slow-lane benchmarks below.
func mustNoTCPPluginClaims(tb testing.TB, port uint16) {
	tb.Helper()
	for _, p := range sortedTCPPlugins {
		if p.PortPriority(port) {
			tb.Fatalf("port %d unexpectedly claimed by TCP plugin %q; choose a different non-standard port", port, p.Name())
		}
	}
	for _, p := range sortedTCPTLSPlugins {
		if p.PortPriority(port) {
			tb.Fatalf("port %d unexpectedly claimed by TCPTLS plugin %q; choose a different non-standard port", port, p.Name())
		}
	}
}

// mustTCPPluginClaims fails the benchmark if no registered TCP plugin's
// PortPriority claims port, which would invalidate the "standard port" (fast
// lane) premise.
func mustTCPPluginClaims(tb testing.TB, port uint16) {
	tb.Helper()
	for _, p := range sortedTCPPlugins {
		if p.PortPriority(port) {
			return
		}
	}
	tb.Fatalf("expected a TCP plugin to claim port %d, none did", port)
}

// mustTCPTLSPluginClaims fails the benchmark if no registered TCPTLS plugin's
// PortPriority claims port.
func mustTCPTLSPluginClaims(tb testing.TB, port uint16) {
	tb.Helper()
	for _, p := range sortedTCPTLSPlugins {
		if p.PortPriority(port) {
			return
		}
	}
	tb.Fatalf("expected a TCPTLS plugin to claim port %d, none did", port)
}

// pluginPosition returns the 1-based position of the first plugin in list
// whose Name() matches name, or 0 if not found. Used to report how many
// plugins the slow lane must try before reaching a known plugin.
func pluginPosition(list []plugins.Plugin, name string) int {
	for i, p := range list {
		if p.Name() == name {
			return i + 1
		}
	}
	return 0
}

// startMockTCPServer listens on 127.0.0.1:port (port 0 picks a free ephemeral
// port) and runs handle for every accepted connection. It returns the bound
// port. If a non-zero port is already in use (e.g. a real service on the
// developer's machine happens to occupy it), the benchmark is skipped rather
// than failing outright, since a literal port number is required to match a
// plugin's PortPriority.
func startMockTCPServer(tb testing.TB, port uint16, handle func(net.Conn)) uint16 {
	tb.Helper()

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		tb.Skipf("cannot bind 127.0.0.1:%d (likely already in use): %v", port, err)
	}
	tb.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()

	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// startMockTLSServer is like startMockTCPServer but wraps accepted
// connections in a TLS server using a throwaway self-signed certificate. The
// client side (Config.DialTLS in simple_scan.go) sets InsecureSkipVerify, so
// no CA trust setup is required here.
func startMockTLSServer(tb testing.TB, port uint16, handle func(net.Conn)) uint16 {
	tb.Helper()

	cert := generateBenchmarkTLSCert(tb)
	ln, err := tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		tb.Skipf("cannot bind 127.0.0.1:%d (likely already in use): %v", port, err)
	}
	tb.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()

	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// generateBenchmarkTLSCert creates an in-memory self-signed ECDSA certificate
// for the mock TLS server, following the same pattern used in
// pkg/plugins/tlscheck_test.go.
func generateBenchmarkTLSCert(tb testing.TB) tls.Certificate {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generateBenchmarkTLSCert: GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nerva-benchmark"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("generateBenchmarkTLSCert: CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		tb.Fatalf("generateBenchmarkTLSCert: MarshalECPrivateKey: %v", err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		tb.Fatalf("generateBenchmarkTLSCert: X509KeyPair: %v", err)
	}
	return cert
}

// handleRedisPong replies to every connection with a Redis "+PONG\r\n"
// response, satisfying REDISPlugin/REDISTLSPlugin's detection handshake
// (see pkg/plugins/services/redis/redis.go DetectRedis) so SimpleScanTarget
// finds a match on the first plugin it dials in the fast lane.
func handleRedisPong(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(benchmarkProbeTimeout))
	buf := make([]byte, 256)
	_, _ = conn.Read(buf) // discard the PING probe
	_, _ = conn.Write([]byte("+PONG\r\n"))
}

// handleSSHBanner sends an SSH-style version banner to every connection,
// simulating an SSH service listening on a non-standard port (the motivating
// LAB-5299 scenario). SSHPlugin (see pkg/plugins/services/ssh/ssh.go) accepts
// the banner and gracefully falls back to a banner-only identification when
// the follow-on key-exchange response can't be parsed, so a fixed 4-byte
// reply is enough for it to succeed. Earlier-priority plugins that also probe
// this connection fail to parse the banner and move on.
func handleSSHBanner(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(benchmarkProbeTimeout))
	_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_8.9\r\n"))
	buf := make([]byte, 256)
	_, _ = conn.Read(buf)                 // discard the client's banner / KEXINIT probe
	_, _ = conn.Write([]byte{0, 0, 0, 0}) // not a valid KEXINIT; SSHPlugin still succeeds using the banner alone
}

// handleCloseImmediately closes every connection without reading or writing,
// simulating a completely unrecognized plain-TCP service. No plugin can
// identify this, so SimpleScanTarget must exhaust every TCP plugin in the
// slow lane.
func handleCloseImmediately(conn net.Conn) {
	_ = conn.Close()
}

// handleTLSNoAppData completes the TLS handshake (an implicit side effect of
// the Write call below, so DialTLS's initial handshake check succeeds and the
// slow lane exercises the TCPTLS plugin list) and then sends unrecognized
// data so no plugin can identify a service.
func handleTLSNoAppData(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(benchmarkProbeTimeout))
	_, _ = conn.Write([]byte("unrecognized-service\r\n"))
	buf := make([]byte, 256)
	_, _ = conn.Read(buf) // discard whatever the plugin sends in response
}

// runSingleTargetScan scans one target through the same ScanTargets +
// ScanPool + SimpleScanTarget path the CLI uses (see scan_api.go), with a
// single worker since there is only one target.
//
// Before the timed loop starts, it runs ScanTargets once and passes the
// result to validate, which must assert the scan found (or didn't find)
// the expected service. Without this check, the "plugins-tried/op" metrics
// reported by callers are computed statically from the plugin registry and
// would stay unchanged even if a plugin regression silently broke
// detection, making the benchmark numbers meaningless.
func runSingleTargetScan(b *testing.B, target plugins.Target, cfg Config, validate func(*testing.B, []plugins.Service)) {
	b.Helper()
	cfg.Workers = 1
	if cfg.DefaultTimeout == 0 {
		cfg.DefaultTimeout = benchmarkProbeTimeout
	}

	ctx := context.Background()
	targets := []plugins.Target{target}

	result, err := ScanTargets(ctx, targets, cfg)
	if err != nil {
		b.Fatalf("ScanTargets (validation run): %v", err)
	}
	validate(b, result)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ScanTargets(ctx, targets, cfg); err != nil {
			b.Fatalf("ScanTargets: %v", err)
		}
	}
}

// assertServiceFound fails the benchmark unless ScanTargets returned at
// least one result, i.e. some plugin identified the service.
func assertServiceFound(b *testing.B, services []plugins.Service) {
	b.Helper()
	if len(services) < 1 {
		b.Fatalf("expected at least 1 result, got %d", len(services))
	}
}

// assertNoServiceFound fails the benchmark unless ScanTargets returned zero
// results, i.e. no plugin identified the (unrecognized) mock service.
func assertNoServiceFound(b *testing.B, services []plugins.Service) {
	b.Helper()
	if len(services) != 0 {
		b.Fatalf("expected 0 results, got %d", len(services))
	}
}

// assertSSHServiceFound fails the benchmark unless ScanTargets returned at
// least one result and one of those results' service name contains "ssh"
// (case-insensitive).
func assertSSHServiceFound(b *testing.B, services []plugins.Service) {
	b.Helper()
	if len(services) < 1 {
		b.Fatalf("expected at least 1 result, got %d", len(services))
	}
	for _, s := range services {
		if strings.Contains(strings.ToLower(s.Protocol), "ssh") {
			return
		}
	}
	b.Fatalf("expected a result with service name containing %q, got %+v", "ssh", services)
}

// BenchmarkNonStandard_TCP_FastLane_StandardPort measures scan time when the
// target port matches a plugin's PortPriority and that plugin correctly
// identifies the service (Redis on its default port 6379). SimpleScanTarget
// returns after a single dial + plugin.Run in the fast-lane loop.
func BenchmarkNonStandard_TCP_FastLane_StandardPort(b *testing.B) {
	port := startMockTCPServer(b, 6379, handleRedisPong)
	mustTCPPluginClaims(b, port)

	target := plugins.Target{Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	runSingleTargetScan(b, target, Config{}, assertServiceFound)
}

// BenchmarkNonStandard_TCP_SlowLane_NoMatch measures scan time for a
// completely unrecognized service on a non-standard port: no plugin claims
// PortPriority, and none identifies the (silent) mock service, so
// SimpleScanTarget must sequentially dial and run every registered TCP plugin
// before giving up. This is the worst-case slow-lane scenario from LAB-5299.
func BenchmarkNonStandard_TCP_SlowLane_NoMatch(b *testing.B) {
	port := startMockTCPServer(b, 0, handleCloseImmediately)
	mustNoTCPPluginClaims(b, port)

	target := plugins.Target{Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	runSingleTargetScan(b, target, Config{}, assertNoServiceFound)

	// Plugin iteration count: computed statically (not observed at runtime,
	// since SimpleScanTarget doesn't expose per-attempt counters) from the
	// same registry SimpleScanTarget iterates. No match means every TCP
	// plugin is tried.
	b.ReportMetric(float64(len(sortedTCPPlugins)), "plugins-tried/op")
}

// BenchmarkNonStandard_TCP_SlowLane_PartialMatch_SSH measures scan time for
// an SSH service listening on a non-standard port (the literal LAB-5299
// example: "SSH on 9999"). No plugin claims PortPriority for this port, so
// the fast lane finds nothing; the slow lane then dials every plugin in
// priority order until SSHPlugin identifies the banner.
func BenchmarkNonStandard_TCP_SlowLane_PartialMatch_SSH(b *testing.B) {
	// Earlier-priority plugins probe this connection with an HTTP request
	// before SSHPlugin gets a turn; net/http's Transport logs "Unsolicited
	// response received on idle HTTP channel" via log.Default() when it
	// later reads the SSH banner off that now-idle connection. Silence it
	// for the duration of the benchmark so it doesn't spam benchmark output
	// with synchronous stderr I/O inside the timed loop.
	origOutput := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(origOutput)

	port := startMockTCPServer(b, 0, handleSSHBanner)
	mustNoTCPPluginClaims(b, port)

	target := plugins.Target{Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	runSingleTargetScan(b, target, Config{}, assertSSHServiceFound)

	if pos := pluginPosition(sortedTCPPlugins, "ssh"); pos > 0 {
		b.ReportMetric(float64(pos), "plugins-tried/op")
	}
}

// BenchmarkNonStandard_TCPTLS_FastLane_StandardPort measures scan time when
// the target port matches a TLS plugin's PortPriority and that plugin
// correctly identifies the service (Redis-over-TLS on its default port
// 6380). SimpleScanTarget's initial DialTLS succeeds and the matching plugin
// returns a result in the first TLS pass.
func BenchmarkNonStandard_TCPTLS_FastLane_StandardPort(b *testing.B) {
	port := startMockTLSServer(b, 6380, handleRedisPong)
	mustTCPTLSPluginClaims(b, port)

	target := plugins.Target{Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	runSingleTargetScan(b, target, Config{}, assertServiceFound)
}

// BenchmarkNonStandard_TCPTLS_SlowLane_NoMatch measures scan time for a
// completely unrecognized TLS service on a non-standard port: no plugin
// claims PortPriority, the initial DialTLS handshake succeeds (so the slow
// lane exercises the TCPTLS plugin list), but no plugin identifies the
// (unrecognized) application data, so SimpleScanTarget must sequentially
// dial, handshake, and run every registered TCPTLS plugin before giving up.
func BenchmarkNonStandard_TCPTLS_SlowLane_NoMatch(b *testing.B) {
	// As in BenchmarkNonStandard_TCP_SlowLane_PartialMatch_SSH, an
	// HTTP(S) plugin probing this connection before it's abandoned causes
	// net/http's Transport to log "Unsolicited response received on idle
	// HTTP channel" via log.Default() when the unrecognized application
	// data above arrives after the connection is idle. Silence it for the
	// duration of the benchmark.
	origOutput := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(origOutput)

	port := startMockTLSServer(b, 0, handleTLSNoAppData)
	mustNoTCPPluginClaims(b, port)

	target := plugins.Target{Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	runSingleTargetScan(b, target, Config{}, assertNoServiceFound)

	b.ReportMetric(float64(len(sortedTCPTLSPlugins)), "plugins-tried/op")
}

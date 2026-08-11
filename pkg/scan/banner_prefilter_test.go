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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// --- prefixConn unit tests -------------------------------------------------

// TestPrefixConn_ReplaysThenReadsUnderlying verifies that a prefixConn wired
// with a non-empty prefix returns the prefix bytes on the first Read, then
// falls through to the underlying connection's data on the next Read.
func TestPrefixConn_ReplaysThenReadsUnderlying(t *testing.T) {
	conn := &stubConn{data: []byte("REST")}
	prefix := []byte("PRE-")
	pc := newPrefixConn(conn, prefix)

	buf := make([]byte, 16)

	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("first Read returned error: %v", err)
	}
	if string(buf[:n]) != string(prefix) {
		t.Errorf("first Read = %q, want prefix %q", buf[:n], prefix)
	}

	n, err = pc.Read(buf)
	if err != nil {
		t.Fatalf("second Read returned error: %v", err)
	}
	if string(buf[:n]) != "REST" {
		t.Errorf("second Read = %q, want underlying data %q", buf[:n], "REST")
	}
}

// TestPrefixConn_EmptyPrefix verifies that with an empty/nil prefix, reads go
// straight through to the underlying connection with no replay step.
func TestPrefixConn_EmptyPrefix(t *testing.T) {
	conn := &stubConn{data: []byte("DATA")}
	pc := newPrefixConn(conn, nil)

	buf := make([]byte, 16)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("Read returned error: %v", err)
	}
	if string(buf[:n]) != "DATA" {
		t.Errorf("Read with empty prefix = %q, want underlying data %q", buf[:n], "DATA")
	}
}

// TestPrefixConn_CloseClosesUnderlying verifies that closing a prefixConn
// closes the embedded net.Conn (prefixConn has no Close override, so this
// relies on Go's method embedding forwarding the call).
func TestPrefixConn_CloseClosesUnderlying(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	pc := newPrefixConn(client, []byte("x"))
	if err := pc.Close(); err != nil {
		t.Fatalf("prefixConn.Close returned error: %v", err)
	}

	if _, err := client.Write([]byte("y")); err == nil {
		t.Error("expected write on closed underlying conn to fail, got nil error")
	}
}

// TestPrefixConn_PluginReceivesBannerBytes verifies the core contract: a
// plugin reading from a prefixConn-wrapped connection sees the previously
// consumed banner bytes followed by any trailing data, as if it had connected
// fresh and read the banner itself.
func TestPrefixConn_PluginReceivesBannerBytes(t *testing.T) {
	sshBanner := []byte("SSH-2.0-OpenSSH_8.9\r\n")
	trailing := []byte("EXTRA-DATA-AFTER-BANNER")
	conn := &stubConn{data: trailing}
	pc := newPrefixConn(conn, sshBanner)

	buf := make([]byte, 64)
	n1, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("first Read returned error: %v", err)
	}
	n2, err := pc.Read(buf[n1:])
	if err != nil {
		t.Fatalf("second Read returned error: %v", err)
	}

	got := buf[:n1+n2]
	want := append(append([]byte{}, sshBanner...), trailing...)
	if !bytes.Equal(got, want) {
		t.Errorf("plugin-visible bytes = %q, want %q", got, want)
	}
}

// --- integration test server helpers ---------------------------------------

// startBannerMockServer starts a TCP listener on a random loopback port. On
// each accepted connection it writes banner immediately, then reads and
// discards any further data from the client until the connection closes.
func startBannerMockServer(t *testing.T, banner []byte) (netip.AddrPort, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write(banner)
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	ap := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(addr.Port))
	return ap, func() { ln.Close() }
}

// startClientFirstMockServer starts a TCP listener on a random loopback port
// that never writes to the client; it only reads and discards data. This
// simulates a client-speaks-first protocol (e.g. HTTP), where the server
// produces no bytes until it receives a request the client never sends.
func startClientFirstMockServer(t *testing.T) (netip.AddrPort, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	ap := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(addr.Port))
	return ap, func() { ln.Close() }
}

// startTLSBannerMockServer starts a TLS listener on a random loopback port
// using a self-signed certificate. On each accepted connection, after the TLS
// handshake completes, it writes banner, then reads and discards any further
// data from the client.
func startTLSBannerMockServer(t *testing.T, banner []byte) (netip.AddrPort, func()) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write(banner)
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	ap := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(addr.Port))
	return ap, func() { ln.Close() }
}

// --- integration tests for banner pre-filtering ----------------------------

// TestIntegration_BannerPrefilter_SSHOnNonStandardPort verifies that
// SimpleScanTarget completes without error when the pre-read banner
// classifies cleanly as SSH on a port with no default port-priority match.
func TestIntegration_BannerPrefilter_SSHOnNonStandardPort(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	port := startMockTCPServer(t, 0, handleSSHBanner)
	ap := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)

	cfg := Config{FastMode: false, DefaultTimeout: 5 * time.Second}
	target := plugins.Target{Address: ap}

	services, err := cfg.SimpleScanTarget(target)
	if err != nil {
		t.Fatalf("SimpleScanTarget returned error: %v", err)
	}
	if len(services) == 0 {
		t.Fatal("SimpleScanTarget returned no services; expected at least one SSH service")
	}

	found := false
	for _, s := range services {
		if strings.Contains(strings.ToLower(s.Protocol), "ssh") {
			found = true
			break
		}
	}
	if !found {
		protocols := make([]string, len(services))
		for i, s := range services {
			protocols[i] = s.Protocol
		}
		t.Fatalf("no service identified as SSH; got protocols: %v", protocols)
	}
}

// TestIntegration_BannerPrefilter_UnknownFallsBackToFullIteration verifies
// that an unclassifiable banner does not narrow the candidate list and does
// not cause SimpleScanTarget to error or panic; it simply falls back to
// iterating the full plugin list.
func TestIntegration_BannerPrefilter_UnknownFallsBackToFullIteration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ap, cleanup := startBannerMockServer(t, []byte{0x01, 0x02, 0x03})
	t.Cleanup(cleanup)

	cfg := Config{FastMode: false, DefaultTimeout: 200 * time.Millisecond}
	target := plugins.Target{Address: ap}

	if _, err := cfg.SimpleScanTarget(target); err != nil {
		t.Fatalf("SimpleScanTarget returned error: %v", err)
	}
}

// TestIntegration_BannerPrefilter_ClientSpeaksFirst_NoNarrowing verifies that
// when the server never speaks first (e.g. HTTP), the banner pre-read times
// out, classification is Unknown, and SimpleScanTarget still completes
// without error via full iteration.
func TestIntegration_BannerPrefilter_ClientSpeaksFirst_NoNarrowing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ap, cleanup := startClientFirstMockServer(t)
	t.Cleanup(cleanup)

	cfg := Config{FastMode: false, DefaultTimeout: 100 * time.Millisecond}
	target := plugins.Target{Address: ap}

	if _, err := cfg.SimpleScanTarget(target); err != nil {
		t.Fatalf("SimpleScanTarget returned error: %v", err)
	}
}

// --- TLS integration tests for banner pre-filtering -------------------------

// TestIntegration_BannerPrefilter_TLS_SSHOnNonStandardPort verifies that
// SimpleScanTarget completes without error when a TLS-wrapped server sends
// an SSH banner after the handshake on a non-standard port.
func TestIntegration_BannerPrefilter_TLS_SSHOnNonStandardPort(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ap, cleanup := startTLSBannerMockServer(t, []byte("SSH-2.0-OpenSSH_8.9\r\n"))
	t.Cleanup(cleanup)

	cfg := Config{FastMode: false, DefaultTimeout: 5 * time.Second}
	target := plugins.Target{Address: ap}

	if _, err := cfg.SimpleScanTarget(target); err != nil {
		t.Fatalf("SimpleScanTarget returned error: %v", err)
	}
}

// TestIntegration_BannerPrefilter_TLS_UnknownFallsBackToFullIteration verifies
// that a TLS-wrapped server sending unrecognizable bytes does not narrow the
// candidate list and does not cause SimpleScanTarget to error or panic.
func TestIntegration_BannerPrefilter_TLS_UnknownFallsBackToFullIteration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ap, cleanup := startTLSBannerMockServer(t, []byte{0x01, 0x02, 0x03})
	t.Cleanup(cleanup)

	cfg := Config{FastMode: false, DefaultTimeout: 200 * time.Millisecond}
	target := plugins.Target{Address: ap}

	if _, err := cfg.SimpleScanTarget(target); err != nil {
		t.Fatalf("SimpleScanTarget returned error: %v", err)
	}
}

// TestIntegration_BannerPrefilter_TLS_ReusePreservesTLSFindings verifies that
// TLS connection reuse via prefixConn does not break plugins.CheckTLS — the
// Unwrap method must expose the underlying *tls.Conn so that TLS security
// findings (self-signed cert, weak key, etc.) are still returned.
func TestIntegration_BannerPrefilter_TLS_ReusePreservesTLSFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ap, cleanup := startTLSBannerMockServer(t, []byte("SSH-2.0-OpenSSH_8.9\r\n"))
	t.Cleanup(cleanup)

	cfg := Config{FastMode: false, DefaultTimeout: 5 * time.Second, Verbose: false}
	target := plugins.Target{Address: ap}

	// Dial a TLS connection (same as SimpleScanTarget does in the slow lane).
	tlsConn, err := cfg.DialTLS(target)
	if err != nil {
		t.Fatalf("DialTLS returned error: %v", err)
	}
	defer tlsConn.Close()

	// Pre-read the banner, then wrap in prefixConn (replicating the
	// connection-reuse path in SimpleScanTarget's slow TLS lane).
	banner, _ := ReadBanner(tlsConn, 0)
	_ = tlsConn.SetReadDeadline(time.Time{})
	wrapped := newPrefixConn(tlsConn, banner)

	// CheckTLS must see through the prefixConn wrapper to the underlying
	// *tls.Conn. Without the Unwrap method, the type assertion fails and
	// CheckTLS silently returns nil.
	findings := plugins.CheckTLS(wrapped)
	if len(findings) == 0 {
		t.Fatal("expected TLS security findings from CheckTLS on prefixConn-wrapped *tls.Conn, got none — prefixConn may be hiding *tls.Conn from CheckTLS")
	}
}

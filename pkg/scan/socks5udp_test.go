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

package scan

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// startMockSOCKS5UDPServer starts a minimal but *real* SOCKS5 server that
// implements the UDP ASSOCIATE command end-to-end: it performs the
// handshake, opens a relay socket, and actually forwards one datagram (and
// its reply) between the client and whatever target address is embedded in
// the SOCKS5 UDP header. This is deliberately more than a handshake stub
// (unlike startMockSOCKS5Server, which only completes the negotiation) so
// tests here can prove real data relay, not just a successful handshake.
func startMockSOCKS5UDPServer(t *testing.T) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				select {
				case <-done:
				default:
					handleMockSOCKS5UDPAssociate(conn)
				}
			}()
		}
	}()

	cleanup := func() {
		close(done)
		ln.Close()
	}
	return ln.Addr().String(), cleanup
}

func handleMockSOCKS5UDPAssociate(ctrl net.Conn) {
	defer ctrl.Close()

	buf := make([]byte, 256)
	n, err := ctrl.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	if _, err := ctrl.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	req := make([]byte, 10)
	if _, err := io.ReadFull(ctrl, req); err != nil || req[1] != 0x03 {
		return
	}

	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return
	}
	defer relay.Close()

	relayPort := relay.LocalAddr().(*net.UDPAddr).Port
	reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(relayPort >> 8), byte(relayPort)}
	if _, err := ctrl.Write(reply); err != nil {
		return
	}

	relayBuf := make([]byte, 2048)
	_ = relay.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, clientAddr, err := relay.ReadFromUDP(relayBuf)
	if err != nil {
		return
	}
	targetAddr, payload, err := parseSOCKS5UDPPacket(relayBuf[:n])
	if err != nil {
		return
	}

	targetConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		return
	}
	defer targetConn.Close()

	if _, err := targetConn.Write(payload); err != nil {
		return
	}

	_ = targetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 2048)
	n, err = targetConn.Read(respBuf)
	if err != nil {
		return
	}

	header, err := buildSOCKS5UDPHeader(targetAddr.IP.String(), uint16(targetAddr.Port))
	if err != nil {
		return
	}
	_, _ = relay.WriteToUDP(append(header, respBuf[:n]...), clientAddr)

	// Give the client a moment to read before the control connection (and
	// with it, the association) is torn down when this handler returns.
	time.Sleep(200 * time.Millisecond)
}

// TestIntegration_DialUDP_RealAssociateRoundTrip proves DialUDP performs an
// actual SOCKS5 UDP ASSOCIATE round trip through the proxy rather than
// failing outright or silently bypassing it. This is a regression test for
// the previous implementation, which used golang.org/x/net/proxy and always
// failed with "network not implemented" for *any* proxy (see
// golang.org/x/net/internal/socks.validateTarget), regardless of whether the
// configured proxy actually supported UDP ASSOCIATE.
func TestIntegration_DialUDP_RealAssociateRoundTrip(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer echoConn.Close()
	echoPort := echoConn.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 2048)
		n, from, err := echoConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		_, _ = echoConn.WriteToUDP(buf[:n], from)
	}()

	proxyAddr, cleanup := startMockSOCKS5UDPServer(t)
	defer cleanup()

	config := Config{
		Proxy:          fmt.Sprintf("socks5://%s", proxyAddr),
		DefaultTimeout: 2 * time.Second,
	}
	pd, err := NewProxyDialer(config)
	require.NoError(t, err)

	conn, err := pd.DialUDP("127.0.0.1", uint16(echoPort))
	require.NoError(t, err, "DialUDP should succeed against a proxy that genuinely supports UDP ASSOCIATE")
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	probe := []byte("udp-associate-roundtrip-probe")
	_, err = conn.Write(probe)
	require.NoError(t, err)

	respBuf := make([]byte, 2048)
	n, err := conn.Read(respBuf)
	require.NoError(t, err, "expected the echoed probe to come back through the proxy")
	require.Equal(t, probe, respBuf[:n])
}

// TestDialUDP_RejectsNonSOCKS5Proxy documents that HTTP/HTTPS proxies cannot
// relay UDP at all (they only tunnel TCP via CONNECT) - DialUDP should fail
// fast with a clear error instead of attempting anything.
func TestDialUDP_RejectsNonSOCKS5Proxy(t *testing.T) {
	t.Helper()

	config := Config{
		Proxy:          "http://127.0.0.1:8080",
		DefaultTimeout: 2 * time.Second,
	}
	pd, err := NewProxyDialer(config)
	require.NoError(t, err)

	_, err = pd.DialUDP("127.0.0.1", 53)
	require.Error(t, err)
	require.Contains(t, err.Error(), "socks5")
}

// TestResolveUnspecifiedRelayIP is a regression test for
// resolveUnspecifiedRelayIP, the helper that substitutes a 0.0.0.0 BND.ADDR
// reply with the SOCKS5 control connection's actual resolved remote address.
//
// This is deliberately a pure unit test rather than a live-network one: an
// earlier version dialed the (still-unspecified-on-bug) relay address with
// net.DialUDP and asserted the resulting RemoteAddr() was loopback, but on
// Linux, connecting a UDP socket to 0.0.0.0 is itself silently normalized to
// 127.0.0.1 by the kernel - so that test passed even against the pre-fix
// code, since the test's proxy also happened to be on loopback. Using a
// TEST-NET-3 address (RFC 5737, guaranteed non-loopback and non-routable)
// for the control connection's remote address sidesteps that OS-level
// quirk entirely and actually distinguishes fixed from broken.
func TestResolveUnspecifiedRelayIP(t *testing.T) {
	t.Helper()

	documentationIP := net.ParseIP("203.0.113.5") // RFC 5737 TEST-NET-3

	tests := []struct {
		name           string
		relayIP        net.IP
		ctrlRemoteAddr net.Addr
		want           net.IP
	}{
		{
			name:           "already-specified BND.ADDR is kept as-is",
			relayIP:        net.ParseIP("198.51.100.7"), // RFC 5737 TEST-NET-2
			ctrlRemoteAddr: &net.TCPAddr{IP: documentationIP, Port: 1080},
			want:           net.ParseIP("198.51.100.7"),
		},
		{
			name:           "unspecified IPv4 BND.ADDR is substituted with the control conn's remote IP",
			relayIP:        net.IPv4zero,
			ctrlRemoteAddr: &net.TCPAddr{IP: documentationIP, Port: 1080},
			want:           documentationIP,
		},
		{
			name:           "unspecified IPv6 BND.ADDR is substituted with the control conn's remote IP",
			relayIP:        net.IPv6zero,
			ctrlRemoteAddr: &net.TCPAddr{IP: documentationIP, Port: 1080},
			want:           documentationIP,
		},
		{
			name:           "non-TCPAddr remote (unexpected, but must not panic) leaves relayIP as-is",
			relayIP:        net.IPv4zero,
			ctrlRemoteAddr: &net.UDPAddr{IP: documentationIP, Port: 1080},
			want:           net.IPv4zero,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Helper()
			got := resolveUnspecifiedRelayIP(tt.relayIP, tt.ctrlRemoteAddr)
			require.True(t, tt.want.Equal(got), "got %s, want %s", got, tt.want)
		})
	}
}

// TestDialSOCKS5UDP_RemoteAddrResolvesDomainTarget is a regression test:
// RemoteAddr() used to return net.ParseIP(targetHost), which is nil whenever
// the target was specified as a domain name rather than an IP literal - a
// real, supported path via socks5h:// (see ResolveTargets /
// TestIntegration_ResolveTargets_Socks5h). At least one plugin (tftp.go)
// uses conn.RemoteAddr() as an actual destination address for a follow-up
// packet, so a nil IP there breaks that plugin against domain-named targets.
func TestDialSOCKS5UDP_RemoteAddrResolvesDomainTarget(t *testing.T) {
	t.Helper()

	proxyAddr, cleanup := startMockSOCKS5UDPServer(t)
	defer cleanup()

	conn, err := dialSOCKS5UDP(context.Background(), &net.Dialer{Timeout: 2 * time.Second}, proxyAddr, "", "", 2*time.Second, "localhost:9")
	require.NoError(t, err)
	defer conn.Close()

	remote, ok := conn.RemoteAddr().(*net.UDPAddr)
	require.True(t, ok)
	require.NotNil(t, remote.IP,
		"RemoteAddr() must resolve a domain target to a real IP, not nil - tftp.go uses it as an actual destination address")
}

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

package oracleprotocoldb

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// shortTimeout bounds every Run() call in the loopback tests below. It must be
// short enough that the "hold until deadline" cases resolve quickly, but long
// enough that the -race build (slower scheduling) doesn't spuriously time out
// the "server responds immediately" cases.
const shortTimeout = 150 * time.Millisecond

// ---------------------------------------------------------------------------
// Section 1: shared loopback-server helpers (mirrors activemq_test.go /
// oraclegoldengate_test.go: net.Listen("tcp","127.0.0.1:0"), one Accept
// goroutine running a scripted behavior, net.DialTimeout for the client side).
// ---------------------------------------------------------------------------

// scriptedServer starts a 127.0.0.1:0 listener, runs behavior on the ONE
// accepted conn in a goroutine, and returns the dialed CLIENT conn + a Target
// describing it. t.Cleanup closes the listener (registered before the
// goroutine) so a never-dialed Accept unblocks cleanly under -race.
func scriptedServer(t *testing.T, behavior func(net.Conn)) (net.Conn, plugins.Target) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		behavior(conn)
	}()

	addrPort, ok := ln.Addr().(*net.TCPAddr)
	require.True(t, ok, "listener address is not TCP")
	target := plugins.Target{
		Host:    addrPort.IP.String(),
		Address: netip.MustParseAddrPort(addrPort.String()),
	}

	conn, err := net.DialTimeout("tcp", addrPort.String(), 5*time.Second)
	require.NoError(t, err)
	return conn, target
}

// assertDetectionOnly is the cross-cutting invariant: every positive detection
// from any of the four plugins must carry no SecurityFinding, no
// AnonymousAccess, no Version, no TLS, and exactly the one expected CPE.
func assertDetectionOnly(t *testing.T, svc *plugins.Service, wantProto, wantCPE string) {
	t.Helper()
	require.NotNil(t, svc)
	assert.Equal(t, wantProto, svc.Protocol)
	assert.Equal(t, "", svc.Version)
	assert.False(t, svc.TLS)
	assert.False(t, svc.AnonymousAccess)
	assert.Nil(t, svc.SecurityFindings)

	var cpes struct {
		CPEs []string `json:"cpes,omitempty"`
	}
	require.NoError(t, json.Unmarshal(svc.Raw, &cpes))
	require.Len(t, cpes.CPEs, 1)
	assert.Equal(t, wantCPE, cpes.CPEs[0])
}

// drainOnce performs a single best-effort read to consume whatever the client
// has already written, so the client's own Write doesn't block on a full
// kernel send buffer. Errors are ignored: the round may legitimately be empty.
func drainOnce(conn net.Conn) {
	buf := make([]byte, 4096)
	_, _ = conn.Read(buf)
}

// writeOnce drains one request, writes resp (if any), then closes. Used for
// every single-round-trip plugin (TimesTen, Coherence) and for round-1-only
// NoSQL cases.
func writeOnce(resp []byte) func(net.Conn) {
	return func(conn net.Conn) {
		defer conn.Close()
		drainOnce(conn)
		if len(resp) > 0 {
			_, _ = conn.Write(resp)
		}
	}
}

// closeImmediately closes the accepted connection without reading or writing
// anything -> the client's Send/Recv observes an immediate peer close.
func closeImmediately(conn net.Conn) {
	_ = conn.Close()
}

// holdOpen drains whatever arrives but never writes and never closes on its
// own; it blocks until the peer (the client conn, closed by the test) tears
// down the connection. This models "server holds the conn open until the
// client's read deadline fires" with no time.Sleep and no goroutine leak.
func holdOpen(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}

// buildValidAck constructs a structurally-valid JRMP ProtocolAck for host:port
// that satisfies all 5 layers of isValidRMIResponse and is parseable by
// extractEndpoint(ack[1:]).
func buildValidAck(host string, port uint16) []byte {
	hostBytes := []byte(host)
	buf := make([]byte, 0, 1+2+len(hostBytes)+2+2)
	buf = append(buf, jrmpProtocolAck)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(hostBytes)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, hostBytes...)
	buf = append(buf, 0x00, 0x00) // null separator
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], port)
	buf = append(buf, portBuf[:]...)
	return buf
}

// ackThenListing drains round 1, writes ack, drains round 2, writes listing.
func ackThenListing(ack, listing []byte) func(net.Conn) {
	return func(conn net.Conn) {
		defer conn.Close()
		drainOnce(conn)
		if _, err := conn.Write(ack); err != nil {
			return
		}
		drainOnce(conn)
		if len(listing) > 0 {
			_, _ = conn.Write(listing)
		}
	}
}

// ackThenSplitListing drains round 1, writes ack, drains round 2, then writes
// the listing across TWO separate conn.Write calls: a marker-free prefix
// followed by a suffix carrying the NoSQL marker. pluginutils.Recv performs
// exactly one conn.Read() per call into a fixed 4096-byte buffer (requests.go),
// so a prefix >4096 bytes guarantees the first Recv in NoSQLPlugin's round-2
// read loop can only return (part of) the marker-free prefix; the marker only
// becomes visible in the accumulated buffer once the loop consumes a second
// Recv. This deterministically exercises the multi-read accumulation path
// (no timing/sleep dependency): Read never returns more than the buffer size
// regardless of how much of the two Writes has already arrived in the kernel
// socket buffer.
func ackThenSplitListing(ack, prefix, suffix []byte) func(net.Conn) {
	return func(conn net.Conn) {
		defer conn.Close()
		drainOnce(conn)
		if _, err := conn.Write(ack); err != nil {
			return
		}
		drainOnce(conn)
		if _, err := conn.Write(prefix); err != nil {
			return
		}
		if len(suffix) > 0 {
			_, _ = conn.Write(suffix)
		}
	}
}

// ackThenCloseBeforeRound2 writes the round-1 ack, then closes without ever
// responding to round 2 (models a server that resets after the handshake).
func ackThenCloseBeforeRound2(ack []byte) func(net.Conn) {
	return func(conn net.Conn) {
		defer conn.Close()
		drainOnce(conn)
		_, _ = conn.Write(ack)
	}
}

// ackThenHoldRound2 writes the round-1 ack, then holds round 2 open until the
// client's deadline fires (never writes a listing).
func ackThenHoldRound2(ack []byte) func(net.Conn) {
	return func(conn net.Conn) {
		defer conn.Close()
		drainOnce(conn)
		if _, err := conn.Write(ack); err != nil {
			return
		}
		buf := make([]byte, 4096)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}
}

// partialThenErrorConn wraps a net.Conn so that its Nth Read call (errorOnCall)
// returns injectPartial bytes TOGETHER WITH a non-nil, non-timeout error -
// modeling pluginutils.Recv's "partial read: N bytes before error" branch
// (response[:length], &ReadError{...}) for a connection reset mid-listing.
// This is injected directly rather than relying on OS-level TCP timing to
// combine a data delivery and a close into a single syscall, which is not
// reliably reproducible over a real loopback connection. All other Read calls,
// and every other net.Conn method, forward unchanged to the embedded conn.
type partialThenErrorConn struct {
	net.Conn
	errorOnCall   int
	calls         int
	injectPartial []byte
}

func (c *partialThenErrorConn) Read(b []byte) (int, error) {
	c.calls++
	if c.calls == c.errorOnCall {
		n := copy(b, c.injectPartial)
		return n, errors.New("simulated connection reset mid-read")
	}
	return c.Conn.Read(b)
}

// splitReadConn wraps a net.Conn so its FIRST Read call is capped to at most
// maxFirst bytes, deterministically forcing a multi-Read accumulation (FIX
// 1/3's bounded round-1 handshake / TimesTen reject-prefix accumulation
// loops) rather than relying on OS-level TCP-segment timing, which does not
// reliably split a single small Write across loopback reads. All later Read
// calls, and every other net.Conn method, forward unchanged to the embedded
// conn.
type splitReadConn struct {
	net.Conn
	calls    int
	maxFirst int
}

func (c *splitReadConn) Read(b []byte) (int, error) {
	c.calls++
	if c.calls == 1 && len(b) > c.maxFirst {
		return c.Conn.Read(b[:c.maxFirst])
	}
	return c.Conn.Read(b)
}

// httpOnce drains the client's HTTP request and writes back a raw HTTP
// response built from statusLine and body.
func httpOnce(statusLine, body string) func(net.Conn) {
	raw := fmt.Sprintf("%s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", statusLine, len(body), body)
	return writeOnce([]byte(raw))
}

// coherenceClientAndBaseURL spins up scriptedServer(t, behavior) and wraps the
// dialed client conn in createCoherenceHTTPClient (the keep-alive client
// shared by both Coherence HTTP plugins), returning the client plus baseURL
// (built the same way Run() builds it: "http://"+conn.RemoteAddr()) so
// detectCoherenceMetrics/detectCoherenceManagement can be exercised directly
// with a single scripted round-trip. The caller still owns conn and must
// defer conn.Close(), mirroring every other loopback helper in this file.
func coherenceClientAndBaseURL(t *testing.T, behavior func(net.Conn)) (*http.Client, string, net.Conn) {
	t.Helper()
	conn, _ := scriptedServer(t, behavior)
	client := createCoherenceHTTPClient(conn, shortTimeout)
	return client, "http://" + conn.RemoteAddr().String(), conn
}

// dialHTTPTestServer dials an httptest.Server's address directly and returns
// the raw client conn plus a matching Target. The conn is fed into
// createCoherenceHTTPClient's DialContext exactly as
// CoherenceHTTPPlugin/CoherenceHTTPTLSPlugin.Run feed it the framework-dialed
// conn. httptest.Server is a real net/http server, so it natively answers
// several sequential GETs over the ONE resulting keep-alive connection - the
// Coherence HTTP detectors issue up to three (metrics, then the two
// management paths) - without any hand-rolled request/response scripting.
// Mirrors the identical helper already used by oraclegoldengate_test.go /
// oracleidentity_test.go for their own HTTP-plugin Run() tests.
func dialHTTPTestServer(t *testing.T, serverURL string) (net.Conn, plugins.Target) {
	t.Helper()
	hostPort := strings.TrimPrefix(serverURL, "http://")
	host, portStr, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	addr := netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))

	conn, err := net.DialTimeout("tcp", hostPort, 5*time.Second)
	require.NoError(t, err)

	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}
	return conn, target
}

// ---------------------------------------------------------------------------
// Section 2.1: TestIsValidRMIResponse (re-derived JRMP validator)
// ---------------------------------------------------------------------------

func TestIsValidRMIResponse(t *testing.T) {
	validAck := buildValidAck("172.18.0.1", 64612)

	invalidFirstByte := buildValidAck("172.18.0.1", 64612)
	invalidFirstByte[0] = 0x4f // ProtocolNack

	validWithExtra := append(append([]byte{}, validAck...), 0x01, 0x02, 0x03)

	tests := []struct {
		name     string
		response []byte
		expected bool
	}{
		{"valid ack", validAck, true},
		{"too short - 2 bytes", []byte{0x4e, 0x00}, false},
		{"wrong first byte - ProtocolNack", invalidFirstByte, false},
		{"claimed length 2 - too short", []byte{0x4e, 0x00, 0x02, 'a', 'b'}, false},
		{"claimed length 256 - too long", []byte{0x4e, 0x01, 0x00}, false},
		{"short for claim", []byte{0x4e, 0x00, 0x0a, '1', '2', '3'}, false},
		{
			"non-printable endpoint",
			[]byte{0x4e, 0x00, 0x05, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0x00, 0x00, 0x00, 0x50},
			false,
		},
		{"valid with trailing extra bytes", validWithExtra, true},
		{
			"minimum valid response (len==3)",
			[]byte{0x4e, 0x00, 0x03, '1', '.', '2', 0x00, 0x00, 0x04, 0x4b},
			true,
		},
		{"empty", []byte{}, false},
		{
			"coincidental 0x4e - unreasonable length",
			[]byte{0x4e, 0xff, 0xff, 0x01, 0x02, 0x03, 0x04},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isValidRMIResponse(tt.response))
		})
	}
}

// ---------------------------------------------------------------------------
// Section 2.1b: TestCouldBePartialRMIAck (FIX 1/3 round-1 accumulation guard)
// ---------------------------------------------------------------------------

func TestCouldBePartialRMIAck(t *testing.T) {
	validAck := buildValidAck("172.18.0.1", 64612)

	tests := []struct {
		name     string
		resp     []byte
		expected bool
	}{
		{"empty", []byte{}, false},
		{"wrong first byte - not ProtocolAck", []byte{0x4f}, false},
		{"1 byte, correct ProtocolAck - too short to hold length field", []byte{jrmpProtocolAck}, true},
		{"2 bytes, correct ProtocolAck - still too short", []byte{jrmpProtocolAck, 0x00}, true},
		{"claimed length too small (<3) - contradicts", []byte{jrmpProtocolAck, 0x00, 0x02}, false},
		{"claimed length too large (>253) - contradicts", []byte{jrmpProtocolAck, 0x01, 0x00}, false},
		{
			"full structural length already present - isValidRMIResponse failed for a non-length reason",
			validAck, false,
		},
		{
			"partial endpoint bytes so far are all printable - could still complete",
			validAck[:13], // ProtocolAck + 2-byte length + 10-byte host, before the null separator
			true,
		},
		{
			"partial endpoint bytes contain a non-printable byte - contradicts",
			[]byte{jrmpProtocolAck, 0x00, 0x05, 0xff, 0xfe},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, couldBePartialRMIAck(tt.resp))
		})
	}
}

// ---------------------------------------------------------------------------
// Section 2.2: TestExtractEndpoint
// ---------------------------------------------------------------------------

func TestExtractEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "valid endpoint with port",
			data:     []byte{0x00, 0x0a, '1', '7', '2', '.', '1', '8', '.', '0', '.', '1', 0x00, 0x00, 0xfc, 0x64},
			expected: "172.18.0.1:64612",
		},
		{
			name:     "localhost endpoint",
			data:     []byte{0x00, 0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x00, 0x00, 0x04, 0x4b},
			expected: "localhost:1099",
		},
		{
			name:     "host-only branch - no port bytes",
			data:     []byte{0x00, 0x04, 't', 'e', 's', 't'},
			expected: "test",
		},
		{
			name:     "too short - no length field",
			data:     []byte{0x00},
			expected: "",
		},
		{
			name:     "claimed length exceeds actual data",
			data:     []byte{0x00, 0x14, 't', 'e', 's', 't'},
			expected: "",
		},
		{
			name:     "empty",
			data:     []byte{},
			expected: "",
		},
		{
			name:     "port==0 falls through to host-only",
			data:     []byte{0x00, 0x04, 't', 'e', 's', 't', 0x00, 0x00, 0x00, 0x00},
			expected: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractEndpoint(tt.data))
		})
	}
}

// ---------------------------------------------------------------------------
// Section 2.3: TestOracleNoSQLListingMatches (sole discriminator is the
// oracle.kv class token; the loose binding-name-triad heuristic and its
// port-gating were deleted in a follow-up review to stop LLM-reviewer
// oscillation, so classification is no longer port-dependent)
// ---------------------------------------------------------------------------

func TestOracleNoSQLListingMatches(t *testing.T) {
	noise := bytes.Repeat([]byte{0xac, 0xed, 0x00, 0x05}, 4)

	tests := []struct {
		name     string
		reply    []byte
		expected bool
	}{
		{"oracle.kv.impl class token", append(append([]byte{}, noise...), []byte("oracle.kv.impl.api.KVStoreImpl")...), true},
		{"bare oracle.kv class token", append(append([]byte{}, noise...), []byte("oracle.kv")...), true},
		{
			// The binding-triad heuristic is gone: a bare triad with no
			// oracle.kv class token must NOT classify, even though this is
			// the exact shape the old port-gated heuristic used to trust.
			"binding triad alone (store:sn1:MAIN), no class token - not detected: the triad heuristic was removed",
			[]byte("store:sn1:MAIN"), false,
		},
		{
			"generic RMI role collides with a real enum member (service:node:ADMIN), no class token - not detected",
			[]byte("service:node:ADMIN"), false,
		},
		{"generic jmxrmi only, no class token - not detected", []byte("jmxrmi"), false},
		{"generic JBoss RMI, no class token - not detected", []byte("org.jnp.interfaces.NamingContext"), false},
		{"empty listing - not detected", []byte{}, false},
		{"random binary noise, no marker - not detected", bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x04}, 16), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, oracleNoSQLListingMatches(tt.reply))
		})
	}
}

// ---------------------------------------------------------------------------
// Section 2.4: TestIsOracleNoSQLProxy (HTTP corroboration) - FP guard
// ---------------------------------------------------------------------------

func httpRespWithLocation(location string) *http.Response {
	h := http.Header{}
	if location != "" {
		h.Set("Location", location)
	}
	return &http.Response{Header: h}
}

func TestIsOracleNoSQLProxy(t *testing.T) {
	tests := []struct {
		name     string
		resp     *http.Response
		body     string
		expected bool
	}{
		{"marker: oracle nosql", httpRespWithLocation(""), "...Oracle NoSQL...", true},
		{"marker: nosql database proxy", httpRespWithLocation(""), "NoSQL Database Proxy", true},
		{"marker: kvproxy", httpRespWithLocation(""), "kvproxy/1.0", true},
		{"marker: oracle.kv", httpRespWithLocation(""), "oracle.kv", true},
		{"marker: kvstore", httpRespWithLocation(""), "kvstore", true},
		{"marker: nosql proxy", httpRespWithLocation(""), "nosql proxy", true},
		{
			"regression PR #385: 'ords' word-boundary fix - 'records' contains bare substring 'ords' but must not be rejected",
			httpRespWithLocation(""), "Oracle NoSQL proxy records", true,
		},
		{
			"regression PR #385: 'ords' word-boundary fix - 'keywords' contains bare substring 'ords' but must not be rejected",
			httpRespWithLocation(""), "keywords: kvproxy", true,
		},
		{"bare 200, no marker", httpRespWithLocation(""), "<html>OK</html>", false},
		{"marker + ords in body - ORDS reject precedes marker loop", httpRespWithLocation(""), "oracle nosql ords", false},
		{"apex in body - APEX reject", httpRespWithLocation(""), "apex login", false},
		{"Location ORDS reject", httpRespWithLocation("/ords/f?p=..."), "oracle nosql", false},
		{
			"marker only in Location, empty body - a redirect may carry the product name before any body is sent",
			httpRespWithLocation("/oracle.kv/redirect"),
			"",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isOracleNoSQLProxy(tt.resp, tt.body))
		})
	}
}

// ---------------------------------------------------------------------------
// Section 2.5: TestIsTimesTenHTTPReject - FP guard #3
// ---------------------------------------------------------------------------

func TestIsTimesTenHTTPReject(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			"exact prefix + binary tail",
			append([]byte("HTTP/1.0 400 msg=Bad%20Request&rc="), 0x01, 0x02, 0x00),
			true,
		},
		{"exact prefix, no tail", []byte("HTTP/1.0 400 msg=Bad%20Request&rc="), true},
		{
			"regression PR #385: HTTP/1.1 tolerance - exact prefix + binary tail",
			append([]byte("HTTP/1.1 400 msg=Bad%20Request&rc="), 0x01, 0x02, 0x00),
			true,
		},
		{"no rc= shape", []byte("HTTP/1.0 400 Bad Request"), false},
		{"well-formed generic 400", []byte("HTTP/1.1 400 Bad Request\r\nServer: x\r\n\r\n"), false},
		{"empty", []byte{}, false},
		{"truncated prefix", []byte("HTTP/1.0 400 msg=Bad"), false},
		{"TLS bytes", []byte{0x16, 0x03, 0x01, 0x00}, false},
		{"bare 200 OK", []byte("HTTP/1.0 200 OK"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isTimesTenHTTPReject(tt.input))
		})
	}
}

// ---------------------------------------------------------------------------
// Section 2.5b: TestCouldBeTimesTenRejectPrefix (FIX 1/3 TimesTen
// accumulation guard)
// ---------------------------------------------------------------------------

func TestCouldBeTimesTenRejectPrefix(t *testing.T) {
	tests := []struct {
		name     string
		resp     []byte
		expected bool
	}{
		{"empty - trivially a prefix of HTTP/1.", []byte{}, true},
		{"exact prefix so far", []byte("HTTP/1."), true},
		{"strict prefix of the reject prefix", []byte("HTT"), true},
		{"already begins with the full status line", []byte("HTTP/1.0 400 "), true},
		{"contradicts - wrong leading bytes entirely", []byte("SSH-2.0"), false},
		{"contradicts - same length, diverges mid-prefix", []byte("HTTP/2.0"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, couldBeTimesTenRejectPrefix(tt.resp))
		})
	}
}

func TestCouldBeCoherencePOFPrefix(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{"empty", nil, false},
		{"incomplete frame (body not yet complete)", []byte{0x03, 0x00}, true},
		{"complete exact frame is not a prefix", []byte{0x03, 0x00, 0x01, 0x02}, false},
		{"overshoot contradicts", []byte{0x01, 0x00, 0x01, 0x02}, false},
		{"TLS contradicts", []byte{0x16, 0x03, 0x01, 0x00}, false},
		{"JRMP contradicts", []byte{jrmpProtocolAck, 0x00, 0x09}, false},
		{"printable banner contradicts", []byte("hello world"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, couldBeCoherencePOFPrefix(tt.input))
		})
	}
}

// ---------------------------------------------------------------------------
// Section 2.6: TestDecodePackedInt (POF signed packed int)
// ---------------------------------------------------------------------------

func TestDecodePackedInt(t *testing.T) {
	tests := []struct {
		name         string
		input        []byte
		wantValue    int64
		wantConsumed int
		wantOK       bool
	}{
		{"single-octet positive", []byte{0x03}, 3, 1, true},
		{"zero (probe echo)", []byte{0x00}, 0, 1, true},
		{"negative flag, no continuation", []byte{0x41}, -2, 1, true},
		{"continuation -> value 1<<6", []byte{0x80, 0x01}, 64, 2, true},
		{"empty", []byte{}, 0, 0, false},
		{"truncated mid-integer", []byte{0x80}, 0, 0, false},
		{"overflow guard (bits>56)", append(bytes.Repeat([]byte{0x80}, 10), 0x01), 0, 0, false},
		{"bit6 set, no continuation", []byte{0x7f}, -64, 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, consumed, ok := decodePackedInt(tt.input)
			assert.Equal(t, tt.wantOK, ok, "ok")
			assert.Equal(t, tt.wantValue, value, "value")
			assert.Equal(t, tt.wantConsumed, consumed, "consumed")
		})
	}
}

// ---------------------------------------------------------------------------
// Section 2.7: TestIsLikelyCoherencePOF - FP guard #1, HIGHEST RISK
// ---------------------------------------------------------------------------

func TestIsLikelyCoherencePOF(t *testing.T) {
	// Positive fixture 1: single-octet packed-int length. decodePackedInt({0x03})
	// -> (value=3, consumed=1). 1+3 == 4 == len(resp).
	positiveSingleOctet := []byte{0x03, 0x00, 0x01, 0x02}

	// Positive fixture 2: multi-octet packed-int length. decodePackedInt({0x80,0x01})
	// -> (value=64, consumed=2). 2+64 == 66 == len(resp). Tail is 64 bytes of
	// 0xFF: non-printable, and does not spell "JRMI" or "Coherence".
	positiveMultiOctet := append([]byte{0x80, 0x01}, bytes.Repeat([]byte{0xFF}, 64)...)

	overLength := bytes.Repeat([]byte{0xFF}, coherenceMaxFrame+1)

	coherenceFalseFriend := append([]byte{0x01, 0x02}, []byte("Coherence")...)
	coherenceFalseFriend = append(coherenceFalseFriend, 0x03, 0x04)

	printableBanner := []byte("ABCDEFGHIJKLMNOPQRST") // 20 bytes, 100% printable

	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{"POSITIVE: single-octet length frame-consistent", positiveSingleOctet, true},
		{"POSITIVE: multi-octet length frame-consistent", positiveMultiOctet, true},
		{"empty (also the silence guard)", []byte{}, false},
		{"over coherenceMaxFrame", overLength, false},
		{"TLS discriminator", []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x02}, false},
		{"SSH discriminator", []byte("SSH-2.0-OpenSSH_9\r\n"), false},
		{"HTTP status-line discriminator", []byte("HTTP/1.1 200 OK\r\n"), false},
		{"HTTP verb discriminator", []byte("GET / HTTP/1.1\r\n"), false},
		{"JRMP ProtocolAck discriminator", buildValidAck("172.18.0.1", 64612), false},
		{"JRMP magic JRMI discriminator", append([]byte{0x01, 0x02}, []byte("JRMIxyz")...), false},
		{"Java serialization header discriminator", []byte{0xac, 0xed, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04}, false},
		{"Coherence UPnP/DLNA false friend", coherenceFalseFriend, false},
		{"text banner reject (mostly printable)", printableBanner, false},
		{"length-INCONSISTENT (1+5 != 4)", []byte{0x05, 0x00, 0x01, 0x02}, false},
		{"declaredLength 0 - probe echo", []byte{0x00}, false},
		{"negative declaredLength reject", []byte{0x41, 0x00}, false},
		{"decodePackedInt truncated - not ok", []byte{0x80}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isLikelyCoherencePOF(tt.input))
		})
	}
}

// TestCoherencePOFFixtureIntegrity is the Risk-1 mandated check: first prove
// the positive fixture is detected, THEN mutate exactly one byte and prove the
// classifier flips to reject. This guards against a hand-built fixture that
// accidentally trips a negative discriminator and gives false confidence.
func TestCoherencePOFFixtureIntegrity(t *testing.T) {
	fixture := []byte{0x03, 0x00, 0x01, 0x02}
	require.True(t, isLikelyCoherencePOF(fixture), "sanity: positive fixture must be detected before mutation")

	mutated := append([]byte{}, fixture...)
	mutated[0] = 0x05 // declaredLength becomes 5: 1+5 == 6 != len(mutated)==4
	assert.False(t, isLikelyCoherencePOF(mutated), "single-byte mutation must flip the classifier to reject")
}

// ---------------------------------------------------------------------------
// Section 2.8: TestCoherenceDiscriminatorHelpers - robustness / no-panic
// ---------------------------------------------------------------------------

func TestLooksLikeTLS(t *testing.T) {
	assert.True(t, looksLikeTLS([]byte{0x16, 0x03}))
	assert.False(t, looksLikeTLS([]byte{0x16})) // short, must not panic
	assert.False(t, looksLikeTLS([]byte{0x15, 0x03}))
	assert.False(t, looksLikeTLS([]byte{}))
}

func TestLooksLikeSSH(t *testing.T) {
	assert.True(t, looksLikeSSH([]byte("SSH-2.0-OpenSSH")))
	assert.False(t, looksLikeSSH([]byte("SS")))
	assert.False(t, looksLikeSSH([]byte{}))
}

func TestLooksLikeHTTP(t *testing.T) {
	for _, verb := range []string{"HTTP/", "GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "DELETE "} {
		assert.True(t, looksLikeHTTP([]byte(verb+"rest")), "verb %q", verb)
	}
	assert.False(t, looksLikeHTTP([]byte("GE")))
	assert.False(t, looksLikeHTTP([]byte{}))
}

func TestLooksLikeJRMP(t *testing.T) {
	assert.True(t, looksLikeJRMP([]byte{0x4e}))
	assert.True(t, looksLikeJRMP([]byte{0xac, 0xed}))
	assert.True(t, looksLikeJRMP([]byte("xxJRMIxx")))
	assert.False(t, looksLikeJRMP([]byte{0xac})) // short, must not panic
	assert.False(t, looksLikeJRMP([]byte{}))
}

func TestIsMostlyPrintable(t *testing.T) {
	assert.True(t, isMostlyPrintable([]byte("AAAAAAAAAA"))) // all-ASCII
	assert.False(t, isMostlyPrintable([]byte{}))
	assert.False(t, isMostlyPrintable(bytes.Repeat([]byte{0xFF}, 10))) // mostly-binary
	// 90% boundary: 9 printable of 10 -> true; 8 of 10 -> false.
	nine := append(bytes.Repeat([]byte("A"), 9), 0xFF)
	assert.True(t, isMostlyPrintable(nine))
	eight := append(bytes.Repeat([]byte("A"), 8), 0xFF, 0xFF)
	assert.False(t, isMostlyPrintable(eight))
}

// ---------------------------------------------------------------------------
// Section 2.9: TestProbesAndRegistryCall - probe/builder integrity (P0-8)
// ---------------------------------------------------------------------------

func TestBuildJRMPHandshake(t *testing.T) {
	h := buildJRMPHandshake()
	require.Len(t, h, 7)
	assert.True(t, bytes.HasPrefix(h, []byte("JRMI")))
	assert.Equal(t, []byte{0x00, 0x02, 0x4b}, h[4:7])
}

func TestProbeConstants(t *testing.T) {
	assert.Equal(t, []byte{0x00}, coherenceProbe)
	assert.Equal(t, []byte{0x0d, 0x0a, 0x0d, 0x0a}, timesTenProbe)
}

func TestBuildRegistryListCall(t *testing.T) {
	call := buildRegistryListCall()
	require.Len(t, call, 47)

	// TransportConstants.Call marker at offset 6.
	assert.Equal(t, byte(0x50), call[6])

	// TC_BLOCKDATA framing (offsets 11-12): tag 0x77 + one-byte block length
	// 0x22 (34 = 22 ObjID + 4 op index + 8 interface hash), immediately before
	// the call arguments. Without this the arguments would be raw bytes after
	// the ObjectOutputStream header, which a real ObjectInputStream would
	// misread as a type code and reject.
	assert.Equal(t, byte(0x77), call[11])
	assert.Equal(t, byte(0x22), call[12])

	// 22-byte well-known registry ObjID (offset 13..35) must be all-zero -
	// this proves the call targets ObjID 0, not an attacker-supplied object.
	assert.Equal(t, make([]byte, 22), call[13:35])

	// Operation index = 1 (Registry.list()), NOT bind(2)/unbind(3)/rebind(4).
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x01}, call[35:39])

	// Trailing 8 bytes decode to the well-known RegistryImpl interface hash.
	assert.Equal(t, registryInterfaceHash, binary.BigEndian.Uint64(call[39:47]))
}

func TestItoa(t *testing.T) {
	assert.Equal(t, "0", itoa(0))
	assert.Equal(t, "7", itoa(7))
	assert.Equal(t, "1099", itoa(1099))
	assert.Equal(t, "64612", itoa(64612))
}

// ---------------------------------------------------------------------------
// Section 3.1: TestNoSQLPluginRun (loopback, two round-trips)
// ---------------------------------------------------------------------------

func TestNoSQLPluginRun(t *testing.T) {
	ack := buildValidAck("10.0.0.5", 5000)
	classMarkerListing := append([]byte{0xac, 0xed, 0x00, 0x05}, []byte("oracle.kv.impl.api.KVStoreImpl")...)
	// bindingTriadOnlyListing is a bare <store>:<resourceId>:<InterfaceType>
	// binding name with NO oracle.kv class token anywhere in the reply. The
	// binding-triad heuristic (and its port gate) was deleted in a follow-up
	// review to stop LLM-reviewer oscillation, so this must NOT classify
	// regardless of port.
	bindingTriadOnlyListing := []byte("service:node:ADMIN")
	genericListing := []byte("jmxrmi org.jnp.interfaces.NamingContext")
	invalidAck := buildValidAck("10.0.0.5", 5000)
	invalidAck[0] = 0x4f

	t.Run("ack then oracle.kv listing - detected", func(t *testing.T) {
		conn, target := scriptedServer(t, ackThenListing(ack, classMarkerListing))
		defer conn.Close()

		svc, err := (&NoSQLPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleNoSQL, nosqlCPE)

		var payload plugins.ServiceOracleNoSQL
		require.NoError(t, json.Unmarshal(svc.Raw, &payload))
		assert.Equal(t, "10.0.0.5:5000", payload.Endpoint)
		assert.False(t, payload.ViaHTTP)
	})

	t.Run("round-1 JRMP ack split across two reads - detected", func(t *testing.T) {
		// FIX 1/3: TCP may split the fixed-size JRMP ProtocolAck across
		// segments, so Run accumulates up to 2 extra bounded reads while the
		// bytes-so-far stay consistent with an incomplete ack
		// (couldBePartialRMIAck). splitReadConn deterministically caps the
		// very first Read to 1 byte - far short of the full ack - forcing Run
		// to exercise that accumulation loop instead of relying on real
		// TCP-segment timing.
		conn, target := scriptedServer(t, ackThenListing(ack, classMarkerListing))
		defer conn.Close()
		wrapped := &splitReadConn{Conn: conn, maxFirst: 1}

		svc, err := (&NoSQLPlugin{}).Run(wrapped, shortTimeout, target)
		require.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleNoSQL, nosqlCPE)
	})

	t.Run("round-1 ack truncated to 1 byte then connection closes - accumulation gives up, not detected", func(t *testing.T) {
		// FIX 3: the round-1 accumulation loop stops as soon as an extra Recv
		// comes back with an error or no bytes (a reset/EOF mid-accumulation),
		// rather than looping further. A single ProtocolAck byte followed by a
		// close is still "could be partial" (too short to hold the length
		// field), so this exercises that give-up branch deterministically.
		conn, target := scriptedServer(t, writeOnce([]byte{jrmpProtocolAck}))
		defer conn.Close()

		svc, err := (&NoSQLPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("ack then oracle.kv listing on a non-5000 port - detected (classification is not port-gated)", func(t *testing.T) {
		// Classification rests solely on the oracle.kv class token, which is
		// trusted on ANY port now that the port-gated binding-triad special
		// case was deleted. Prove detection still fires when the target port
		// is not the nosqlRMIPort default.
		conn, target := scriptedServer(t, ackThenListing(ack, classMarkerListing))
		defer conn.Close()
		target.Address = netip.AddrPortFrom(target.Address.Addr(), 9999)

		svc, err := (&NoSQLPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleNoSQL, nosqlCPE)
	})

	t.Run("ack then binding-triad listing with no oracle.kv class token - not detected (triad heuristic removed)", func(t *testing.T) {
		// The <store>:<resourceId>:<InterfaceType> binding-triad heuristic was
		// deleted: a bare triad with no oracle.kv class token must not
		// classify, even on nosqlRMIPort where the old port-gated heuristic
		// used to trust it.
		conn, target := scriptedServer(t, ackThenListing(ack, bindingTriadOnlyListing))
		defer conn.Close()
		target.Address = netip.AddrPortFrom(target.Address.Addr(), nosqlRMIPort)

		svc, err := (&NoSQLPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("ack then generic listing - not detected, let javarmi claim", func(t *testing.T) {
		conn, target := scriptedServer(t, ackThenListing(ack, genericListing))
		defer conn.Close()

		svc, err := (&NoSQLPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("ack then close before round-2 write - not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, ackThenCloseBeforeRound2(ack))
		defer conn.Close()

		svc, err := (&NoSQLPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("round-1 invalid ack (ProtocolNack) - not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, writeOnce(invalidAck))
		defer conn.Close()

		svc, err := (&NoSQLPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("round-1 hold until deadline - silence, not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, holdOpen)
		defer conn.Close()

		svc, err := (&NoSQLPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("round-1 close immediately - not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, closeImmediately)
		defer conn.Close()

		svc, err := (&NoSQLPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("ack then round-2 hold until deadline - not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, ackThenHoldRound2(ack))
		defer conn.Close()

		svc, err := (&NoSQLPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("ack then listing split across two Recv reads - marker only in 2nd segment - detected", func(t *testing.T) {
		// Prefix is a marker-free noise segment larger than the pluginutils.Recv
		// single-Read cap (4096 bytes, see ackThenSplitListing), forcing the
		// bounded read loop to accumulate across (at least) two Recv reads
		// before the oracle.kv marker in the suffix becomes visible.
		prefix := bytes.Repeat([]byte{0xac, 0xed, 0x00, 0x05}, 1200) // 4800 bytes, no marker
		suffix := []byte("oracle.kv.impl.api.KVStoreImpl")
		conn, target := scriptedServer(t, ackThenSplitListing(ack, prefix, suffix))
		defer conn.Close()

		svc, err := (&NoSQLPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleNoSQL, nosqlCPE)
	})

	t.Run("round-2 partial read with error, marker in partial bytes - still detected", func(t *testing.T) {
		// ackThenHoldRound2 keeps the underlying conn open and draining so the
		// round-2 Write succeeds; the round-2 Read is intercepted before it ever
		// reaches the real conn.
		conn, target := scriptedServer(t, ackThenHoldRound2(ack))
		defer conn.Close()
		wrapped := &partialThenErrorConn{
			Conn:          conn,
			errorOnCall:   2, // round 1 = call 1 (ack), round 2 = call 2 (listing)
			injectPartial: classMarkerListing,
		}

		svc, err := (&NoSQLPlugin{}).Run(wrapped, shortTimeout, target)
		require.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleNoSQL, nosqlCPE)
	})

	t.Run("round-2 read error with empty buffer - ambiguous, not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, ackThenHoldRound2(ack))
		defer conn.Close()
		wrapped := &partialThenErrorConn{
			Conn:          conn,
			errorOnCall:   2,
			injectPartial: nil, // no bytes at all alongside the error
		}

		svc, err := (&NoSQLPlugin{}).Run(wrapped, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})
}

// ---------------------------------------------------------------------------
// Section 3.2: TestNoSQLHTTPPluginRun (loopback, single HTTP round-trip)
// ---------------------------------------------------------------------------

func TestNoSQLHTTPPluginRun(t *testing.T) {
	t.Run("200 OK with Oracle NoSQL Database Proxy body - detected", func(t *testing.T) {
		// Run probes the root path "/" (not /V2/health) and classifies solely
		// on nosqlProxyMarkers; confirms detection on the plugin's own default
		// port (8080).
		conn, target := scriptedServer(t, httpOnce("HTTP/1.1 200 OK", "Oracle NoSQL Database Proxy"))
		defer conn.Close()
		target.Address = netip.AddrPortFrom(target.Address.Addr(), nosqlHTTPPort)

		svc, err := (&NoSQLHTTPPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleNoSQL, nosqlCPE)

		var payload plugins.ServiceOracleNoSQL
		require.NoError(t, json.Unmarshal(svc.Raw, &payload))
		assert.True(t, payload.ViaHTTP)
		assert.Equal(t, "", payload.Endpoint)
	})

	t.Run("200 OK with kvproxy body on a non-8080 port - detected (classification is not port-gated)", func(t *testing.T) {
		// Classification rests solely on nosqlProxyMarkers and is no longer
		// gated to nosqlHTTPPort, so 80/443/custom-port deployments must be
		// detected too.
		conn, target := scriptedServer(t, httpOnce("HTTP/1.1 200 OK", "kvproxy"))
		defer conn.Close()
		target.Address = netip.AddrPortFrom(target.Address.Addr(), 9999)

		svc, err := (&NoSQLHTTPPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleNoSQL, nosqlCPE)
	})

	t.Run("bare 200 - not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, httpOnce("HTTP/1.1 200 OK", "<html>hello</html>"))
		defer conn.Close()

		svc, err := (&NoSQLHTTPPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("body contains ords - not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, httpOnce("HTTP/1.1 200 OK", "welcome to ords"))
		defer conn.Close()

		svc, err := (&NoSQLHTTPPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("body contains apex - not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, httpOnce("HTTP/1.1 200 OK", "apex login page"))
		defer conn.Close()

		svc, err := (&NoSQLHTTPPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("close immediately - client.Do error, not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, closeImmediately)
		defer conn.Close()

		svc, err := (&NoSQLHTTPPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("hold until deadline - client.Do timeout, not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, holdOpen)
		defer conn.Close()

		svc, err := (&NoSQLHTTPPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("302 redirect, marker only in Location header with empty body - detected", func(t *testing.T) {
		raw := "HTTP/1.1 302 Found\r\nLocation: /oracle.kv/redirect\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
		conn, target := scriptedServer(t, writeOnce([]byte(raw)))
		defer conn.Close()
		target.Address = netip.AddrPortFrom(target.Address.Addr(), nosqlHTTPPort)

		svc, err := (&NoSQLHTTPPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleNoSQL, nosqlCPE)
	})
}

// ---------------------------------------------------------------------------
// Section 3.3: TestTimesTenPluginRun (loopback, single round-trip)
// ---------------------------------------------------------------------------

func TestTimesTenPluginRun(t *testing.T) {
	t.Run("exact TimesTen reject prefix + binary tail - detected", func(t *testing.T) {
		resp := append([]byte("HTTP/1.0 400 msg=Bad%20Request&rc="), 0x01, 0x02, 0x00)
		conn, target := scriptedServer(t, writeOnce(resp))
		defer conn.Close()

		svc, err := (&TimesTenPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleTimesTen, timesTenCPE)
	})

	t.Run("reject prefix split across two reads - detected", func(t *testing.T) {
		// FIX 1/3: TCP may split the "HTTP/1. ... msg=Bad%20Request&rc=" reject
		// across segments, so Run accumulates up to 2 extra bounded reads while
		// the bytes-so-far stay consistent with a reject prefix
		// (couldBeTimesTenRejectPrefix). splitReadConn deterministically caps
		// the very first Read to 3 bytes ("HTT") - a strict prefix of "HTTP/1."
		// - forcing Run to exercise that accumulation loop instead of relying
		// on real TCP-segment timing.
		resp := append([]byte("HTTP/1.0 400 msg=Bad%20Request&rc="), 0x01, 0x02, 0x00)
		conn, target := scriptedServer(t, writeOnce(resp))
		defer conn.Close()
		wrapped := &splitReadConn{Conn: conn, maxFirst: 3}

		svc, err := (&TimesTenPlugin{}).Run(wrapped, shortTimeout, target)
		assert.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleTimesTen, timesTenCPE)
	})

	t.Run("generic 400 without rc= shape - not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, writeOnce([]byte("HTTP/1.0 400 Bad Request")))
		defer conn.Close()

		svc, err := (&TimesTenPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("well-formed HTTP 400 with headers - not detected", func(t *testing.T) {
		resp := []byte("HTTP/1.1 400 Bad Request\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n")
		conn, target := scriptedServer(t, writeOnce(resp))
		defer conn.Close()

		svc, err := (&TimesTenPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("hold until deadline - silence, not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, holdOpen)
		defer conn.Close()

		svc, err := (&TimesTenPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("close immediately - not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, closeImmediately)
		defer conn.Close()

		svc, err := (&TimesTenPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("round-1 partial read with error, TimesTen reject prefix in partial bytes - still detected", func(t *testing.T) {
		// TimesTen is a single round-trip (probe write, one Recv), so the
		// injected error/partial-bytes pair happens on the very first (and
		// only) Read call. Mirrors NoSQLPlugin's round-2 partial-read case:
		// on a connection reset mid-read, pluginutils.Recv still returns the
		// bytes received before the error, and Run must evaluate them rather
		// than discarding them.
		conn, target := scriptedServer(t, holdOpen)
		defer conn.Close()
		resp := append([]byte("HTTP/1.0 400 msg=Bad%20Request&rc="), 0x01, 0x02, 0x00)
		wrapped := &partialThenErrorConn{
			Conn:          conn,
			errorOnCall:   1, // TimesTen's only Read call
			injectPartial: resp,
		}

		svc, err := (&TimesTenPlugin{}).Run(wrapped, shortTimeout, target)
		assert.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleTimesTen, timesTenCPE)
	})

	t.Run("round-1 read error with empty buffer - ambiguous, not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, holdOpen)
		defer conn.Close()
		wrapped := &partialThenErrorConn{
			Conn:          conn,
			errorOnCall:   1,
			injectPartial: nil, // no bytes at all alongside the error
		}

		svc, err := (&TimesTenPlugin{}).Run(wrapped, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})
}

// ---------------------------------------------------------------------------
// Section 3.4: TestCoherencePluginRun (loopback, single round-trip)
// ---------------------------------------------------------------------------

func TestCoherencePluginRun(t *testing.T) {
	t.Run("positive POF fixture - detected", func(t *testing.T) {
		// coherenceHeuristicEnabled defaults to false (LAB-5056 live validation),
		// so this positive-detection case must opt in explicitly to exercise the
		// heuristic body; see TestCoherenceHeuristicDisabledByDefault for the
		// default-off behavior this opt-in is deliberately overriding.
		saved := coherenceHeuristicEnabled
		coherenceHeuristicEnabled = func() bool { return true }
		t.Cleanup(func() { coherenceHeuristicEnabled = saved })

		conn, target := scriptedServer(t, writeOnce([]byte{0x03, 0x00, 0x01, 0x02}))
		defer conn.Close()
		target.Address = netip.AddrPortFrom(target.Address.Addr(), coherencePort)

		svc, err := (&CoherencePlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleCoherence, coherenceCPE)
	})

	t.Run("TLS response - not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, writeOnce([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x02}))
		defer conn.Close()
		target.Address = netip.AddrPortFrom(target.Address.Addr(), coherencePort)

		svc, err := (&CoherencePlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("Coherence UPnP false friend - not detected", func(t *testing.T) {
		wrapper := append([]byte{0x01, 0x02}, []byte("Coherence")...)
		wrapper = append(wrapper, 0x03, 0x04)
		conn, target := scriptedServer(t, writeOnce(wrapper))
		defer conn.Close()
		target.Address = netip.AddrPortFrom(target.Address.Addr(), coherencePort)

		svc, err := (&CoherencePlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("length-inconsistent frame - not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, writeOnce([]byte{0x05, 0x00, 0x01, 0x02}))
		defer conn.Close()
		target.Address = netip.AddrPortFrom(target.Address.Addr(), coherencePort)

		svc, err := (&CoherencePlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("hold until deadline - silence, not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, holdOpen)
		defer conn.Close()
		target.Address = netip.AddrPortFrom(target.Address.Addr(), coherencePort)

		svc, err := (&CoherencePlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("close immediately - not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, closeImmediately)
		defer conn.Close()
		target.Address = netip.AddrPortFrom(target.Address.Addr(), coherencePort)

		svc, err := (&CoherencePlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("cross-port guard: POF-shaped reply on non-Coherence port - not detected", func(t *testing.T) {
		// Regression for the review fix in PR #385: CoherencePlugin.Run must
		// confine the loose POF heuristic to coherencePort (7574). Here the
		// reply is the exact positive POF fixture (would be detected on 7574),
		// but the target port is forced to a non-Coherence port, so Run must
		// short-circuit at the port gate before any I/O and return (nil, nil).
		conn, target := scriptedServer(t, writeOnce([]byte{0x03, 0x00, 0x01, 0x02}))
		defer conn.Close()
		target.Address = netip.AddrPortFrom(target.Address.Addr(), 9999)

		svc, err := (&CoherencePlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("round-1 partial read with error (respond-then-EOF), positive POF fixture in partial bytes - still detected", func(t *testing.T) {
		// Regression for the review fix in PR #385: a server that writes the POF
		// handshake frame and then immediately closes surfaces io.EOF alongside
		// those bytes on a single conn.Read (pluginutils.Recv's "partial read: N
		// bytes before error" branch). CoherencePlugin.Run must evaluate those
		// bytes rather than discarding them on any non-empty read error. Real
		// loopback timing does not reliably combine a data delivery and a close
		// into one syscall (see partialThenErrorConn's doc comment), so this is
		// injected deterministically exactly as TestTimesTenPluginRun's
		// equivalent partial-read case does.
		//
		// coherenceHeuristicEnabled defaults to false (LAB-5056 live validation),
		// so this positive-detection case must opt in explicitly.
		saved := coherenceHeuristicEnabled
		coherenceHeuristicEnabled = func() bool { return true }
		t.Cleanup(func() { coherenceHeuristicEnabled = saved })

		conn, target := scriptedServer(t, holdOpen)
		defer conn.Close()
		target.Address = netip.AddrPortFrom(target.Address.Addr(), coherencePort)
		wrapped := &partialThenErrorConn{
			Conn:          conn,
			errorOnCall:   1, // Coherence's only Read call
			injectPartial: []byte{0x03, 0x00, 0x01, 0x02},
		}

		svc, err := (&CoherencePlugin{}).Run(wrapped, shortTimeout, target)
		assert.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleCoherence, coherenceCPE)
	})

	t.Run("round-1 read error with empty buffer - ambiguous, not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, holdOpen)
		defer conn.Close()
		target.Address = netip.AddrPortFrom(target.Address.Addr(), coherencePort)
		wrapped := &partialThenErrorConn{
			Conn:          conn,
			errorOnCall:   1,
			injectPartial: nil, // no bytes at all alongside the error
		}

		svc, err := (&CoherencePlugin{}).Run(wrapped, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("split POF frame across reads - accumulated and detected", func(t *testing.T) {
		// Regression for the review fix in PR #385: TCP may deliver the POF handshake
		// frame across multiple reads. CoherencePlugin.Run must accumulate a small,
		// bounded number of extra reads (couldBeCoherencePOFPrefix) rather than
		// rejecting a valid frame seen only in part on the first Recv. splitReadConn
		// caps the first Read to 2 bytes so the 4-byte fixture is guaranteed to arrive
		// across two reads (real loopback timing does not reliably split a small Write).
		//
		// coherenceHeuristicEnabled defaults to false (LAB-5056 live validation),
		// so this positive-detection case must opt in explicitly.
		saved := coherenceHeuristicEnabled
		coherenceHeuristicEnabled = func() bool { return true }
		t.Cleanup(func() { coherenceHeuristicEnabled = saved })

		conn, target := scriptedServer(t, writeOnce([]byte{0x03, 0x00, 0x01, 0x02}))
		defer conn.Close()
		target.Address = netip.AddrPortFrom(target.Address.Addr(), coherencePort)
		wrapped := &splitReadConn{Conn: conn, maxFirst: 2}

		svc, err := (&CoherencePlugin{}).Run(wrapped, shortTimeout, target)
		assert.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleCoherence, coherenceCPE)
	})
}

// ---------------------------------------------------------------------------
// Section 3.5: TestCoherenceHeuristicDisabled - the kill-switch branch
// ---------------------------------------------------------------------------

func TestCoherenceHeuristicDisabled(t *testing.T) {
	orig := coherenceHeuristicEnabled
	t.Cleanup(func() { coherenceHeuristicEnabled = orig })

	receivedBytes := make(chan int, 1)
	conn, target := scriptedServer(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		receivedBytes <- n
	})
	defer conn.Close()
	// Set the target port to coherencePort so this test exercises the
	// disable-switch branch itself rather than short-circuiting on the
	// port gate (which runs before the coherenceHeuristicEnabled check).
	target.Address = netip.AddrPortFrom(target.Address.Addr(), coherencePort)

	coherenceHeuristicEnabled = func() bool { return false }

	// Positive fixture that WOULD detect if the heuristic were enabled.
	svc, err := (&CoherencePlugin{}).Run(conn, shortTimeout, target)
	assert.Nil(t, svc)
	assert.NoError(t, err)

	// Force the server's Read to unblock and report whether the disabled path
	// ever sent probe bytes (it must not: the gate is checked before any I/O).
	conn.Close()
	select {
	case n := <-receivedBytes:
		assert.Equal(t, 0, n, "server must not receive probe bytes when heuristic disabled")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for scripted-server goroutine")
	}
}

// TestCoherenceHeuristicDisabledByDefault locks in the new LAB-5056 default:
// coherenceHeuristicEnabled defaults to `func() bool { return false }` (live
// validation proved real Coherence CE 22.06.10 is silent to the POF probe on
// 7574 while the heuristic can false-positive on unrelated short
// length-prefixed binary services on that port). Deliberately does NOT set
// coherenceHeuristicEnabled at all - unlike TestCoherenceHeuristicDisabled
// above, which exercises the disable-switch branch via an explicit override -
// so this test fails if the package default is ever flipped back to enabled.
func TestCoherenceHeuristicDisabledByDefault(t *testing.T) {
	receivedBytes := make(chan int, 1)
	conn, target := scriptedServer(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		receivedBytes <- n
	})
	defer conn.Close()
	// Set the target port to coherencePort so this test exercises the
	// disable-switch branch itself rather than short-circuiting on the port
	// gate (which runs before the coherenceHeuristicEnabled check).
	target.Address = netip.AddrPortFrom(target.Address.Addr(), coherencePort)

	// Positive fixture that WOULD detect if the heuristic were enabled.
	svc, err := (&CoherencePlugin{}).Run(conn, shortTimeout, target)
	assert.Nil(t, svc, "the 7574 heuristic must be off by default")
	assert.NoError(t, err)

	// Force the server's Read to unblock and report whether the disabled-by-default
	// path ever sent probe bytes (it must not: the gate is checked before any I/O).
	conn.Close()
	select {
	case n := <-receivedBytes:
		assert.Equal(t, 0, n, "server must not receive probe bytes when heuristic is disabled by default")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for scripted-server goroutine")
	}
}

// ---------------------------------------------------------------------------
// Section 4: TestPluginMetadata
// ---------------------------------------------------------------------------

func TestPluginMetadata(t *testing.T) {
	tests := []struct {
		name         string
		plugin       plugins.Plugin
		wantName     string
		wantType     plugins.Protocol
		wantPriority int
		truePorts    []uint16
		falsePorts   []uint16
	}{
		{
			name:         "CoherencePlugin",
			plugin:       &CoherencePlugin{},
			wantName:     plugins.ProtoOracleCoherence,
			wantType:     plugins.TCP,
			wantPriority: 900,
			truePorts:    []uint16{7574},
			falsePorts:   []uint16{5000, 8080, 6624, 1099},
		},
		{
			name:     "NoSQLPlugin",
			plugin:   &NoSQLPlugin{},
			wantName: plugins.ProtoOracleNoSQL,
			wantType: plugins.TCP,
			// Priority 400, deliberately BELOW javarmi's 500 so NoSQL (ascending
			// sort) runs FIRST in a full sweep and gets to inspect the registry
			// listing before javarmi claims the endpoint.
			wantPriority: 400,
			truePorts:    []uint16{5000},
			falsePorts:   []uint16{7574, 8080, 6625},
		},
		{
			name:         "NoSQLHTTPPlugin",
			plugin:       &NoSQLHTTPPlugin{},
			wantName:     oracleNoSQLHTTPName,
			wantType:     plugins.TCP,
			wantPriority: -1,
			truePorts:    []uint16{8080},
			falsePorts:   []uint16{5000, 7574, 6624},
		},
		{
			name:         "TimesTenPlugin",
			plugin:       &TimesTenPlugin{},
			wantName:     plugins.ProtoOracleTimesTen,
			wantType:     plugins.TCP,
			wantPriority: 900,
			truePorts:    []uint16{6624, 6625},
			falsePorts:   []uint16{6623, 6626, 7574, 5000},
		},
	}

	names := make(map[string]bool, len(tests))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantName, tt.plugin.Name())
			assert.Equal(t, tt.wantType, tt.plugin.Type())
			assert.Equal(t, tt.wantPriority, tt.plugin.Priority())
			for _, p := range tt.truePorts {
				assert.True(t, tt.plugin.PortPriority(p), "PortPriority(%d) expected true", p)
			}
			for _, p := range tt.falsePorts {
				assert.False(t, tt.plugin.PortPriority(p), "PortPriority(%d) expected false", p)
			}
		})
		names[tt.plugin.Name()] = true
	}
	assert.Len(t, names, len(tests), "all four plugin Name() values must be distinct (registry key uniqueness)")

	// NoSQL must sort BEFORE the generic javarmi plugin (priority 500) so it
	// gets first look at the registry listing in a full sweep.
	assert.Less(t, (&NoSQLPlugin{}).Priority(), 500,
		"NoSQLPlugin priority must be below javarmi's 500 so it dispatches first")
}

// ---------------------------------------------------------------------------
// Section 2.10: TestBuildCoherenceCPE / TestParseCoherenceManagement -
// pure-function unit tests for the Coherence HTTP detectors' CPE assembly and
// JSON marker rule.
// ---------------------------------------------------------------------------

func TestBuildCoherenceCPE(t *testing.T) {
	assert.Equal(t, "cpe:2.3:a:oracle:coherence:22.06.10:*:*:*:*:*:*:*", buildCoherenceCPE("22.06.10"))
	assert.Equal(t, "cpe:2.3:a:oracle:coherence:*:*:*:*:*:*:*:*", buildCoherenceCPE(""))
}

func TestParseCoherenceManagement(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantOK      bool
		wantVersion string
		wantCluster string
		wantLicense string
	}{
		{
			"version + clusterName - detected",
			`{"version":"22.06.10","clusterName":"root's cluster"}`,
			true, "22.06.10", "root's cluster", "",
		},
		{
			"version + licenseMode - detected",
			`{"version":"22.06.10","licenseMode":"Development"}`,
			true, "22.06.10", "", "Development",
		},
		{
			"version + links[].href containing management/coherence, no clusterName/licenseMode - detected",
			`{"version":"22.06.10","links":[{"rel":"self","href":"http://host:30000/management/coherence/cluster"}]}`,
			true, "22.06.10", "", "",
		},
		{
			"version present but no marker at all - not detected",
			`{"version":"22.06.10","running":true}`,
			false, "", "", "",
		},
		{
			"marker present but no version - not detected",
			`{"clusterName":"root's cluster","licenseMode":"Development"}`,
			false, "", "", "",
		},
		{
			"HTML body, not JSON - not detected",
			`<html><body>Not JSON</body></html>`,
			false, "", "", "",
		},
		{
			"empty body - not detected",
			``,
			false, "", "", "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, ok := parseCoherenceManagement([]byte(tt.body))
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantVersion, res.version)
			assert.Equal(t, tt.wantCluster, res.clusterName)
			assert.Equal(t, tt.wantLicense, res.licenseMode)
		})
	}
}

// ---------------------------------------------------------------------------
// Section 2.11: TestDetectCoherenceMetrics / TestDetectCoherenceManagement -
// single-vector unit tests (loopback), isolating each HTTP vector from the
// other before the full Run() matrix below.
// ---------------------------------------------------------------------------

// Real-capture-derived fixtures (Coherence CE 22.06.10, live validation - see
// package doc and detectCoherenceHTTP's doc comment).
const (
	coherenceMetricsViaVendorBody = `vendor:coherence_cluster_size{cluster="root's cluster", version="22.06.10"} 1` + "\n"
	// coherenceMetricsViaRoleOnlyBody deliberately contains NO "vendor:coherence_"
	// substring anywhere, so it fires only the role="CoherenceServer" marker and
	// the version stays unparsed.
	coherenceMetricsViaRoleOnlyBody = "jvm_info{version=\"17\"} 1\n" +
		`Coherence_Node_MemberIdentity{role="CoherenceServer"} 1` + "\n"
	coherenceGenericPrometheusBody  = "go_gc_duration_seconds{quantile=\"0\"} 0\nprocess_cpu_seconds_total 1.2\n"
	coherenceManagementFullPositive = `{"licenseMode":"Development","clusterSize":1,"version":"22.06.10","running":true,` +
		`"clusterName":"root's cluster","members":["Member(Id=1, Role=CoherenceServer)"],` +
		`"links":[{"rel":"self","href":"http://host:30000/management/coherence/cluster"}]}`
)

func TestDetectCoherenceMetrics(t *testing.T) {
	t.Run("vendor:coherence_ marker present - detected, version parsed", func(t *testing.T) {
		client, baseURL, conn := coherenceClientAndBaseURL(t, httpOnce("HTTP/1.1 200 OK", coherenceMetricsViaVendorBody))
		defer conn.Close()

		res, ok := detectCoherenceMetrics(client, baseURL, "")
		require.True(t, ok)
		assert.Equal(t, "22.06.10", res.version)
		assert.Equal(t, "", res.clusterName)
		assert.Equal(t, "", res.licenseMode)
	})

	t.Run(`role="CoherenceServer" marker only, no vendor:coherence_ prefix - detected, version empty`, func(t *testing.T) {
		client, baseURL, conn := coherenceClientAndBaseURL(t, httpOnce("HTTP/1.1 200 OK", coherenceMetricsViaRoleOnlyBody))
		defer conn.Close()

		res, ok := detectCoherenceMetrics(client, baseURL, "")
		require.True(t, ok)
		assert.Equal(t, "", res.version)
	})

	t.Run("generic prometheus metrics, no Coherence marker - not detected", func(t *testing.T) {
		client, baseURL, conn := coherenceClientAndBaseURL(t, httpOnce("HTTP/1.1 200 OK", coherenceGenericPrometheusBody))
		defer conn.Close()

		_, ok := detectCoherenceMetrics(client, baseURL, "")
		assert.False(t, ok)
	})

	t.Run("404 response carrying a Coherence marker in the body - not detected (status filtered before body parse)", func(t *testing.T) {
		client, baseURL, conn := coherenceClientAndBaseURL(t, httpOnce("HTTP/1.1 404 Not Found", coherenceMetricsViaVendorBody))
		defer conn.Close()

		_, ok := detectCoherenceMetrics(client, baseURL, "")
		assert.False(t, ok)
	})

	t.Run("connection closed immediately - transport error, not detected", func(t *testing.T) {
		client, baseURL, conn := coherenceClientAndBaseURL(t, closeImmediately)
		defer conn.Close()

		_, ok := detectCoherenceMetrics(client, baseURL, "")
		assert.False(t, ok)
	})
}

func TestDetectCoherenceManagement(t *testing.T) {
	t.Run("cluster path positive on first try - detected via a single GET", func(t *testing.T) {
		client, baseURL, conn := coherenceClientAndBaseURL(t, httpOnce("HTTP/1.1 200 OK", coherenceManagementFullPositive))
		defer conn.Close()

		res, ok := detectCoherenceManagement(client, baseURL, "")
		require.True(t, ok)
		assert.Equal(t, "22.06.10", res.version)
		assert.Equal(t, "root's cluster", res.clusterName)
		assert.Equal(t, "Development", res.licenseMode)
	})

	t.Run("cluster path 404, /management/coherence fallback positive - detected across two GETs", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/management/coherence/cluster":
				w.WriteHeader(http.StatusNotFound)
			case "/management/coherence":
				fmt.Fprint(w, coherenceManagementFullPositive)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		conn, _ := dialHTTPTestServer(t, server.URL)
		defer conn.Close()
		client := createCoherenceHTTPClient(conn, shortTimeout)
		baseURL := "http://" + conn.RemoteAddr().String()

		res, ok := detectCoherenceManagement(client, baseURL, "")
		require.True(t, ok)
		assert.Equal(t, "22.06.10", res.version)
	})

	t.Run("both management paths return 404 - not detected", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		conn, _ := dialHTTPTestServer(t, server.URL)
		defer conn.Close()
		client := createCoherenceHTTPClient(conn, shortTimeout)
		baseURL := "http://" + conn.RemoteAddr().String()

		_, ok := detectCoherenceManagement(client, baseURL, "")
		assert.False(t, ok)
	})
}

// ---------------------------------------------------------------------------
// Section 3.6: TestCoherenceHTTPPluginRun (loopback, httptest.Server -
// CoherenceHTTPPlugin, plaintext HTTP)
// ---------------------------------------------------------------------------

func TestCoherenceHTTPPluginRun(t *testing.T) {
	t.Run("metrics vendor:coherence_ marker - detected, version parsed, CPE carries version", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/metrics":
				fmt.Fprint(w, coherenceMetricsViaVendorBody)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		conn, target := dialHTTPTestServer(t, server.URL)
		defer conn.Close()

		svc, err := (&CoherenceHTTPPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.Equal(t, plugins.ProtoOracleCoherence, svc.Protocol)
		assert.Equal(t, "22.06.10", svc.Version)
		assert.False(t, svc.TLS)

		var payload plugins.ServiceOracleCoherence
		require.NoError(t, json.Unmarshal(svc.Raw, &payload))
		assert.True(t, payload.ViaHTTP)
		assert.Equal(t, "", payload.ClusterName)
		assert.Equal(t, "", payload.LicenseMode)
		require.Len(t, payload.CPEs, 1)
		assert.Equal(t, "cpe:2.3:a:oracle:coherence:22.06.10:*:*:*:*:*:*:*", payload.CPEs[0])
	})

	t.Run(`metrics role="CoherenceServer" marker only - detected, version empty, CPE wildcarded`, func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/metrics":
				fmt.Fprint(w, coherenceMetricsViaRoleOnlyBody)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		conn, target := dialHTTPTestServer(t, server.URL)
		defer conn.Close()

		svc, err := (&CoherenceHTTPPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.Equal(t, "", svc.Version)

		var payload plugins.ServiceOracleCoherence
		require.NoError(t, json.Unmarshal(svc.Raw, &payload))
		require.Len(t, payload.CPEs, 1)
		assert.Equal(t, "cpe:2.3:a:oracle:coherence:*:*:*:*:*:*:*:*", payload.CPEs[0])
	})

	t.Run("metrics fails, management/cluster positive with clusterName+licenseMode - detected via fallback vector, metrics tried first", func(t *testing.T) {
		var metricsHit, clusterHit bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/metrics":
				metricsHit = true
				fmt.Fprint(w, coherenceGenericPrometheusBody)
			case "/management/coherence/cluster":
				clusterHit = true
				fmt.Fprint(w, coherenceManagementFullPositive)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		conn, target := dialHTTPTestServer(t, server.URL)
		defer conn.Close()

		svc, err := (&CoherenceHTTPPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.True(t, metricsHit, "metrics vector must be tried")
		assert.True(t, clusterHit, "management vector must be tried after metrics fails")
		assert.Equal(t, "22.06.10", svc.Version)

		var payload plugins.ServiceOracleCoherence
		require.NoError(t, json.Unmarshal(svc.Raw, &payload))
		assert.Equal(t, "root's cluster", payload.ClusterName)
		assert.Equal(t, "Development", payload.LicenseMode)
	})

	t.Run("metrics 404, management/cluster 404, management fallback positive - detected across all three GETs in order", func(t *testing.T) {
		var order []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, r.URL.Path)
			switch r.URL.Path {
			case "/management/coherence":
				fmt.Fprint(w, coherenceManagementFullPositive)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		conn, target := dialHTTPTestServer(t, server.URL)
		defer conn.Close()

		svc, err := (&CoherenceHTTPPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.Equal(t, []string{"/metrics", "/management/coherence/cluster", "/management/coherence"}, order,
			"metrics must be tried before management, and the canonical /cluster path before the fallback path")
		assert.Equal(t, "22.06.10", svc.Version)
	})

	t.Run("metrics and both management paths fail - not detected", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		conn, target := dialHTTPTestServer(t, server.URL)
		defer conn.Close()

		svc, err := (&CoherenceHTTPPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("detection is not port-gated - fires on a custom port via the metrics vector", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/metrics":
				fmt.Fprint(w, coherenceMetricsViaVendorBody)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		conn, target := dialHTTPTestServer(t, server.URL)
		defer conn.Close()
		// Neither coherenceMetricsPort (9612) nor coherenceMgmtPort (30000).
		target.Address = netip.AddrPortFrom(target.Address.Addr(), 9999)

		svc, err := (&CoherenceHTTPPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		require.NotNil(t, svc, "classification must not be port-gated")
	})

	t.Run("Misconfigs=true - AnonymousAccess and oracle-coherence-exposed finding", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/metrics":
				fmt.Fprint(w, coherenceMetricsViaVendorBody)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		conn, target := dialHTTPTestServer(t, server.URL)
		defer conn.Close()
		target.Misconfigs = true

		svc, err := (&CoherenceHTTPPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.True(t, svc.AnonymousAccess)
		require.Len(t, svc.SecurityFindings, 1)
		assert.Equal(t, "oracle-coherence-exposed", svc.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityLow, svc.SecurityFindings[0].Severity)
	})

	t.Run("Misconfigs=false - no AnonymousAccess, no SecurityFindings", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/metrics":
				fmt.Fprint(w, coherenceMetricsViaVendorBody)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		conn, target := dialHTTPTestServer(t, server.URL)
		defer conn.Close()
		target.Misconfigs = false

		svc, err := (&CoherenceHTTPPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.False(t, svc.AnonymousAccess)
		assert.Empty(t, svc.SecurityFindings)
	})
}

// ---------------------------------------------------------------------------
// Section 3.6b: TestCoherenceHTTPPluginRun_ManagementAfterMetricsClose -
// regression for the connection-handling fix documented in
// detectCoherenceHTTP's doc comment: on a real Coherence management node
// (Helidon), GET /metrics returns 404 and the server closes the TCP
// connection immediately after that response, so the management vector must
// NOT reuse the now-dead framework-injected conn - it must self-dial a FRESH
// connection to target.Address. httptest.Server (used by every other
// CoherenceHTTPPlugin.Run test above) keeps its keep-alive connection open
// and therefore cannot reproduce the close; this test uses a raw
// net.Listener with a scripted accept loop so the FIRST accepted connection
// (the framework-injected one) can 404-then-close while every LATER accepted
// connection (the self-dialed one) answers the management probe. Pre-fix,
// the management vector would run over the dead injected conn, read an
// empty reply, and Run would return nil; this test fails on that code and
// passes once the self-dial is in place.
// ---------------------------------------------------------------------------

func TestCoherenceHTTPPluginRun_ManagementAfterMetricsClose(t *testing.T) {
	// notFoundClose models Helidon's /metrics 404: the framework-injected
	// conn always receives this on its one and only request, then the server
	// closes the socket.
	notFoundClose := []byte("HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")

	// acceptLoop starts a raw 127.0.0.1:0 listener whose FIRST accepted
	// connection always gets notFoundClose (modeling the dead metrics conn),
	// and every LATER accepted connection gets buildFreshResp(addr) (modeling
	// the management vector's self-dial back to the same listener, since
	// target.Address points at it). It returns the dialed framework conn
	// (the first-accepted one) and a matching Target.
	acceptLoop := func(t *testing.T, buildFreshResp func(addr string) []byte) (net.Conn, plugins.Target) {
		t.Helper()

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })

		addrPort, ok := ln.Addr().(*net.TCPAddr)
		require.True(t, ok, "listener address is not TCP")
		freshResp := buildFreshResp(addrPort.String())

		go func() {
			accepted := 0
			for {
				c, aerr := ln.Accept()
				if aerr != nil {
					return
				}
				accepted++
				isFirst := accepted == 1
				go func(c net.Conn, isFirst bool) {
					defer c.Close()
					buf := make([]byte, 4096)
					_, _ = c.Read(buf)
					if isFirst {
						_, _ = c.Write(notFoundClose)
						return
					}
					_, _ = c.Write(freshResp)
				}(c, isFirst)
			}
		}()

		target := plugins.Target{
			Host:       addrPort.IP.String(),
			Address:    netip.MustParseAddrPort(addrPort.String()),
			Misconfigs: true,
		}

		conn, err := net.DialTimeout("tcp", addrPort.String(), 5*time.Second)
		require.NoError(t, err)
		return conn, target
	}

	t.Run("metrics 404s and closes the injected conn - management self-dials a fresh conn to the same target and detects", func(t *testing.T) {
		conn, target := acceptLoop(t, func(addr string) []byte {
			body := fmt.Sprintf(
				`{"licenseMode":"Development","clusterSize":1,"version":"22.06.10","running":true,"clusterName":"root's cluster","members":["Member(Id=1, ... Role=CoherenceServer)"],"links":[{"rel":"self","href":"http://%s/management/coherence/cluster"}]}`,
				addr,
			)
			return []byte(fmt.Sprintf(
				"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
				len(body), body,
			))
		})
		defer conn.Close()

		svc, err := (&CoherenceHTTPPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		require.NotNil(t, svc, "management vector must self-dial a fresh conn instead of reusing the dead metrics conn")
		assert.Equal(t, plugins.ProtoOracleCoherence, svc.Protocol)
		assert.Equal(t, "22.06.10", svc.Version)

		var payload plugins.ServiceOracleCoherence
		require.NoError(t, json.Unmarshal(svc.Raw, &payload))
		assert.True(t, payload.ViaHTTP)
		assert.Equal(t, "root's cluster", payload.ClusterName)
		assert.Equal(t, "Development", payload.LicenseMode)
	})

	t.Run("metrics 404s and closes, fresh self-dial ALSO 404s for management - not detected", func(t *testing.T) {
		conn, target := acceptLoop(t, func(addr string) []byte { return notFoundClose })
		defer conn.Close()

		svc, err := (&CoherenceHTTPPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		assert.Nil(t, svc)
	})
}

// ---------------------------------------------------------------------------
// Section 3.6c: TestCoherenceHTTPPluginRun_ManagementPerPathRedial - regression
// for the per-path re-dial fix in detectCoherenceManagementFresh (LAB-5056): a
// Coherence management node (Helidon) answers a non-2xx on the canonical
// /management/coherence/cluster path with `Connection: close`. Reusing that
// SAME connection for the /management/coherence fallback GET (the pre-fix
// behavior, one fresh dial for the whole management vector rather than one
// per path) would land on a dead socket and never reach the server for the
// fallback attempt. httptest.Server's keep-alive connection cannot reproduce
// a mid-vector close, so (like TestCoherenceHTTPPluginRun_ManagementAfterMetricsClose
// above) this uses a raw net.Listener with a scripted accept loop keyed by
// connection order: conn #1 is the framework-injected conn (the metrics probe,
// 404s), conn #2 is the cluster-path self-dial (404 + Connection: close), and
// conn #3 is the fallback-path self-dial. Pre-fix, the cluster path's close
// would poison the single shared self-dialed conn before the fallback GET
// could run, so the positive subcase below would fail with svc == nil; it
// passes once each management path gets its own fresh dial.
// ---------------------------------------------------------------------------

func TestCoherenceHTTPPluginRun_ManagementPerPathRedial(t *testing.T) {
	notFoundClose := []byte("HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")

	// acceptLoop starts a raw 127.0.0.1:0 listener. The first two accepted
	// connections (the framework-injected metrics conn, and the cluster-path
	// self-dial) always get notFoundClose; every LATER accepted connection
	// (the fallback-path self-dial, and any further attempt) gets
	// buildThirdResp(addr). It returns the dialed framework conn (the
	// first-accepted one) and a matching Target.
	acceptLoop := func(t *testing.T, buildThirdResp func(addr string) []byte) (net.Conn, plugins.Target) {
		t.Helper()

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })

		addrPort, ok := ln.Addr().(*net.TCPAddr)
		require.True(t, ok, "listener address is not TCP")
		thirdResp := buildThirdResp(addrPort.String())

		go func() {
			accepted := 0
			for {
				c, aerr := ln.Accept()
				if aerr != nil {
					return
				}
				accepted++
				n := accepted
				go func(c net.Conn, n int) {
					defer c.Close()
					buf := make([]byte, 4096)
					_, _ = c.Read(buf)
					if n <= 2 {
						_, _ = c.Write(notFoundClose)
						return
					}
					_, _ = c.Write(thirdResp)
				}(c, n)
			}
		}()

		target := plugins.Target{
			Host:    addrPort.IP.String(),
			Address: netip.MustParseAddrPort(addrPort.String()),
		}

		conn, err := net.DialTimeout("tcp", addrPort.String(), 5*time.Second)
		require.NoError(t, err)
		return conn, target
	}

	t.Run("cluster path 404s and closes - fallback path re-dials a fresh conn and detects", func(t *testing.T) {
		conn, target := acceptLoop(t, func(addr string) []byte {
			body := coherenceManagementFullPositive
			return []byte(fmt.Sprintf(
				"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
				len(body), body,
			))
		})
		defer conn.Close()

		svc, err := (&CoherenceHTTPPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		require.NotNil(t, svc, "the fallback management path must re-dial a fresh conn instead of reusing the closed cluster-path conn")
		assert.Equal(t, plugins.ProtoOracleCoherence, svc.Protocol)
		assert.Equal(t, "22.06.10", svc.Version)

		var payload plugins.ServiceOracleCoherence
		require.NoError(t, json.Unmarshal(svc.Raw, &payload))
		assert.True(t, payload.ViaHTTP)
		assert.Equal(t, "root's cluster", payload.ClusterName)
	})

	t.Run("both management paths 404 - not detected", func(t *testing.T) {
		conn, target := acceptLoop(t, func(addr string) []byte { return notFoundClose })
		defer conn.Close()

		svc, err := (&CoherenceHTTPPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		assert.Nil(t, svc)
	})
}

// ---------------------------------------------------------------------------
// Section 3.7: TestCoherenceHTTPTLSPluginRun (loopback, httptest.Server -
// CoherenceHTTPTLSPlugin; CheckTLS is a documented no-op on a non-*tls.Conn -
// see oracledirectory_test.go's identical TLS-parity pattern - so
// detection/protocol parity is what is under test here, not certificate
// inspection).
// ---------------------------------------------------------------------------

func TestCoherenceHTTPTLSPluginRun(t *testing.T) {
	t.Run("positive detection - TLS flag set, protocol parity with the plain TCP variant", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/metrics":
				fmt.Fprint(w, coherenceMetricsViaVendorBody)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		conn, target := dialHTTPTestServer(t, server.URL)
		defer conn.Close()

		svc, err := (&CoherenceHTTPTLSPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.True(t, svc.TLS)
		assert.Equal(t, plugins.ProtoOracleCoherence, svc.Protocol,
			"parity with plain TCP: same product Type() despite the distinct oracle_coherence_http registry Name()")
		assert.Equal(t, "22.06.10", svc.Version)
	})

	t.Run("Misconfigs=true - exposed finding present; CheckTLS append path exercised without panic on a non-TLS conn", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/metrics":
				fmt.Fprint(w, coherenceMetricsViaVendorBody)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		conn, target := dialHTTPTestServer(t, server.URL)
		defer conn.Close()
		target.Misconfigs = true

		svc, err := (&CoherenceHTTPTLSPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		require.NotNil(t, svc)
		assert.True(t, svc.AnonymousAccess)
		require.NotEmpty(t, svc.SecurityFindings)
		assert.Equal(t, "oracle-coherence-exposed", svc.SecurityFindings[0].ID)
	})

	t.Run("not detected - no marker on any vector", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		conn, target := dialHTTPTestServer(t, server.URL)
		defer conn.Close()

		svc, err := (&CoherenceHTTPTLSPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		assert.Nil(t, svc)
	})
}

// ---------------------------------------------------------------------------
// Section 4b: TestCoherenceHTTPPluginMetadata - PortPriority/Name/Type/
// Priority for both HTTP variants. Kept separate from TestPluginMetadata
// above: that table's "all Name() values distinct" invariant intentionally
// does not hold here, since the plaintext/TLS HTTP variants share
// oracleCoherenceHTTPName by design (differentiated by Protocol, not Name -
// see oracleCoherenceHTTPName's doc comment).
// ---------------------------------------------------------------------------

func TestCoherenceHTTPPluginMetadata(t *testing.T) {
	tests := []struct {
		name         string
		plugin       plugins.Plugin
		wantType     plugins.Protocol
		wantPriority int
	}{
		{"CoherenceHTTPPlugin", &CoherenceHTTPPlugin{}, plugins.TCP, -1},
		{"CoherenceHTTPTLSPlugin", &CoherenceHTTPTLSPlugin{}, plugins.TCPTLS, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, oracleCoherenceHTTPName, tt.plugin.Name())
			assert.Equal(t, tt.wantType, tt.plugin.Type())
			assert.Equal(t, tt.wantPriority, tt.plugin.Priority())
			assert.True(t, tt.plugin.PortPriority(coherenceMetricsPort), "PortPriority(9612) expected true")
			assert.True(t, tt.plugin.PortPriority(coherenceMgmtPort), "PortPriority(30000) expected true")
			assert.False(t, tt.plugin.PortPriority(coherencePort), "PortPriority(7574) expected false")
			assert.False(t, tt.plugin.PortPriority(nosqlHTTPPort), "PortPriority(8080) expected false")
		})
	}

	// The two HTTP variants deliberately share Name() (distinguished by
	// Protocol). That name is, in turn, deliberately DISTINCT from the
	// byte-heuristic CoherencePlugin's Name() (plugins.ProtoOracleCoherence) so
	// the {Name, Protocol} registry key stays unique across all three
	// Coherence plugins even though all three emit the same
	// ServiceOracleCoherence product type.
	assert.NotEqual(t, plugins.ProtoOracleCoherence, oracleCoherenceHTTPName)
}

// ---------------------------------------------------------------------------
// Section 5: TestCoherencePluginsRegistered - registration/regression check.
// Both the HTTP plugin (TCP + TCPTLS) and the byte-heuristic 7574 plugin must
// exist in the package-level registry, and the heuristic's own behavior
// (TestCoherencePluginRun above) is unaffected by the HTTP plugins' addition.
// ---------------------------------------------------------------------------

func TestCoherencePluginsRegistered(t *testing.T) {
	tcpNames := make(map[string]bool)
	for _, p := range plugins.Plugins[plugins.TCP] {
		tcpNames[p.Name()] = true
	}
	tlsNames := make(map[string]bool)
	for _, p := range plugins.Plugins[plugins.TCPTLS] {
		tlsNames[p.Name()] = true
	}

	assert.True(t, tcpNames[oracleCoherenceHTTPName], "oracle_coherence_http must be registered under TCP")
	assert.True(t, tlsNames[oracleCoherenceHTTPName], "oracle_coherence_http must be registered under TCPTLS")
	assert.True(t, tcpNames[plugins.ProtoOracleCoherence],
		"the oracle_coherence byte-heuristic plugin (port 7574) must remain registered under TCP")
}

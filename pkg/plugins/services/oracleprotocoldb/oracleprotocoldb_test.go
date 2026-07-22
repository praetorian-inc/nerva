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
	"fmt"
	"net"
	"net/http"
	"net/netip"
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

// httpOnce drains the client's HTTP request and writes back a raw HTTP
// response built from statusLine and body.
func httpOnce(statusLine, body string) func(net.Conn) {
	raw := fmt.Sprintf("%s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", statusLine, len(body), body)
	return writeOnce([]byte(raw))
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
// Section 2.3: TestIsOracleNoSQLListing (raw-byte NoSQL marker) - FP guard #2
// ---------------------------------------------------------------------------

func TestIsOracleNoSQLListing(t *testing.T) {
	noise := bytes.Repeat([]byte{0xac, 0xed, 0x00, 0x05}, 4)

	tests := []struct {
		name     string
		reply    []byte
		expected bool
	}{
		{"oracle.kv.impl class token", append(append([]byte{}, noise...), []byte("oracle.kv.impl.api.KVStoreImpl")...), true},
		{"bare oracle.kv", append(append([]byte{}, noise...), []byte("oracle.kv")...), true},
		{"binding triad - main", []byte("store:sn1:main"), true},
		{"binding triad - monitor", []byte("mystore:base:monitor"), true},
		{"binding triad - trusted_login", []byte("s:b:trusted_login"), true},
		{"generic jmxrmi only", []byte("jmxrmi"), false},
		{"generic JBoss RMI", []byte("org.jnp.interfaces.NamingContext"), false},
		{"empty listing", []byte{}, false},
		{"random binary noise, no marker", bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x04}, 16), false},
		{"triad requires 3 segments - only 2", []byte("store:main"), false},
		{"iface not in allowlist", []byte("store:base:bogusrole"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isOracleNoSQLListing(tt.reply))
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
		{"bare 200, no marker", httpRespWithLocation(""), "<html>OK</html>", false},
		{"marker + ords in body - ORDS reject precedes marker loop", httpRespWithLocation(""), "oracle nosql ords", false},
		{"apex in body - APEX reject", httpRespWithLocation(""), "apex login", false},
		{"Location ORDS reject", httpRespWithLocation("/ords/f?p=..."), "oracle nosql", false},
		{
			"DIVERGENCE: marker only in Location, body empty - markers matched in body only",
			httpRespWithLocation("/oracle.kv/redirect"),
			"",
			false,
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
	require.Len(t, call, 45)

	// TransportConstants.Call marker at offset 6.
	assert.Equal(t, byte(0x50), call[6])

	// 22-byte well-known registry ObjID (offset 11..33) must be all-zero -
	// this proves the call targets ObjID 0, not an attacker-supplied object.
	assert.Equal(t, make([]byte, 22), call[11:33])

	// Operation index = 1 (Registry.list()), NOT bind(2)/unbind(3)/rebind(4).
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x01}, call[33:37])

	// Trailing 8 bytes decode to the well-known RegistryImpl interface hash.
	assert.Equal(t, registryInterfaceHash, binary.BigEndian.Uint64(call[37:45]))
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
	triadListing := []byte("store:sn1:main")
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

	t.Run("ack then binding-triad listing - detected", func(t *testing.T) {
		conn, target := scriptedServer(t, ackThenListing(ack, triadListing))
		defer conn.Close()

		svc, err := (&NoSQLPlugin{}).Run(conn, shortTimeout, target)
		require.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleNoSQL, nosqlCPE)

		var payload plugins.ServiceOracleNoSQL
		require.NoError(t, json.Unmarshal(svc.Raw, &payload))
		assert.Equal(t, "10.0.0.5:5000", payload.Endpoint)
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
}

// ---------------------------------------------------------------------------
// Section 3.2: TestNoSQLHTTPPluginRun (loopback, single HTTP round-trip)
// ---------------------------------------------------------------------------

func TestNoSQLHTTPPluginRun(t *testing.T) {
	t.Run("200 OK with Oracle NoSQL Database Proxy body - detected", func(t *testing.T) {
		conn, target := scriptedServer(t, httpOnce("HTTP/1.1 200 OK", "Oracle NoSQL Database Proxy"))
		defer conn.Close()

		svc, err := (&NoSQLHTTPPlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleNoSQL, nosqlCPE)

		var payload plugins.ServiceOracleNoSQL
		require.NoError(t, json.Unmarshal(svc.Raw, &payload))
		assert.True(t, payload.ViaHTTP)
		assert.Equal(t, "", payload.Endpoint)
	})

	t.Run("200 OK with kvproxy body - detected", func(t *testing.T) {
		conn, target := scriptedServer(t, httpOnce("HTTP/1.1 200 OK", "kvproxy"))
		defer conn.Close()

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
}

// ---------------------------------------------------------------------------
// Section 3.4: TestCoherencePluginRun (loopback, single round-trip)
// ---------------------------------------------------------------------------

func TestCoherencePluginRun(t *testing.T) {
	t.Run("positive POF fixture - detected", func(t *testing.T) {
		conn, target := scriptedServer(t, writeOnce([]byte{0x03, 0x00, 0x01, 0x02}))
		defer conn.Close()

		svc, err := (&CoherencePlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assertDetectionOnly(t, svc, plugins.ProtoOracleCoherence, coherenceCPE)
	})

	t.Run("TLS response - not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, writeOnce([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x02}))
		defer conn.Close()

		svc, err := (&CoherencePlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("Coherence UPnP false friend - not detected", func(t *testing.T) {
		wrapper := append([]byte{0x01, 0x02}, []byte("Coherence")...)
		wrapper = append(wrapper, 0x03, 0x04)
		conn, target := scriptedServer(t, writeOnce(wrapper))
		defer conn.Close()

		svc, err := (&CoherencePlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("length-inconsistent frame - not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, writeOnce([]byte{0x05, 0x00, 0x01, 0x02}))
		defer conn.Close()

		svc, err := (&CoherencePlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("hold until deadline - silence, not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, holdOpen)
		defer conn.Close()

		svc, err := (&CoherencePlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("close immediately - not detected", func(t *testing.T) {
		conn, target := scriptedServer(t, closeImmediately)
		defer conn.Close()

		svc, err := (&CoherencePlugin{}).Run(conn, shortTimeout, target)
		assert.NoError(t, err)
		assert.Nil(t, svc)
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
			name:         "NoSQLPlugin",
			plugin:       &NoSQLPlugin{},
			wantName:     plugins.ProtoOracleNoSQL,
			wantType:     plugins.TCP,
			wantPriority: 900,
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
}

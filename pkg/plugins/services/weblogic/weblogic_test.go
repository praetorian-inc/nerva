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

package weblogic

import (
	"crypto/tls"
	"encoding/json"
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

// -----------------------------------------------------------------------------
// PURE FUNCTIONS: parseT3Response
// -----------------------------------------------------------------------------

// TestParseT3Response_HELOFixtures uses real HELO banners drawn from
// .fingerprintx-development/version-matrix.md across the WebLogic release
// families that report either a 4-segment or 5-segment version.
func TestParseT3Response_HELOFixtures(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantVersion string
	}{
		{
			name:        "10.3.6 (11g) - 4-segment version",
			raw:         "HELO:10.3.6.0.false AS:255 HL:19",
			wantVersion: "10.3.6.0",
		},
		{
			name:        "12.1.3 - 4-segment version",
			raw:         "HELO:12.1.3.0.false AS:2048 HL:19",
			wantVersion: "12.1.3.0",
		},
		{
			name:        "12.2.1.3.0 - 5-segment version with MS/PN echoes",
			raw:         "HELO:12.2.1.3.0.false AS:2048 HL:19 MS:10000000 PN:DOMAIN",
			wantVersion: "12.2.1.3.0",
		},
		{
			name:        "14.1.1.0.0 - 5-segment version",
			raw:         "HELO:14.1.1.0.0.false AS:2048 HL:19",
			wantVersion: "14.1.1.0.0",
		},
		{
			name:        "true flag instead of false is also accepted",
			raw:         "HELO:12.2.1.4.0.true AS:2048 HL:19",
			wantVersion: "12.2.1.4.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, detected := parseT3Response([]byte(tt.raw))
			assert.True(t, detected, "expected detected=true for a HELO: reply")
			assert.Equal(t, tt.wantVersion, version)
		})
	}
}

// TestParseT3Response_NonHELOPrefixes verifies that every other known T3
// prefix still proves WebLogic (detected=true) even though it carries no
// parseable version.
func TestParseT3Response_NonHELOPrefixes(t *testing.T) {
	prefixes := []string{"LGIN:", "SERV:", "UNAV:", "LICN:", "RESC:", "VERS:", "CATA:", "CMND:"}

	for _, p := range prefixes {
		t.Run(p, func(t *testing.T) {
			raw := p + "Invalid parameter."
			version, detected := parseT3Response([]byte(raw))
			assert.True(t, detected, "prefix %q must be detected as WebLogic T3", p)
			assert.Empty(t, version, "non-HELO prefix must not report a version")
		})
	}
}

// TestParseT3Response_MalformedInputsNeverPanic is the G4 regression: garbage,
// truncated, binary, and TLS-alert input must never panic and must always
// report detected=false with an empty version.
func TestParseT3Response_MalformedInputsNeverPanic(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "empty input", raw: []byte{}},
		{name: "nil input", raw: nil},
		{name: "single byte", raw: []byte{0x41}},
		{name: "truncated HEL (no colon, no digits)", raw: []byte("HEL")},
		{
			name: "garbage binary",
			raw:  []byte{0x00, 0xFF, 0x10, 0x7E, 0x9A, 0x03, 0x88, 0x01},
		},
		{
			name: "TLS alert record bytes",
			raw:  []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28},
		},
		{
			name: "whitespace only",
			raw:  []byte("   \t\r\n\v\f"),
		},
		{
			name: "unrelated HTTP response",
			raw:  []byte("HTTP/1.1 400 Bad Request\r\n\r\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				version, detected := parseT3Response(tt.raw)
				assert.False(t, detected)
				assert.Empty(t, version)
			})
		})
	}
}

// -----------------------------------------------------------------------------
// PURE FUNCTIONS: matchConsole
// -----------------------------------------------------------------------------

func TestMatchConsole(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		setCookies []string
		want       bool
	}{
		{
			name:  "modern console title matches",
			title: "Oracle WebLogic Server Administration Console",
			want:  true,
		},
		{
			name:  "legacy console title matches",
			title: "WebLogic Server Console Login",
			want:  true,
		},
		{
			name:  "console title match is case-insensitive",
			title: "oracle weblogic server administration console",
			want:  true,
		},
		{
			name:       "ADMINCONSOLESESSION cookie matches",
			title:      "Login",
			setCookies: []string{"ADMINCONSOLESESSION=abc123; Path=/console; HttpOnly"},
			want:       true,
		},
		{
			name:       "bare JSESSIONID cookie does not match (anti-FP)",
			title:      "",
			setCookies: []string{"JSESSIONID=abc123; Path=/"},
			want:       false,
		},
		{
			// Anti-FP regression: matchConsole no longer accepts a Server header
			// at all, so a WebLogic-branded Server header carries no weight here
			// unless paired with a console title or the ADMINCONSOLESESSION
			// cookie. A generic WebLogic-hosted app response (e.g. a /* wildcard
			// mapping returning 200 at the console path) must not be mistaken for
			// the real admin console.
			name: "bare WebLogic Server header does not confirm console (anti-FP)",
			want: false,
		},
		{
			name: "generic 200 with no signals does not match",
			want: false,
		},
		{
			name:  "Tomcat title does not match",
			title: "Apache Tomcat/9.0.65 - Error report",
			want:  false,
		},
		{
			name:  "Jetty title does not match",
			title: "Error 404 - /",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchConsole(tt.title, tt.setCookies)
			assert.Equal(t, tt.want, got)
		})
	}
}

// -----------------------------------------------------------------------------
// PURE FUNCTIONS: buildWebLogicCPE
// -----------------------------------------------------------------------------

func TestBuildWebLogicCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "known version",
			version: "12.2.1.3.0",
			want:    "cpe:2.3:a:oracle:weblogic_server:12.2.1.3.0:*:*:*:*:*:*:*",
		},
		{
			name:    "another known version",
			version: "10.3.6.0",
			want:    "cpe:2.3:a:oracle:weblogic_server:10.3.6.0:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version wildcards the version field",
			version: "",
			want:    "cpe:2.3:a:oracle:weblogic_server:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildWebLogicCPE(tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}

// -----------------------------------------------------------------------------
// PURE FUNCTIONS: t3ReadTimeout
// -----------------------------------------------------------------------------

// TestT3ReadTimeout covers every branch of t3ReadTimeout deterministically:
// timeouts above the cap are clamped down, the cap itself passes through,
// positive timeouts below the cap are returned unchanged, and non-positive
// timeouts (zero or negative) fall back to the cap as a floor.
func TestT3ReadTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{
			name:    "timeout greater than cap is clamped to the cap",
			timeout: 10 * time.Second,
			want:    maxT3ReadTimeout,
		},
		{
			name:    "timeout much greater than cap is clamped to the cap",
			timeout: 30 * time.Second,
			want:    maxT3ReadTimeout,
		},
		{
			name:    "timeout equal to the cap passes through unchanged",
			timeout: maxT3ReadTimeout,
			want:    maxT3ReadTimeout,
		},
		{
			name:    "positive timeout below the cap is returned unchanged",
			timeout: 1 * time.Second,
			want:    1 * time.Second,
		},
		{
			name:    "small positive timeout below the cap is returned unchanged",
			timeout: 500 * time.Millisecond,
			want:    500 * time.Millisecond,
		},
		{
			name:    "zero timeout floors to the cap",
			timeout: 0,
			want:    maxT3ReadTimeout,
		},
		{
			name:    "negative timeout floors to the cap",
			timeout: -1 * time.Second,
			want:    maxT3ReadTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := t3ReadTimeout(tt.timeout)
			assert.Equal(t, tt.want, got)
		})
	}
}

// -----------------------------------------------------------------------------
// PURE FUNCTIONS: canSelfDialConsole
// -----------------------------------------------------------------------------

// TestCanSelfDialConsole covers every branch of canSelfDialConsole
// deterministically: a valid, routable address permits the self-dial, an
// unspecified address (e.g. 0.0.0.0, seen behind socks5h/proxy or unresolved
// scans) refuses it, and a zero-value/invalid netip.AddrPort also refuses it.
func TestCanSelfDialConsole(t *testing.T) {
	tests := []struct {
		name string
		addr netip.AddrPort
		want bool
	}{
		{
			name: "valid routable address is self-dialable",
			addr: netip.MustParseAddrPort("127.0.0.1:7002"),
			want: true,
		},
		{
			name: "unspecified address (0.0.0.0) is not self-dialable",
			addr: netip.MustParseAddrPort("0.0.0.0:7002"),
			want: false,
		},
		{
			name: "zero-value/invalid AddrPort is not self-dialable",
			addr: netip.AddrPort{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := plugins.Target{Address: tt.addr}
			got := canSelfDialConsole(target)
			assert.Equal(t, tt.want, got)
		})
	}
}

// -----------------------------------------------------------------------------
// NETWORK MOCK HELPERS
// -----------------------------------------------------------------------------

// startT3Mock starts a TCP listener that captures the first message written by
// a client, replies with response, and then attempts one more short-deadline
// read to detect any additional (second) frame written by the client. It
// returns the listener address, a channel receiving the first captured
// message, a channel receiving any second message (nil if none arrived), and
// a cleanup func.
func startT3Mock(t *testing.T, response []byte) (addr string, capturedCh chan []byte, secondCh chan []byte, cleanup func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	capturedCh = make(chan []byte, 1)
	secondCh = make(chan []byte, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			capturedCh <- nil
			secondCh <- nil
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			capturedCh <- nil
			secondCh <- nil
			return
		}
		capturedCh <- append([]byte{}, buf[:n]...)

		if len(response) > 0 {
			_, _ = conn.Write(response)
		}

		// G1 regression: after the single reply, the client must never write a
		// second frame on this connection. A short deadline is sufficient
		// because the plugin returns immediately after Recv.
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n2, err2 := conn.Read(buf)
		if err2 == nil && n2 > 0 {
			secondCh <- append([]byte{}, buf[:n2]...)
		} else {
			secondCh <- nil
		}
	}()

	addr = listener.Addr().String()
	cleanup = func() { _ = listener.Close() }
	return addr, capturedCh, secondCh, cleanup
}

// unreachableAddr returns an address that refuses connections: a listener is
// opened and immediately closed, so the port is guaranteed free but unbound.
func unreachableAddr(t *testing.T) netip.AddrPort {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := netip.MustParseAddrPort(listener.Addr().String())
	require.NoError(t, listener.Close())
	return addr
}

// dummyT3Conn dials a listener that accepts a connection, reads whatever the
// plugin sends, and replies with a benign non-T3 line. This lets the T3 probe
// complete cleanly (no detection, no I/O error, no panic) so tests that are
// only exercising the HTTP console path aren't coupled to T3 error handling.
func dummyT3Conn(t *testing.T) net.Conn {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("OK\r\n"))
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	return conn
}

// parseWeblogicTestServerAddr parses an httptest server URL into a
// netip.AddrPort, as dialConsoleConn dials target.Address directly.
func parseWeblogicTestServerAddr(t *testing.T, serverURL string) netip.AddrPort {
	t.Helper()
	hostPort := strings.TrimPrefix(strings.TrimPrefix(serverURL, "https://"), "http://")
	host, portStr, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))
}

// findFinding returns the first SecurityFinding with the given ID, or nil.
func findFinding(findings []plugins.SecurityFinding, id string) *plugins.SecurityFinding {
	for i := range findings {
		if findings[i].ID == id {
			return &findings[i]
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// NETWORK: T3 probe via net.Listen mock (G1 regression)
// -----------------------------------------------------------------------------

// TestWebLogicPlugin_Run_T3Detection_G1 verifies the T3 handshake sent on the
// wire is exactly the single benign nmap-form line (G1): no serialized Java
// marker (0xAC 0xED), and never a second write. It also verifies the resulting
// service is correctly detected, versioned, typed, and CPE-tagged.
func TestWebLogicPlugin_Run_T3Detection_G1(t *testing.T) {
	heloResponse := []byte("HELO:12.2.1.3.0.false AS:2048 HL:19 MS:10000000 PN:DOMAIN")
	addr, capturedCh, secondCh, cleanup := startT3Mock(t, heloResponse)
	defer cleanup()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{
		Host:    "127.0.0.1",
		Address: unreachableAddr(t), // console dial must fail so it can't interfere
	}

	plugin := &WebLogicPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	captured := <-capturedCh
	require.NotNil(t, captured, "expected the client to write the T3 handshake")
	capturedStr := string(captured)
	assert.True(t, strings.HasPrefix(capturedStr, "t3 "), "handshake must start with \"t3 \"")
	assert.NotContains(t, capturedStr, string([]byte{0xAC, 0xED}), "handshake must never contain the Java serialization magic")
	assert.Equal(t, t3Handshake, captured, "handshake bytes must be exactly the single benign probe")

	second := <-secondCh
	assert.Nil(t, second, "the plugin must never write a second frame on the T3 connection")

	assert.Equal(t, plugins.ProtoOracleWebLogic, service.Protocol)
	assert.Equal(t, "12.2.1.3.0", service.Version)

	var wl plugins.ServiceWebLogic
	require.NoError(t, json.Unmarshal(service.Raw, &wl))
	assert.True(t, wl.T3)
	assert.Equal(t, "12.2.1.3.0", wl.T3Version)
	require.Len(t, wl.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:weblogic_server:12.2.1.3.0:*:*:*:*:*:*:*", wl.CPEs[0])
}

// -----------------------------------------------------------------------------
// NETWORK: HTTP console via httptest
// -----------------------------------------------------------------------------

func TestWebLogicPlugin_Run_ConsoleDetection(t *testing.T) {
	tests := []struct {
		name        string
		handler     http.HandlerFunc
		wantConsole bool
	}{
		{
			name: "LoginForm.jsp title triggers detection",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "<html><head><title>Oracle WebLogic Server Administration Console</title></head><body></body></html>")
			},
			wantConsole: true,
		},
		{
			name: "ADMINCONSOLESESSION cookie triggers detection",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.SetCookie(w, &http.Cookie{Name: "ADMINCONSOLESESSION", Value: "abc123"})
				fmt.Fprint(w, "<html><head><title>Login</title></head><body></body></html>")
			},
			wantConsole: true,
		},
		{
			name: "non-WebLogic Tomcat server yields no detection",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "<html><head><title>Apache Tomcat/9.0.65 - Error report</title></head><body></body></html>")
			},
			wantConsole: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.handler))
			defer server.Close()

			addr := parseWeblogicTestServerAddr(t, server.URL)
			t3Conn := dummyT3Conn(t)
			defer t3Conn.Close()

			target := plugins.Target{Host: addr.Addr().String(), Address: addr}
			plugin := &WebLogicPlugin{}
			service, err := plugin.Run(t3Conn, 5*time.Second, target)
			require.NoError(t, err)

			if !tt.wantConsole {
				assert.Nil(t, service, "non-WebLogic server must yield no detection")
				return
			}

			require.NotNil(t, service)
			var wl plugins.ServiceWebLogic
			require.NoError(t, json.Unmarshal(service.Raw, &wl))
			assert.True(t, wl.AdminConsole)
		})
	}
}

// -----------------------------------------------------------------------------
// NETWORK: Misconfig gating (G7 regression)
// -----------------------------------------------------------------------------

func TestWebLogicPlugin_Run_MisconfigGating(t *testing.T) {
	t.Run("Misconfigs=true and reachable console 2xx yields Medium finding and AnonymousAccess=true", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "<html><head><title>Oracle WebLogic Server Administration Console</title></head><body></body></html>")
		}))
		defer server.Close()

		addr := parseWeblogicTestServerAddr(t, server.URL)
		t3Conn := dummyT3Conn(t)
		defer t3Conn.Close()

		target := plugins.Target{Host: addr.Addr().String(), Address: addr, Misconfigs: true}
		plugin := &WebLogicPlugin{}
		service, err := plugin.Run(t3Conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "oracle-weblogic-console-exposed", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityMedium, service.SecurityFindings[0].Severity)
		assert.NotEmpty(t, service.SecurityFindings[0].Description)
		assert.NotEmpty(t, service.SecurityFindings[0].Evidence)
	})

	t.Run("Misconfigs=true and T3-only detection yields Low finding and AnonymousAccess=false (G7)", func(t *testing.T) {
		heloResponse := []byte("HELO:12.1.3.0.false AS:2048 HL:19")
		addr, capturedCh, secondCh, cleanup := startT3Mock(t, heloResponse)
		defer cleanup()

		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		target := plugins.Target{
			Host:       "127.0.0.1",
			Address:    unreachableAddr(t), // console must not be reachable
			Misconfigs: true,
		}

		plugin := &WebLogicPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		<-capturedCh
		<-secondCh

		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "oracle-weblogic-t3-exposed", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityLow, service.SecurityFindings[0].Severity)

		// G7 regression: T3-only exposure must NOT imply anonymous console
		// access. AnonymousAccess is reserved for a 2xx console response.
		assert.False(t, service.AnonymousAccess, "G7 regression: T3-only detection must not set AnonymousAccess")
	})

	t.Run("Misconfigs=true and both console 2xx and T3 answer yield both findings and AnonymousAccess=true", func(t *testing.T) {
		heloResponse := []byte("HELO:12.2.1.3.0.false AS:2048 HL:19")
		addr, capturedCh, secondCh, cleanup := startT3Mock(t, heloResponse)
		defer cleanup()

		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "<html><head><title>Oracle WebLogic Server Administration Console</title></head><body></body></html>")
		}))
		defer server.Close()
		consoleAddr := parseWeblogicTestServerAddr(t, server.URL)

		target := plugins.Target{Host: consoleAddr.Addr().String(), Address: consoleAddr, Misconfigs: true}
		plugin := &WebLogicPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		<-capturedCh
		<-secondCh

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 2)

		consoleFinding := findFinding(service.SecurityFindings, "oracle-weblogic-console-exposed")
		require.NotNil(t, consoleFinding, "expected the console-exposed finding to be present")
		assert.Equal(t, plugins.SeverityMedium, consoleFinding.Severity)

		t3Finding := findFinding(service.SecurityFindings, "oracle-weblogic-t3-exposed")
		require.NotNil(t, t3Finding, "expected the T3-exposed finding to be present")
		assert.Equal(t, plugins.SeverityLow, t3Finding.Severity)
	})

	t.Run("Misconfigs=false yields no SecurityFindings at all", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "<html><head><title>Oracle WebLogic Server Administration Console</title></head><body></body></html>")
		}))
		defer server.Close()

		addr := parseWeblogicTestServerAddr(t, server.URL)
		t3Conn := dummyT3Conn(t)
		defer t3Conn.Close()

		target := plugins.Target{Host: addr.Addr().String(), Address: addr, Misconfigs: false}
		plugin := &WebLogicPlugin{}
		service, err := plugin.Run(t3Conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}

// TestWebLogicPlugin_Run_ServerHeaderAloneDoesNotConfirmConsole is the round-3
// review regression (LAB-5071, PR #386): a generic WebLogic-hosted response
// carrying a "Server: WebLogic Server" header but no console <title> and no
// ADMINCONSOLESESSION cookie must not be mistaken for the real admin console
// (e.g. a WebLogic-hosted app with a /* wildcard mapping returning 200 at the
// console path is not proof the console is actually deployed there). With T3
// also undetected (the mock never answers), the plugin must return a clean
// negative rather than a false console-exposure finding, even with
// Misconfigs=true.
func TestWebLogicPlugin_Run_ServerHeaderAloneDoesNotConfirmConsole(t *testing.T) {
	// T3 mock accepts the connection but never writes a reply, so probeT3 sees
	// an I/O error (the mock closes after its short second-read deadline) and
	// t3Detected is false.
	addr, capturedCh, secondCh, cleanup := startT3Mock(t, nil)
	defer cleanup()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "WebLogic Server")
		fmt.Fprint(w, "<html><head></head><body>OK</body></html>")
	}))
	defer server.Close()
	consoleAddr := parseWeblogicTestServerAddr(t, server.URL)

	target := plugins.Target{Host: consoleAddr.Addr().String(), Address: consoleAddr, Misconfigs: true}
	plugin := &WebLogicPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	<-capturedCh
	<-secondCh

	require.NoError(t, err)
	assert.Nil(t, service, "a bare WebLogic Server header with no console title/cookie and no T3 answer must yield a clean negative, not a false console detection")
}

// -----------------------------------------------------------------------------
// NETWORK: Error contract
// -----------------------------------------------------------------------------

// TestWebLogicPlugin_Run_T3IOFailure_CleanNegative verifies that a T3 I/O
// failure (here: a write to an already-closed connection) is treated as an
// unrecognized/closed T3 endpoint and yields a clean (nil, nil) negative,
// mirroring the other detection-only Oracle plugins, rather than surfacing as
// an error — provided the console probe also fails to reach anything.
func TestWebLogicPlugin_Run_T3IOFailure_CleanNegative(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.Close()) // closed before Run() so the write fails

	target := plugins.Target{
		Host:    "127.0.0.1",
		Address: unreachableAddr(t), // console dial must also fail
	}

	plugin := &WebLogicPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

// TestWebLogicPlugin_Run_CleanNonWebLogicService verifies that a target which
// answers neither the T3 handshake nor the HTTP console with WebLogic signals
// returns (nil, nil): detected as absent, not as an error.
func TestWebLogicPlugin_Run_CleanNonWebLogicService(t *testing.T) {
	addr, capturedCh, secondCh, cleanup := startT3Mock(t, []byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	defer cleanup()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><head><title>Apache Tomcat/9.0.65 - Error report</title></head><body></body></html>")
	}))
	defer server.Close()
	consoleAddr := parseWeblogicTestServerAddr(t, server.URL)

	target := plugins.Target{Host: consoleAddr.Addr().String(), Address: consoleAddr}
	plugin := &WebLogicPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	<-capturedCh
	<-secondCh

	assert.NoError(t, err)
	assert.Nil(t, service)
}

// -----------------------------------------------------------------------------
// NETWORK: TLS variant
// -----------------------------------------------------------------------------

// TestWebLogicTLSPlugin_Run exercises the TLS transport variant end-to-end:
// the scanner-provided conn is a real *tls.Conn (so plugins.CheckTLS has
// something to inspect), the console is reachable and returns the modern
// console title, and Misconfigs=true so the console-exposed finding and the
// TLS findings are both merged without panicking.
func TestWebLogicTLSPlugin_Run(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><head><title>Oracle WebLogic Server Administration Console</title></head><body></body></html>")
	}))
	defer tlsServer.Close()

	addr := parseWeblogicTestServerAddr(t, tlsServer.URL)

	// The scanner-provided T3 conn: a real TLS connection to the same server.
	// The T3 handshake is invalid HTTP and will not be understood by the
	// httptest handler, but that's fine — only the console-detection path is
	// under test here, and any T3 I/O error is ignored once the console is
	// detected.
	tlsConn, err := tls.Dial("tcp", tlsServer.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec
	require.NoError(t, err)
	defer tlsConn.Close()

	target := plugins.Target{Host: addr.Addr().String(), Address: addr, Misconfigs: true}
	plugin := &WebLogicTLSPlugin{}
	service, err := plugin.Run(tlsConn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	assert.True(t, service.TLS)
	assert.Equal(t, "tcptls", service.Transport)
	assert.True(t, service.AnonymousAccess)

	f := findFinding(service.SecurityFindings, "oracle-weblogic-console-exposed")
	require.NotNil(t, f, "expected the console-exposed finding to be present")
	assert.Equal(t, plugins.SeverityMedium, f.Severity)
}

// -----------------------------------------------------------------------------
// PLUGIN METADATA
// -----------------------------------------------------------------------------

func TestWebLogicPlugin_Metadata(t *testing.T) {
	plugin := &WebLogicPlugin{}
	assert.Equal(t, plugins.ProtoOracleWebLogic, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(7001))
	assert.True(t, plugin.PortPriority(7003))
	assert.False(t, plugin.PortPriority(7002))
	assert.False(t, plugin.PortPriority(80))
}

func TestWebLogicTLSPlugin_Metadata(t *testing.T) {
	plugin := &WebLogicTLSPlugin{}
	assert.Equal(t, plugins.ProtoOracleWebLogic, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(7002))
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(7001))
}

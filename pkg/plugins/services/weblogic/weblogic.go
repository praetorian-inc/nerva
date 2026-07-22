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

/*
Oracle WebLogic Server Fingerprinting (LAB-5071)

This package detects Oracle WebLogic Server via two independent surfaces:

  1. The T3 handshake (primary, authoritative version source). WebLogic's
     proprietary RMI transport answers a benign plaintext handshake with a
     text line beginning HELO: (or another T3 prefix such as LGIN:/SERV:).
     No other Java application server answers the "t3 ...\n\n" line with these
     prefixes, so this is the single strongest WebLogic discriminator, and the
     HELO: line carries the real server version.

  2. The HTTP admin console (corroborator). GET /console/login/LoginForm.jsp on
     an admin server returns a login page whose <title> is "Oracle WebLogic
     Server Administration Console" and sets an ADMINCONSOLESESSION cookie.

Because a single Name() ("oracle_weblogic") admits at most two plugins keyed by
transport, and because a T3 handshake leaves the scanner-provided connection in
T3 state (unusable for HTTP), each Run probes T3 on the scanner-provided conn
and probes the HTTP console on a short-lived, self-dialed second connection,
then merges the results into one ServiceWebLogic.

Security posture (detection-only, read-only): the plugin writes exactly ONE
benign T3 handshake and never a serialized Java object or a second frame; the
T3 read is bounded (single 4096-byte read via utils.SendRecv); the parser never
panics on empty/truncated/garbage input; the HTTP probe is GET-only, does not
follow redirects, and bounds the body. All Misconfig findings are gated behind
target.Misconfigs and are informational only.

Default ports:
  - 7001 plaintext HTTP + T3, 7003 also probed by nmap (TCP variant)
  - 7002 TLS HTTPS + T3s, 443 standard HTTPS (TLS variant)
*/

package weblogic

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	// maxResponseSize caps how much of the HTTP console body is read.
	maxResponseSize = int64(10 * 1024 * 1024)

	// consolePath is the WebLogic admin console login page.
	consolePath = "/console/login/LoginForm.jsp"

	// consoleTitleModern / consoleTitleLegacy are the two positive <title>
	// markers for the WebLogic administration console.
	consoleTitleModern = "Oracle WebLogic Server Administration Console"
	consoleTitleLegacy = "WebLogic Server Console Login"

	// consoleCookie is the WebLogic console's default session cookie name.
	consoleCookie = "ADMINCONSOLESESSION"

	// serverMarker is the branded token that may appear in a Server header.
	serverMarker = "weblogic server"
)

// t3Handshake is the single benign T3 probe sent on connect. It is the nmap
// weblogic-t3-info.nse reference string: bare-LF terminated, blank-line
// delimited, pure ASCII, containing no serialized Java (no 0xAC 0xED magic).
// The plugin writes this exactly once and never writes a second frame (G1).
var t3Handshake = []byte("t3 12.1.2\nAS:2048\nHL:19\n\n")

// t3Prefixes are the known first-token prefixes a WebLogic T3 listener returns
// to the handshake. Any of these proves WebLogic regardless of version.
var t3Prefixes = []string{
	"HELO:", "LGIN:", "SERV:", "UNAV:", "LICN:", "RESC:", "VERS:", "CATA:", "CMND:",
}

// t3HeloVersion captures 3-to-5 dotted-numeric segments after HELO:, anchored on
// the trailing false/true flag so the flag digit is not swallowed (10.3.x/12.1.x
// report 4 segments; 12.2.1.x/14.1.1 report 5).
var t3HeloVersion = regexp.MustCompile(`^HELO:(\d+(?:\.\d+){2,4})\.(?:true|false)\b`)

// t3HeloVersionLoose is the fallback when the trailing flag is absent.
var t3HeloVersionLoose = regexp.MustCompile(`^HELO:(\d+(?:\.\d+){2,4})`)

// titlePattern extracts the contents of an HTML <title> element.
var titlePattern = regexp.MustCompile(`(?is)<title>(.*?)</title>`)

type WebLogicPlugin struct{}

// WebLogicTLSPlugin detects Oracle WebLogic over TLS connections.
type WebLogicTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&WebLogicPlugin{})
	plugins.RegisterPlugin(&WebLogicTLSPlugin{})
}

// createHTTPClient creates an http.Client that wraps the provided net.Conn and
// does not follow redirects (so headers can be inspected directly).
func createHTTPClient(conn net.Conn, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}
}

// doGet performs a GET request with the nerva User-Agent header. When host is
// non-empty it is set as the HTTP Host header so name-based virtual hosts are
// reached (the connection is still dialed by IP via the client's transport).
func doGet(client *http.Client, url string, host string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nerva/1.0")
	if host != "" {
		req.Host = host
	}
	return client.Do(req)
}

// isSuccessStatus reports whether an HTTP status code is a 2xx success.
func isSuccessStatus(code int) bool {
	return code >= 200 && code < 300
}

// extractTitle returns the trimmed contents of the first <title> element, if any.
func extractTitle(body string) string {
	if m := titlePattern.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// parseT3Response classifies a raw T3 reply and extracts the HELO version. It is
// a pure function with no socket access and never panics on empty, truncated, or
// binary input (G4). detected == the first non-whitespace token has a known T3
// prefix; version == the HELO dotted-numeric run, else "".
func parseT3Response(raw []byte) (version string, detected bool) {
	if len(raw) == 0 {
		return "", false
	}
	s := strings.TrimLeft(string(raw), " \t\r\n\v\f")
	if s == "" {
		return "", false
	}
	for _, p := range t3Prefixes {
		if strings.HasPrefix(s, p) {
			detected = true
			break
		}
	}
	if !detected {
		return "", false
	}
	if m := t3HeloVersion.FindStringSubmatch(s); len(m) >= 2 {
		return m[1], true
	}
	if m := t3HeloVersionLoose.FindStringSubmatch(s); len(m) >= 2 {
		return m[1], true
	}
	return "", true
}

// matchConsole applies the HTTP-console detection and anti-false-positive rules
// to already-extracted primitives. A host is the WebLogic console when ANY strong
// signal is present: a console <title>, an ADMINCONSOLESESSION cookie, or a
// "WebLogic Server" Server header. A bare JSESSIONID cookie or generic servlet
// response never triggers.
func matchConsole(title string, setCookies []string, server string) (detected bool) {
	lt := strings.ToLower(title)
	if strings.Contains(lt, strings.ToLower(consoleTitleModern)) ||
		strings.Contains(lt, strings.ToLower(consoleTitleLegacy)) {
		return true
	}
	for _, c := range setCookies {
		if strings.Contains(strings.ToUpper(c), consoleCookie) {
			return true
		}
	}
	if strings.Contains(strings.ToLower(server), serverMarker) {
		return true
	}
	return false
}

// buildWebLogicCPE builds the NVD-aligned CPE 2.3 token, wildcarding the version
// when unknown. Verified against NVD CVE-2023-21839.
func buildWebLogicCPE(version string) string {
	v := version
	if v == "" {
		v = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:oracle:weblogic_server:%s:*:*:*:*:*:*:*", v)
}

// maxT3ReadTimeout bounds how long we wait for the T3 handshake reply. A live
// WebLogic T3 listener answers within one round-trip; capping the wait keeps a
// non-WebLogic host (e.g. any HTTPS server on 443/7002 that silently ignores
// the plaintext handshake bytes) from stalling the whole plugin for the full
// scanner timeout before we fall through to the console probe.
const maxT3ReadTimeout = 3 * time.Second

// t3ReadTimeout returns the (possibly shortened) timeout used for the T3
// handshake read: min(timeout, maxT3ReadTimeout), with a sane floor if the
// caller passes a non-positive timeout.
func t3ReadTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 || timeout > maxT3ReadTimeout {
		return maxT3ReadTimeout
	}
	return timeout
}

// probeT3 sends the single benign handshake on the scanner-provided conn and
// classifies the reply. The whole operation is bounded by a deadline that is
// cleared on return (G3); the read is a single 4096-byte Recv (G2). An I/O
// failure is surfaced as ioErr; runWebLogic treats it as an expected negative
// (dropped/closed connection on a non-WebLogic host) and ignores it.
func probeT3(conn net.Conn, timeout time.Duration) (version string, detected bool, ioErr error) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	raw, err := utils.SendRecv(conn, t3Handshake, timeout)
	if err != nil {
		return "", false, err
	}
	version, detected = parseT3Response(raw)
	return version, detected, nil
}

// canSelfDialConsole reports whether the target has a concrete, routable address
// for the self-dialed HTTP console probe. When the address is unspecified
// (e.g. 0.0.0.0 in socks5h/proxy or unresolved scans) we skip the console
// corroborator rather than misdial a wrong local address or leak scan traffic
// outside the configured proxy; T3 detection still runs on the scanner-provided
// (proxy-aware) connection. Full proxy routing for the self-dial requires an
// engine-level dialer that is not exposed to plugins.
func canSelfDialConsole(target plugins.Target) bool {
	a := target.Address.Addr()
	return a.IsValid() && !a.IsUnspecified()
}

// dialConsoleConn opens a short-lived connection to the target for the HTTP
// console corroborator. The TLS variant mirrors the scanner's read-only cert
// posture (skip-verify) since the certificate is used only for fingerprinting.
func dialConsoleConn(target plugins.Target, timeout time.Duration, useTLS bool) (net.Conn, error) {
	addr := target.Address.String()
	if useTLS {
		d := &net.Dialer{Timeout: timeout}
		return tls.DialWithDialer(d, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- fingerprinting; certificate is not trusted
			ServerName:         target.Host,
		})
	}
	return net.DialTimeout("tcp", addr, timeout)
}

// probeConsole is a best-effort, non-fatal HTTP probe of the console login page
// on a self-dialed connection. Any dial/GET error yields (false, "", 0). The
// body is bounded and redirects are not followed (G5).
func probeConsole(target plugins.Target, timeout time.Duration, useTLS bool) (detected bool, title string, statusCode int) {
	conn, err := dialConsoleConn(target, timeout, useTLS)
	if err != nil {
		return false, "", 0
	}
	defer func() { _ = conn.Close() }()

	client := createHTTPClient(conn, timeout)
	// The conn is already TLS for the TLS variant, so speak plaintext HTTP over
	// it (the transport returns the dialed conn verbatim) — same idiom glassfish
	// uses for its TLS variant.
	url := "http://" + conn.RemoteAddr().String() + consolePath
	resp, err := doGet(client, url, target.Host)
	if err != nil {
		return false, "", 0
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	title = extractTitle(string(body))
	detected = matchConsole(title, resp.Header.Values("Set-Cookie"), resp.Header.Get("Server"))
	return detected, title, resp.StatusCode
}

// weblogicConsoleFinding reports that the admin console is reachable without
// authentication. Evidence is a static, non-sensitive string (G8).
func weblogicConsoleFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-weblogic-console-exposed",
		Severity:    plugins.SeverityMedium,
		Description: "Oracle WebLogic Server administration console (/console/login/LoginForm.jsp) is reachable without authentication on the network; the console provides application deployment and server configuration and should not be exposed to untrusted networks",
		Evidence:    "WebLogic admin console login page responded without credentials",
	}
}

// weblogicT3ExposedFinding reports that the T3 listener answered the handshake,
// disclosing the server version. Evidence is a static, non-sensitive string (G8).
func weblogicT3ExposedFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-weblogic-t3-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle WebLogic Server T3 listener is reachable and answers the T3 handshake, disclosing the server version and aiding targeted exploitation of T3/IIOP deserialization vulnerabilities",
		Evidence:    "WebLogic T3 handshake answered without credentials",
	}
}

// applyMisconfigs appends exposure findings and sets AnonymousAccess. The T3
// listener (deserialization RCE surface, CVE-2015-4852) and the HTTP admin
// console are independent attack surfaces, so each fires its own finding when
// present: an exposed console (Medium, only on a 2xx surface) additionally sets
// AnonymousAccess, while an answered T3 handshake always emits the Low banner
// finding. Called only under target.Misconfigs. Shared by both transport
// variants (DRY).
func applyMisconfigs(service *plugins.Service, adminConsole bool, consoleStatus int, t3Detected bool) {
	if adminConsole && isSuccessStatus(consoleStatus) {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, weblogicConsoleFinding())
	}
	if t3Detected {
		service.SecurityFindings = append(service.SecurityFindings, weblogicT3ExposedFinding())
	}
}

// runWebLogic is the shared probe+merge+emit path for both transport variants.
// It probes T3 on the scanner-provided conn and the HTTP console on a self-dialed
// conn, merges into one ServiceWebLogic, and applies the gated findings. The T3
// version is canonical; HTTP-only detection emits version "" and a wildcard CPE.
func runWebLogic(conn net.Conn, timeout time.Duration, target plugins.Target, useTLS bool) (*plugins.Service, error) {
	// Cap the T3 handshake read so a non-WebLogic host on 443/7002 that ignores
	// the plaintext handshake cannot stall the plugin for the full scanner
	// timeout before we fall through to the console probe. The console probe
	// keeps the full timeout (its dial may legitimately need the full budget).
	t3Version, t3Detected, _ := probeT3(conn, t3ReadTimeout(timeout))

	// Only run the self-dialed console corroborator when the target has a
	// concrete, routable address; otherwise skip it and rely on the T3 probe
	// (see canSelfDialConsole).
	consoleDetected, consoleTitle, consoleStatus := false, "", 0
	if canSelfDialConsole(target) {
		consoleDetected, consoleTitle, consoleStatus = probeConsole(target, timeout, useTLS)
	}

	// No WebLogic surface answered. A dropped/closed connection on a
	// non-WebLogic host is an expected negative for a fingerprinter, so we
	// return a clean (nil, nil) rather than a RequestError.
	if !t3Detected && !consoleDetected {
		return nil, nil
	}

	version := t3Version // T3 is the authoritative version source
	payload := plugins.ServiceWebLogic{
		T3:           t3Detected,
		T3Version:    t3Version,
		AdminConsole: consoleDetected,
		ConsoleTitle: consoleTitle,
		CPEs:         []string{buildWebLogicCPE(version)},
	}

	transport := plugins.TCP
	if useTLS {
		transport = plugins.TCPTLS
	}
	service := plugins.CreateServiceFrom(target, payload, useTLS, version, transport)
	if target.Misconfigs {
		applyMisconfigs(service, consoleDetected, consoleStatus, t3Detected)
		if useTLS {
			service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
		}
	}
	return service, nil
}

func (p *WebLogicPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return runWebLogic(conn, timeout, target, false)
}

// PortPriority prioritizes the WebLogic plaintext listener (7001) and the
// additional listener nmap probes (7003).
func (p *WebLogicPlugin) PortPriority(port uint16) bool {
	return port == 7001 || port == 7003
}
func (p *WebLogicPlugin) Name() string           { return plugins.ProtoOracleWebLogic }
func (p *WebLogicPlugin) Type() plugins.Protocol { return plugins.TCP }
func (p *WebLogicPlugin) Priority() int          { return -1 } // Runs before generic HTTP so it can claim the port

func (p *WebLogicTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return runWebLogic(conn, timeout, target, true)
}

// PortPriority prioritizes the WebLogic TLS listener (7002) and standard HTTPS
// (443).
func (p *WebLogicTLSPlugin) PortPriority(port uint16) bool {
	return port == 7002 || port == 443
}
func (p *WebLogicTLSPlugin) Name() string           { return plugins.ProtoOracleWebLogic }
func (p *WebLogicTLSPlugin) Type() plugins.Protocol { return plugins.TCPTLS }
func (p *WebLogicTLSPlugin) Priority() int          { return -1 } // Runs before generic HTTPS so it can claim the port

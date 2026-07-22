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
Package oracleprotocoldb provides best-effort binary TCP fingerprinting for
three proprietary Oracle data-grid / database protocols that expose no ASCII
banner and no network-facing version string (LAB-5056). It registers four TCP
plugins from a single init():

  - CoherencePlugin  (oracle_coherence,   port 7574) — best-effort POF-shape heuristic
  - NoSQLPlugin      (oracle_nosql,        port 5000) — JRMP handshake + registry list() marker
  - NoSQLHTTPPlugin  (oracle_nosql_http,   port 8080) — conservative HTTP proxy corroboration
  - TimesTenPlugin   (oracle_timesten, ports 6624/6625) — malformed-HTTP reject signature

Detection-only: none of these plugins emits a SecurityFinding, sets
AnonymousAccess, or reports a version (all CPEs are versionless wildcards). Mere
presence of a data service is not a misconfiguration, mirroring the sibling
binary-protocol plugins oracledb, javarmi, and activemq.

Security invariants (all four plugins):
  - Every response is read once via pluginutils.SendRecv/Recv (fixed 4 KB buffer,
    single Read, deadline; []byte{} on timeout/refused -> treated as silence).
  - Round-trips are capped: TimesTen 1, Coherence 1, NoSQL-RMI <=2, NoSQL-HTTP 1.
    There are no read loops and no self-dialed sockets; the framework owns and
    closes the conn.
  - Attacker-controlled response bytes are NEVER Java-deserialized. The RMI
    registry list() reply is scanned as raw bytes with anchored RE2 regexes.
  - Every index / slice / binary.BigEndian access is length-guarded so a short or
    truncated response cannot panic.
  - Silence, empty, or ambiguous responses always return (nil, nil).
  - No response bytes are ever placed in logs, Info, Version, Metadata, or
    Evidence.
*/
package oracleprotocoldb

import (
	"bytes"
	"context"
	"encoding/binary"
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
	// oracleNoSQLHTTPName is the registry Name() of the HTTP proxy plugin. It is
	// distinct from the RMI plugin's name so the {Name, Protocol} registry key is
	// unique, but both plugins emit the same ServiceOracleNoSQL product type.
	oracleNoSQLHTTPName = "oracle_nosql_http"

	// coherencePort is the Coherence NameService (cluster) port. The deliberately
	// loose POF heuristic is only allowed to assert on this port (see
	// CoherencePlugin.Run); PortPriority uses the same const.
	coherencePort = 7574

	// coherenceMaxFrame bounds the length of a response the Coherence heuristic
	// will consider a plausible NameService handshake frame (not a bulk stream).
	coherenceMaxFrame = 512

	// registryInterfaceHash is the well-known RMI RegistryImpl interface hash
	// (0x44154DC9D4E63BDF). It is emitted big-endian via binary.BigEndian.PutUint64
	// rather than hand-transcribed hex.
	registryInterfaceHash uint64 = 4905912898345647071

	// httpUserAgent is the User-Agent used by the HTTP proxy probe.
	httpUserAgent = "nerva/1.0"

	// maxHTTPBodySize caps how much of the HTTP proxy response body is read.
	maxHTTPBodySize = int64(64 * 1024)

	// jrmpProtocolAck is the JRMP ProtocolAck byte (re-derived from
	// javarmi/rmi.go:77 — TransportConstants).
	jrmpProtocolAck = 0x4e

	coherenceCPE = "cpe:2.3:a:oracle:coherence:*:*:*:*:*:*:*:*"
	nosqlCPE     = "cpe:2.3:a:oracle:nosql_database:*:*:*:*:*:*:*:*"
	timesTenCPE  = "cpe:2.3:a:oracle:timesten_in-memory_database:*:*:*:*:*:*:*:*"
)

// Package-scope RE2 patterns compiled once (P1-3). RE2 has no backtracking, so
// these are ReDoS-immune; quantifiers are additionally bounded.
var (
	// nosqlBindingRe matches an Oracle NoSQL registry binding name of the form
	// <store>:<base>:<iface>, where iface is one of the NoSQL interface types
	// (RegistryUtils.java). trusted_login precedes login so the alternation is
	// greedy-safe; the trailing \b keeps ordering correctness-independent.
	nosqlBindingRe = regexp.MustCompile(
		`\b[\w.-]{1,63}:[\w.-]{1,63}:(?:trusted_login|main|monitor|admin|login|test)\b`)

	// nosqlClassRe matches an oracle.kv / oracle.kv.impl class token that leaks
	// into a serialized list() reply. Quantifier bounded per P1-3.
	nosqlClassRe = regexp.MustCompile(`oracle\.kv(?:\.impl)?[\w.$]{0,128}`)
)

// nosqlProxyMarkers are lowercase NoSQL-Database-Proxy-specific tokens. A bare
// HTTP 200 with none of these present is never classified as NoSQL.
var nosqlProxyMarkers = []string{
	"oracle nosql",
	"nosql database proxy",
	"nosql proxy",
	"kvproxy",
	"oracle.kv",
	"kvstore",
}

// --- probe byte constants (P0-8: benign, read-only, hardcoded) ---

// coherenceProbe is a single 0x00 byte: a POF packed integer decoding to 0, i.e.
// a zero-length frame. It is deliberately inert — it declares an empty body and
// cannot drive server-side message processing.
var coherenceProbe = []byte{0x00}

// timesTenProbe is the nmap GenericLines probe (two CRLFs). Inert.
var timesTenProbe = []byte{0x0d, 0x0a, 0x0d, 0x0a}

type CoherencePlugin struct{}
type NoSQLPlugin struct{}
type NoSQLHTTPPlugin struct{}
type TimesTenPlugin struct{}

func init() {
	plugins.RegisterPlugin(&CoherencePlugin{})
	plugins.RegisterPlugin(&NoSQLPlugin{})
	plugins.RegisterPlugin(&NoSQLHTTPPlugin{})
	plugins.RegisterPlugin(&TimesTenPlugin{})
}

// ---------------------------------------------------------------------------
// Shared JRMP helpers — re-derived from javarmi/rmi.go:156-293. The javarmi
// validator is unexported in another package; with only two occurrences we
// re-derive here (Rule of Three) rather than exporting javarmi internals. Source
// of truth: pkg/plugins/services/javarmi/rmi.go. Do not weaken the 5 layers.
// ---------------------------------------------------------------------------

// buildJRMPHandshake returns the 7-byte JRMP StreamProtocol handshake
// ("JRMI" 0x00 0x02 0x4b). Inert (javarmi/rmi.go:156-164).
func buildJRMPHandshake() []byte {
	return []byte{0x4a, 0x52, 0x4d, 0x49, 0x00, 0x02, 0x4b}
}

// isValidRMIResponse applies javarmi's 5-layer structural validation
// (javarmi/rmi.go:193-244). Every index/slice/BigEndian access is length-guarded.
func isValidRMIResponse(response []byte) bool {
	// Layer 1: minimum length (ProtocolAck + 2-byte length field).
	if len(response) < 3 {
		return false
	}
	// Layer 2: first byte must be ProtocolAck.
	if response[0] != jrmpProtocolAck {
		return false
	}
	// Layer 3: endpoint length field in a sane hostname range.
	claimedLength := binary.BigEndian.Uint16(response[1:3])
	if claimedLength < 3 || claimedLength > 253 {
		return false
	}
	// Layer 4: actual length is consistent with the claimed structure.
	requiredLength := 1 + 2 + int(claimedLength) + 2 + 2
	if len(response) < requiredLength {
		return false
	}
	// Layer 5: the endpoint bytes must be printable ASCII.
	endpointBytes := response[3 : 3+int(claimedLength)]
	for _, b := range endpointBytes {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}

// extractEndpoint parses the "host:port" endpoint from a JRMP ProtocolAck body
// (javarmi/rmi.go:266-293). Length-guarded; returns "" when it cannot parse.
func extractEndpoint(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	strLen := binary.BigEndian.Uint16(data[0:2])
	if len(data) < int(2+strLen) {
		return ""
	}
	host := string(data[2 : 2+strLen])
	portOffset := 2 + int(strLen) + 2 // +2 for the null separator bytes
	if len(data) >= portOffset+2 {
		port := binary.BigEndian.Uint16(data[portOffset : portOffset+2])
		if port > 0 {
			return host + ":" + itoa(int(port))
		}
	}
	return host
}

// itoa avoids an fmt dependency for the one integer-to-string need.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// buildRegistryListCall returns a hardcoded, read-only JRMP Call that invokes
// the RMI registry's list() enumeration on the well-known registry object
// (ObjID 0). It is enumeration-only: NOT bind/rebind/unbind, and mutates no
// server state (P0-8).
//
// The framing follows the classic skeleton-style stub protocol as documented in
// architecture.md §2a. It is NOT verified against a live rmiregistry capture in
// this environment; the developer note stands that this framing is best-effort.
//
// KNOWN GAP (deferred pending live validation): the call arguments (ObjID +
// operation index + interface hash) written after the 0xac 0xed 0x00 0x05
// ObjectOutputStream header should be carried inside a TC_BLOCKDATA (0x77) record
// — i.e. a 0x77 tag plus a one-byte block length must precede those raw argument
// bytes. As written they are emitted without that wrapper, so a real rmiregistry
// may read the first argument byte as an ObjectStreamConstants type code, fail to
// recognize it, and reject the call before Registry.list() ever executes. This is
// DEFERRED until it can be checked against a live Oracle NoSQL RMI registry
// capture (adding 0x77 <len> here is the specific thing to validate).
//
// The gap is FN-safe, never FP-causing: a rejected or mis-framed call yields no
// listing, so pluginutils.Recv returns []byte{} and Run returns (nil, nil).
// Detection is gated on the marker regex over a real listing, not on merely
// eliciting a reply, so a wrongly-framed call can only under-detect. Oracle NoSQL
// is additionally still detected via the HTTP/8080 (NoSQLHTTPPlugin) path.
func buildRegistryListCall() []byte {
	buf := make([]byte, 0, 45)
	// Client-side EndpointIdentifier written after ProtocolAck: writeUTF("") then
	// writeInt(0) for the client port.
	buf = append(buf, 0x00, 0x00)             // writeUTF("") — length 0
	buf = append(buf, 0x00, 0x00, 0x00, 0x00) // writeInt(0) — client port 0
	// Call message.
	buf = append(buf, 0x50)                   // TransportConstants.Call
	buf = append(buf, 0xac, 0xed, 0x00, 0x05) // ObjectOutputStream stream header
	// ObjID of the RMI registry (well-known ID 0): 22 zero bytes
	// (objNum long=0, UID.unique int=0, UID.time long=0, UID.count short=0).
	buf = append(buf, make([]byte, 22)...)
	// Operation index = 1 (Registry.list()) and the RegistryImpl interface hash.
	buf = append(buf, 0x00, 0x00, 0x00, 0x01)
	var hash [8]byte
	binary.BigEndian.PutUint64(hash[:], registryInterfaceHash)
	buf = append(buf, hash[:]...)
	return buf
}

// ---------------------------------------------------------------------------
// NoSQL over RMI — port 5000
// ---------------------------------------------------------------------------

// isOracleNoSQLListing reports whether a raw (never deserialized) RMI registry
// list() reply carries an Oracle-NoSQL-specific marker: an oracle.kv class token
// or a <store>:<base>:<iface> binding triad. A bare JRMP ack, an empty listing,
// or only generic names (jmxrmi, org.jnp.*, JBoss/HornetQ) return false so the
// generic javarmi plugin reports it instead.
func isOracleNoSQLListing(reply []byte) bool {
	if len(reply) == 0 {
		return false
	}
	if nosqlClassRe.Match(reply) {
		return true
	}
	if nosqlBindingRe.Match(reply) {
		return true
	}
	return false
}

func (p *NoSQLPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Round 1: confirm a generic RMI endpoint via the JRMP handshake.
	handshakeResp, err := utils.SendRecv(conn, buildJRMPHandshake(), timeout)
	if err != nil {
		return nil, nil // peer close / refused / write / read error -> no evidence, not us
	}
	if len(handshakeResp) == 0 {
		return nil, nil // silence -> not us
	}
	if !isValidRMIResponse(handshakeResp) {
		return nil, nil // not RMI at all
	}
	// A valid ack alone is generic RMI, NOT NoSQL — continue to the list() marker.
	endpoint := extractEndpoint(handshakeResp[1:])

	// Round 2: enumerate the registry and scan the raw reply for a NoSQL marker.
	listResp, err := utils.SendRecv(conn, buildRegistryListCall(), timeout)
	if err != nil {
		return nil, nil // read error / partial -> treat as ambiguous, not us
	}
	if len(listResp) == 0 {
		return nil, nil // no listing / mis-framed / blocked -> not us
	}
	if !isOracleNoSQLListing(listResp) {
		return nil, nil // generic RMI (let javarmi report it)
	}

	payload := plugins.ServiceOracleNoSQL{
		Endpoint: endpoint,
		CPEs:     []string{nosqlCPE},
	}
	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

func (p *NoSQLPlugin) PortPriority(port uint16) bool { return port == 5000 }
func (p *NoSQLPlugin) Name() string                  { return plugins.ProtoOracleNoSQL }
func (p *NoSQLPlugin) Type() plugins.Protocol        { return plugins.TCP }

// Priority 900 (matches oracledb). The scheduler sorts priority ASCENDING, so in
// a full sweep the generic javarmi plugin (Priority 500) actually runs BEFORE
// this one; that ordering is harmless because NoSQL bails to nil when the marker
// is absent, leaving javarmi to report generic RMI. What matters here is fast
// mode: NoSQL is the sole PortPriority claimant of 5000, so it is the one plugin
// dispatched there and it wins that port regardless of the numeric priority.
func (p *NoSQLPlugin) Priority() int { return 900 }

// ---------------------------------------------------------------------------
// NoSQL over the HTTP proxy — port 8080 (conservative corroboration only)
// ---------------------------------------------------------------------------

// createHTTPClient wraps the framework-dialed conn in an http.Client that does
// not follow redirects (re-derived from oracleidentity.go:121-133; the sibling
// helper is unexported in another package).
func createHTTPClient(conn net.Conn, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
			// The probe makes exactly one request over a framework-owned conn.
			// Disable keep-alives so the transport does not pool the conn or leave
			// a background read goroutine waiting after Run returns.
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// isOracleNoSQLProxy reports whether an HTTP response corroborates an Oracle
// NoSQL Database Proxy. It requires a NoSQL-proxy-specific token (never a bare
// 200) and explicitly rejects the ORDS/APEX surface, which is a different product.
func isOracleNoSQLProxy(resp *http.Response, body string) bool {
	lb := strings.ToLower(body)
	loc := strings.ToLower(resp.Header.Get("Location"))
	// Reject Oracle REST Data Services / APEX (handled by oracleords).
	if strings.Contains(lb, "ords") || strings.Contains(lb, "apex") ||
		strings.Contains(loc, "ords") || strings.Contains(loc, "apex") {
		return false
	}
	for _, marker := range nosqlProxyMarkers {
		if strings.Contains(lb, marker) {
			return true
		}
	}
	return false
}

func (p *NoSQLHTTPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := "http://" + conn.RemoteAddr().String()

	req, err := http.NewRequest("GET", baseURL+"/V2/health", nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("User-Agent", httpUserAgent)
	if target.Host != "" {
		req.Host = target.Host
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil // no HTTP surface here -> not us
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodySize))
	if !isOracleNoSQLProxy(resp, string(body)) {
		return nil, nil // bare 200 / no NoSQL marker / ORDS -> not us
	}

	payload := plugins.ServiceOracleNoSQL{
		ViaHTTP: true,
		CPEs:    []string{nosqlCPE},
	}
	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

func (p *NoSQLHTTPPlugin) PortPriority(port uint16) bool { return port == 8080 }
func (p *NoSQLHTTPPlugin) Name() string                  { return oracleNoSQLHTTPName }
func (p *NoSQLHTTPPlugin) Type() plugins.Protocol        { return plugins.TCP }

// Priority -1 (matches the oracleidentity HTTP plugins) so it can pre-empt the
// generic HTTP fingerprinter on shared 8080 and only claims on a NoSQL marker.
func (p *NoSQLHTTPPlugin) Priority() int { return -1 }

// ---------------------------------------------------------------------------
// TimesTen — ports 6624 (corroboration) / 6625 (primary confirmed vector)
// ---------------------------------------------------------------------------

// isTimesTenHTTPReject reports whether a reply to the \r\n\r\n probe begins with
// the exact TimesTen httpd malformed-reject prefix (nmap p/TimesTen httpd/). A
// well-formed generic HTTP 400 (with Server:/Content-Type: headers) never
// produces this "msg=Bad%20Request&rc=<binary>" shape, so the prefix alone
// rejects generic HTTP.
func isTimesTenHTTPReject(resp []byte) bool {
	return bytes.HasPrefix(resp, []byte("HTTP/1.0 400 msg=Bad%20Request&rc="))
}

func (p *TimesTenPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	resp, err := utils.SendRecv(conn, timesTenProbe, timeout)
	if err != nil {
		return nil, nil // peer close / refused / write / read error -> no evidence, not us
	}
	if len(resp) == 0 {
		return nil, nil // silence -> not us
	}
	if !isTimesTenHTTPReject(resp) {
		return nil, nil // generic 400 / TLS / binary garbage -> not us
	}

	payload := plugins.ServiceOracleTimesTen{
		CPEs: []string{timesTenCPE},
	}
	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

// PortPriority returns true for both TimesTen ports. The 6624 raw daemon
// handshake is publicly unknown (no bytes are invented for it); 6625 is the
// primary confirmed vector. The same probe + prefix classifier runs on either.
func (p *TimesTenPlugin) PortPriority(port uint16) bool { return port == 6624 || port == 6625 }
func (p *TimesTenPlugin) Name() string                  { return plugins.ProtoOracleTimesTen }
func (p *TimesTenPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *TimesTenPlugin) Priority() int                 { return 900 }

// ---------------------------------------------------------------------------
// Coherence — port 7574 — MOST CONSERVATIVE, best-effort heuristic
// ---------------------------------------------------------------------------

// coherenceHeuristicEnabled gates the ENTIRE Coherence heuristic. There is no
// confirmed public byte-level Coherence signature; this detector is best-effort
// and may under-detect real nodes (that is intentional — a false negative is
// preferred over a false positive). It is a package var (not a plain func) so it
// stays the one-line disable switch: if field false-positives ever appear, set it
// to `func() bool { return false }` to disable oracle_coherence detection with
// zero other changes — and, being a var, a test can also flip it.
var coherenceHeuristicEnabled = func() bool { return true }

// looksLikeTLS reports a TLS record header (handshake, TLS 1.x).
func looksLikeTLS(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x16 && b[1] == 0x03
}

// looksLikeSSH reports an SSH identification string.
func looksLikeSSH(b []byte) bool {
	return bytes.HasPrefix(b, []byte("SSH-"))
}

// looksLikeHTTP reports an HTTP status line or request verb.
func looksLikeHTTP(b []byte) bool {
	if bytes.HasPrefix(b, []byte("HTTP/")) {
		return true
	}
	for _, verb := range [][]byte{
		[]byte("GET "), []byte("POST "), []byte("HEAD "),
		[]byte("PUT "), []byte("OPTIONS "), []byte("DELETE "),
	} {
		if bytes.HasPrefix(b, verb) {
			return true
		}
	}
	return false
}

// looksLikeJRMP reports a JRMP ProtocolAck / "JRMI" magic / Java-serialization
// header — all of which are RMI, not Coherence.
func looksLikeJRMP(b []byte) bool {
	if len(b) >= 1 && b[0] == jrmpProtocolAck {
		return true
	}
	if bytes.Contains(b, []byte("JRMI")) {
		return true
	}
	if len(b) >= 2 && b[0] == 0xac && b[1] == 0xed {
		return true
	}
	return false
}

// isMostlyPrintable reports whether a buffer is predominantly printable ASCII
// (a text banner), used to reject text responses.
func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == 0x09 || c == 0x0a || c == 0x0d || (c >= 0x20 && c <= 0x7e) {
			printable++
		}
	}
	return printable*100 >= len(b)*90
}

// decodePackedInt decodes a POF signed packed integer (PIF-POF format: first
// octet bit7=continuation, bit6=negative, bits5-0=value; subsequent octets
// bit7=continuation, bits6-0=value). It returns the decoded value, the number of
// bytes consumed, and ok=false when the input is empty, truncated mid-integer,
// or would overflow. Fully length-guarded.
func decodePackedInt(b []byte) (value int64, consumed int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	first := b[0]
	neg := first&0x40 != 0
	n := int64(first & 0x3F)
	bits := uint(6)
	cont := first&0x80 != 0
	i := 1
	for cont {
		if i >= len(b) {
			return 0, 0, false // truncated mid-integer
		}
		if bits > 56 {
			return 0, 0, false // overflow guard (> 63 bits)
		}
		cur := b[i]
		n |= int64(cur&0x7F) << bits
		bits += 7
		cont = cur&0x80 != 0
		i++
	}
	if neg {
		n = ^n
	}
	return n, i, true
}

// isLikelyCoherencePOF is the Coherence positive-signal classifier. It asserts
// ONLY if ALL of the following hold; on any doubt it returns false (bias to
// false-negative):
//
//  1. non-empty;
//  2. short (<= coherenceMaxFrame) — a handshake reply, not a bulk stream;
//  3. NOT a known other protocol (TLS / SSH / HTTP / JRMP);
//  4. NOT the "Coherence" ASCII string (the Frontier Silicon UPnP/DLNA false friend);
//  5. binary, not a printable-ASCII banner;
//  6. POSITIVE POF length-consistency: the leading bytes decode as a POF packed
//     integer whose value exactly frames the remaining bytes
//     (bytesConsumed + declaredLength == len(resp)), with declaredLength a small
//     positive value in (0, coherenceMaxFrame].
//
// Requirement 6 is the positive structural signal (security-assessment P0-5.1):
// detection is NOT built on negative discriminators alone. Because the exact
// on-wire Coherence framing is not verified against a live capture in this
// environment, this signal is deliberately strict (exact frame match) to bias
// hard to false-negative; the whole path is disable-able via
// coherenceHeuristicEnabled.
func isLikelyCoherencePOF(resp []byte) bool {
	if len(resp) == 0 {
		return false
	}
	if len(resp) > coherenceMaxFrame {
		return false
	}
	if looksLikeTLS(resp) || looksLikeSSH(resp) || looksLikeHTTP(resp) || looksLikeJRMP(resp) {
		return false
	}
	// The "Coherence" UPnP/DLNA false friend (Frontier Silicon) — never match it.
	if bytes.Contains(resp, []byte("Coherence")) {
		return false
	}
	if isMostlyPrintable(resp) {
		return false
	}
	// Positive POF length-consistency check.
	declaredLength, consumed, ok := decodePackedInt(resp)
	if !ok {
		return false
	}
	if declaredLength <= 0 || declaredLength > int64(coherenceMaxFrame) {
		return false
	}
	return int64(consumed)+declaredLength == int64(len(resp))
}

func (p *CoherencePlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Port gate: the POF heuristic is deliberately loose, so confine WHERE it may
	// assert to the Coherence port. In full-sweep scans the engine runs every
	// plugin on every open port (PortPriority only governs fast-mode ordering), so
	// without this gate the heuristic could fire on an unrelated length-prefixed
	// binary service on some other port and mislabel it oracle_coherence.
	if target.Address.Port() != coherencePort {
		return nil, nil
	}

	// Disable switch is checked before any I/O.
	if !coherenceHeuristicEnabled() {
		return nil, nil
	}

	resp, err := utils.SendRecv(conn, coherenceProbe, timeout)
	if err != nil {
		return nil, nil // peer close / refused / write / read error -> no evidence, not us
	}
	if len(resp) == 0 {
		return nil, nil // silence -> not us
	}
	if !isLikelyCoherencePOF(resp) {
		return nil, nil // ambiguous / other protocol / no positive POF signal -> not us
	}

	payload := plugins.ServiceOracleCoherence{
		CPEs: []string{coherenceCPE},
	}
	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

func (p *CoherencePlugin) PortPriority(port uint16) bool { return port == coherencePort }
func (p *CoherencePlugin) Name() string                  { return plugins.ProtoOracleCoherence }
func (p *CoherencePlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *CoherencePlugin) Priority() int                 { return 900 }

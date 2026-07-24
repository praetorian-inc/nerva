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
Package oracleprotocoldb fingerprints several proprietary Oracle data-grid /
database protocols (LAB-5056). It registers six plugins from a single init():

  - CoherenceHTTPPlugin    (oracle_coherence, ports 9612/30000) — PRIMARY,
    high-confidence Coherence detector over cleartext HTTP: the Prometheus
    /metrics endpoint (vendor:coherence_* markers) and Management-over-REST
    (/management/coherence/cluster JSON). Both expose an exact version and, for
    management, cluster metadata. Not port-gated — the markers are unambiguous, so
    the ports are only the fast-mode PortPriority defaults.
  - CoherenceHTTPTLSPlugin (oracle_coherence, ports 9612/30000) — the same
    high-confidence HTTP detector over a TLS-wrapped connection.
  - CoherencePlugin        (oracle_coherence, port 7574) — LOW-CONFIDENCE,
    best-effort binary POF-shape heuristic on the TCMP cluster/NameService port.
    DISABLED BY DEFAULT: live validation proved real Coherence CE 22.06.10 is
    silent to the POF probe on 7574 (it detects nothing real) while the heuristic
    can false-positive on any short length-prefixed binary service on that port.
    The HTTP metrics (/metrics) and management (/management/coherence/cluster)
    vectors above are the supported detection paths. It is gated behind
    coherenceHeuristicEnabled (an embedder can flip that toggle to re-enable the
    best-effort 7574 heuristic) and biased hard to false-negative.
  - NoSQLPlugin      (oracle_nosql,        port 5000) — JRMP handshake + registry list()
    oracle.kv class-token marker
  - NoSQLHTTPPlugin  (oracle_nosql_http,   port 8080) — HTTP proxy product-name markers on
    any port (8080 is only the fast-mode PortPriority default, not a gate)
  - TimesTenPlugin   (oracle_timesten, ports 6624/6625) — malformed-HTTP reject signature

The binary detectors (Coherence 7574 heuristic, NoSQL, TimesTen) are
detection-only: they emit no SecurityFinding, set no AnonymousAccess, and report
no version (all their CPEs are versionless wildcards), mirroring the sibling
binary-protocol plugins oracledb, javarmi, and activemq. The Coherence HTTP
detectors additionally report the parsed version (in the CPE version component and
Service.Version) and, under target.Misconfigs, an exposed-surface SecurityFinding
with AnonymousAccess, mirroring the sibling Oracle HTTP plugins (oracleidentity,
oraclegoldengate).

Security invariants (all four plugins):
  - Every read goes through pluginutils.SendRecv/Recv (fixed 4 KB buffer per Read,
    deadline; []byte{} on timeout/refused -> treated as silence). Some paths do a
    small BOUNDED read-accumulation to tolerate TCP segmentation (a valid ack,
    reject, or POF frame can be split across segments): the NoSQL round-1 JRMP
    handshake, the TimesTen probe, and the Coherence POF handshake each read at most 3
    times total, only while the bytes so far stay consistent with the target shape; the
    NoSQL round-2 registry list() loop reads until the marker appears or the buffer is
    exhausted. NoSQL-HTTP still reads once.
  - Requests are capped: TimesTen 1, Coherence 1, NoSQL-RMI <=2, NoSQL-HTTP 1. Every
    read loop is bounded by ONE absolute deadline (time.Now().Add(timeout), NOT a fresh
    per-read timeout, so a drip-feeding peer cannot amplify the wall-clock) plus a
    read/iteration cap; the round-2 list() loop additionally has a total-byte cap. There
    are no self-dialed sockets; the framework owns and closes the conn.
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
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
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

	// oracleCoherenceHTTPName is the registry Name() shared by both HTTP Coherence
	// plugins (plaintext and TLS). It is distinct from the byte-heuristic plugin's
	// name (ProtoOracleCoherence) so the {Name, Protocol} registry key is unique —
	// the TCP heuristic already owns {TCP, oracle_coherence} — but all three
	// plugins still emit the same ServiceOracleCoherence product type
	// (ProtoOracleCoherence). The plaintext/TLS variants can share this one name
	// because they differ by Protocol (TCP vs TCPTLS), mirroring the sibling
	// oracleidentity OAM/OIM TCP+TLS variants.
	oracleCoherenceHTTPName = "oracle_coherence_http"

	// coherencePort is the Coherence NameService (cluster) port. The deliberately
	// loose POF heuristic is only allowed to assert on this port (see
	// CoherencePlugin.Run); PortPriority uses the same const.
	coherencePort = 7574

	// coherenceMetricsPort / coherenceMgmtPort are the Coherence Prometheus
	// metrics and Management-over-REST default ports. They only govern fast-mode
	// ordering via the HTTP plugins' PortPriority; HTTP classification is NOT
	// port-gated — it rests solely on unambiguous Coherence markers (see
	// detectCoherenceHTTP), so custom-port deployments are detected too.
	coherenceMetricsPort = 9612
	coherenceMgmtPort    = 30000

	// coherenceMaxFrame bounds the length of a response the Coherence heuristic
	// will consider a plausible NameService handshake frame (not a bulk stream).
	coherenceMaxFrame = 512

	// nosqlRMIPort is the Oracle NoSQL RMI registry default port. It only governs
	// fast-mode ordering via NoSQLPlugin.PortPriority; classification is NOT
	// port-gated — the unambiguous oracle.kv class token is the sole discriminator on
	// any port (see NoSQLPlugin.Run / oracleNoSQLListingMatches).
	nosqlRMIPort = 5000

	// nosqlHTTPPort is the Oracle NoSQL Database Proxy default port. It only governs
	// fast-mode ordering via NoSQLHTTPPlugin.PortPriority; HTTP classification is NOT
	// port-gated — it rests solely on unambiguous product-name markers, so 80/443/custom
	// deployments are detected too (see NoSQLHTTPPlugin.Run / isOracleNoSQLProxy).
	nosqlHTTPPort = 8080

	// registryInterfaceHash is the well-known RMI RegistryImpl interface hash
	// (0x44154DC9D4E63BDF). It is emitted big-endian via binary.BigEndian.PutUint64
	// rather than hand-transcribed hex.
	registryInterfaceHash uint64 = 4905912898345647071

	// httpUserAgent is the User-Agent used by the HTTP proxy probe.
	httpUserAgent = "nerva/1.0"

	// maxHTTPBodySize caps how much of the HTTP proxy response body is read.
	maxHTTPBodySize = int64(64 * 1024)

	// maxRegistryListResponse / maxRegistryListReads bound the RMI registry list()
	// read loop (round 2). TCP may split the listing across segments, and a large
	// listing can exceed a single ~4 KB Recv, so the reply is accumulated until the
	// NoSQL marker is seen — but stays bounded (total bytes and iteration count) so a
	// chatty or hostile peer can never drive an unbounded read. Mirrors the
	// oracledirectory (LDAP) rootDSE read loop; each read inherits pluginutils.Recv's
	// per-call 4096-byte cap and the connection timeout.
	maxRegistryListResponse = 64 * 1024
	maxRegistryListReads    = 16

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
	// nosqlClassRe matches an oracle.kv / oracle.kv.impl class token that leaks
	// into a serialized list() reply. Quantifier bounded per P1-3. This is the SOLE
	// discriminator for RMI NoSQL classification (see oracleNoSQLListingMatches).
	//
	// DESIGN DECISION — binding-name triads are intentionally NOT used for
	// classification. An Oracle NoSQL registry binding NAME has the shape
	// <store>:<resourceId>:<InterfaceType> (the final segment an UPPERCASE Java
	// InterfaceType enum member such as ADMIN/MAIN/MONITOR/LOGIN/TRUSTED_LOGIN). That
	// word:word:ENUM shape is NOT Oracle-specific: a generic non-NoSQL RMI registry can
	// legitimately expose a colliding role (e.g. service:node:ADMIN), which no regex can
	// distinguish from a true NoSQL binding. Any triad-based heuristic therefore
	// oscillates — flagged false-positive one review round, false-negative the next — so
	// it is deliberately removed. Detection rests ONLY on the unambiguous oracle.kv class
	// token. A binding-only listing (no class token present) is deliberately NOT
	// classified: FN-safe (a real NoSQL registry whose reply happens to omit the class
	// token is left to javarmi as generic RMI) and FP-free (no ambiguous marker exists).
	nosqlClassRe = regexp.MustCompile(`oracle\.kv(?:\.impl)?[\w.$]{0,128}`)

	// ordsApexRejectRe matches the Oracle REST Data Services / APEX surface (a
	// different Oracle product, handled by oracleords) as ORDS/APEX-SPECIFIC tokens,
	// NOT as a bare substring: a plain strings.Contains(body,"ords") wrongly rejects
	// ordinary words like "records" or "keywords" (a false negative). The \b word
	// boundaries keep "ords"/"apex" specific while still matching the "/ords/" and
	// "/apex/" URL paths and the full "oracle rest data services" / "oracle
	// application express" product names.
	ordsApexRejectRe = regexp.MustCompile(
		`\bords\b|\bapex\b|oracle rest data services|oracle application express`)

	// coherenceMetricsVersionRe extracts the exact Coherence version from the
	// version="X" label of a Prometheus vendor:coherence_ metric line (e.g.
	// `vendor:coherence_cluster_size{cluster="...", version="22.06.10"} 1`). The
	// [^\n]{0,512} span keeps the match confined to the single metric line that
	// carries the vendor:coherence_ marker, and every quantifier is bounded per
	// P1-3 (RE2 is backtracking-free, so this is ReDoS-immune).
	coherenceMetricsVersionRe = regexp.MustCompile(
		`vendor:coherence_[^\n]{0,512}version="([0-9][0-9.]{0,32})"`)
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

type CoherenceHTTPPlugin struct{}
type CoherenceHTTPTLSPlugin struct{}
type CoherencePlugin struct{}
type NoSQLPlugin struct{}
type NoSQLHTTPPlugin struct{}
type TimesTenPlugin struct{}

func init() {
	plugins.RegisterPlugin(&CoherenceHTTPPlugin{})
	plugins.RegisterPlugin(&CoherenceHTTPTLSPlugin{})
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

// couldBePartialRMIAck reports whether resp is a non-empty prefix still consistent
// with an as-yet-incomplete JRMP ProtocolAck — i.e. isValidRMIResponse fails ONLY
// because more bytes are needed, not because resp positively contradicts the ack
// shape. TCP may split the fixed-size ack across segments, so a single Recv can
// return a valid ack's leading prefix; this predicate decides whether accumulating
// one more bounded read is worthwhile. It never widens acceptance (isValidRMIResponse
// still makes the final call), so detection stays FN-safe: a mis-read only under-detects.
func couldBePartialRMIAck(resp []byte) bool {
	if len(resp) == 0 {
		return false
	}
	// First byte, once present, must be the ProtocolAck; anything else is not RMI and
	// reading more bytes cannot change that.
	if resp[0] != jrmpProtocolAck {
		return false
	}
	// Too short to even hold the 2-byte endpoint length field -> could still complete.
	if len(resp) < 3 {
		return true
	}
	// Endpoint length field must be in the sane hostname range; out of range contradicts.
	claimedLength := binary.BigEndian.Uint16(resp[1:3])
	if claimedLength < 3 || claimedLength > 253 {
		return false
	}
	// If the full structural length is already present, isValidRMIResponse failed for a
	// non-length reason (non-printable endpoint bytes) -> more reads won't help.
	requiredLength := 1 + 2 + int(claimedLength) + 2 + 2
	if len(resp) >= requiredLength {
		return false
	}
	// The endpoint bytes received so far must be printable ASCII; a non-printable byte
	// contradicts the ack shape.
	for _, b := range resp[3:] {
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
// architecture.md §2a. The call arguments (ObjID + operation index + interface
// hash) written after the 0xac 0xed 0x00 0x05 ObjectOutputStream header are now
// carried inside a TC_BLOCKDATA (0x77) record — a 0x77 tag plus a one-byte block
// length (0x22 = 34) precede those argument bytes — per the reviewer consensus
// that Java's ObjectInputStream reads those primitives from a block-data record,
// not raw from the stream. Without it a real rmiregistry could read the first
// argument byte as an ObjectStreamConstants type code and reject the call before
// Registry.list() runs.
//
// STILL UNVALIDATED end-to-end: the block-data framing is applied, but the FULL
// call (operation-index encoding, interface hash, and the ProtocolAck handshake
// sequence) has NOT been confirmed against a live Oracle NoSQL rmiregistry
// capture in this environment. Live validation against a real capture remains the
// pre-merge confirmation for this vector. The response-side marker (the oracle.kv
// class token accepted by oracleNoSQLListingMatches) is Oracle-specific and
// unambiguous, so it classifies on any port with no port gate. Binding-name triads
// are deliberately NOT used for classification: their word:word:ENUM shape is not
// Oracle-specific and oscillates between false positives and negatives (see
// nosqlClassRe). Likewise the HTTP path keys only on unambiguous product-name markers
// (see isOracleNoSQLProxy), never on a health beacon.
//
// This is FN-safe, never FP-causing: a rejected or mis-framed call yields no
// listing, so pluginutils.Recv returns []byte{} and Run returns (nil, nil).
// Detection is gated on the marker regex over a real listing, not on merely
// eliciting a reply, so a wrongly-framed call can only under-detect. Oracle NoSQL
// is additionally still detected via the HTTP/8080 (NoSQLHTTPPlugin) path.
func buildRegistryListCall() []byte {
	buf := make([]byte, 0, 47)
	// Client-side EndpointIdentifier written after ProtocolAck: writeUTF("") then
	// writeInt(0) for the client port.
	buf = append(buf, 0x00, 0x00)             // writeUTF("") — length 0
	buf = append(buf, 0x00, 0x00, 0x00, 0x00) // writeInt(0) — client port 0
	// Call message.
	buf = append(buf, 0x50)                   // TransportConstants.Call
	buf = append(buf, 0xac, 0xed, 0x00, 0x05) // ObjectOutputStream stream header
	// TC_BLOCKDATA framing: Java's ObjectInputStream requires the primitive call
	// arguments below (ObjID + operation index + interface hash) to be carried
	// inside a block-data record, not written raw after the stream header. 0x77 is
	// TransportConstants/ObjectStreamConstants TC_BLOCKDATA; 0x22 is the one-byte
	// block length = 34 = 22 (ObjID) + 4 (op index) + 8 (interface hash).
	buf = append(buf, 0x77, 0x22)
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

// hasNoSQLClassToken reports the reliable oracle.kv / oracle.kv.impl class token.
// It is the sole, unambiguous NoSQL discriminator and is trusted on ANY port
// (see oracleNoSQLListingMatches).
func hasNoSQLClassToken(reply []byte) bool {
	return len(reply) > 0 && nosqlClassRe.Match(reply)
}

// oracleNoSQLListingMatches is the classifier used by NoSQLPlugin.Run. Classification
// rests SOLELY on the unambiguous oracle.kv class token, which is Oracle-specific on
// any port. Binding-name triads are intentionally NOT consulted: their
// <store>:<resourceId>:<InterfaceType> shape is not Oracle-specific and produced
// oscillating false positives/negatives (a generic RMI registry can expose a colliding
// role such as service:node:ADMIN — see nosqlClassRe). A binding-only listing that
// carries no class token is deliberately left unclassified, so the generic javarmi
// plugin reports it as generic RMI instead — FN-safe and FP-free.
func oracleNoSQLListingMatches(reply []byte) bool {
	return hasNoSQLClassToken(reply)
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
	// TCP may split the fixed-size JRMP ProtocolAck across segments, so a single Recv
	// can return a valid ack's leading prefix that isValidRMIResponse rejects purely for
	// being too short, dropping a real RMI endpoint. While the bytes so far stay
	// consistent with an incomplete ack (couldBePartialRMIAck), accumulate a small,
	// bounded number of extra reads under ONE absolute deadline (mirrors the round-2
	// loop) so a drip-feeding peer cannot reset the timeout per read. FN-safe: a
	// positively contradicting shape stops immediately, and a mis-read only under-detects.
	if !isValidRMIResponse(handshakeResp) {
		deadline := time.Now().Add(timeout)
		// At most 2 extra reads (<=3 total) — enough to reassemble a split ack without
		// turning this into an unbounded read.
		for reads := 0; reads < 2 &&
			!isValidRMIResponse(handshakeResp) &&
			couldBePartialRMIAck(handshakeResp); reads++ {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			chunk, rerr := utils.Recv(conn, remaining)
			handshakeResp = append(handshakeResp, chunk...)
			if rerr != nil || len(chunk) == 0 {
				break // partial-read error (bytes already appended) or silence/EOF -> stop
			}
		}
	}
	if !isValidRMIResponse(handshakeResp) {
		return nil, nil // not RMI at all
	}
	// A valid ack alone is generic RMI, NOT NoSQL — continue to the list() marker.
	endpoint := extractEndpoint(handshakeResp[1:])

	// Round 2: enumerate the registry and scan the raw reply for a NoSQL marker. The
	// list() reply can arrive across several TCP segments and may exceed a single
	// ~4 KB Recv, so accumulate into a bounded buffer and test the marker against the
	// whole buffer rather than a single read. On a partial-read error, Recv still
	// returns the bytes received before the error, so those are appended and scanned
	// too before stopping. The loop is bounded by a total-byte cap and an iteration
	// cap so a chatty or hostile peer can never drive an unbounded read; no extra
	// requests are issued (the round-1 handshake and the list() request bytes are
	// unchanged). This mirrors the oracledirectory (LDAP) rootDSE read loop.
	if err := utils.Send(conn, buildRegistryListCall(), timeout); err != nil {
		return nil, nil // write error -> no evidence, not us
	}
	// ONE absolute deadline for the WHOLE loop. Passing the full timeout to every Recv
	// would let a drip-feeding peer reset the clock on each of up to maxRegistryListReads
	// iterations and occupy a worker for ~maxRegistryListReads*timeout. Instead each Recv
	// gets only the time still remaining, so the loop's total wall-clock is bounded by
	// ~timeout. The byte-cap and iteration-cap below are unchanged.
	deadline := time.Now().Add(timeout)
	var listResp []byte
	for reads := 0; reads < maxRegistryListReads && len(listResp) < maxRegistryListResponse; reads++ {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break // whole-loop deadline exhausted -> stop
		}
		chunk, err := utils.Recv(conn, remaining)
		listResp = append(listResp, chunk...)
		if oracleNoSQLListingMatches(listResp) {
			break // NoSQL marker present in the accumulated buffer -> done
		}
		if err != nil || len(chunk) == 0 {
			break // partial-read error (bytes already scanned) or silence/EOF -> stop
		}
	}
	if !oracleNoSQLListingMatches(listResp) {
		// No listing / generic RMI / mis-framed / blocked / silence -> not us. An empty
		// buffer also lands here (oracleNoSQLListingMatches returns false), so the
		// ambiguous "error with no bytes" case is covered too. Let javarmi report
		// generic RMI.
		return nil, nil
	}

	payload := plugins.ServiceOracleNoSQL{
		Endpoint: endpoint,
		CPEs:     []string{nosqlCPE},
	}
	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

func (p *NoSQLPlugin) PortPriority(port uint16) bool { return port == nosqlRMIPort }
func (p *NoSQLPlugin) Name() string                  { return plugins.ProtoOracleNoSQL }
func (p *NoSQLPlugin) Type() plugins.Protocol        { return plugins.TCP }

// Priority 400 — deliberately BELOW the generic javarmi plugin (Priority 500).
// The scheduler sorts priority ASCENDING, so this NoSQL plugin runs FIRST: it
// gets to inspect the registry listing for the oracle.kv/NoSQL marker before
// javarmi claims the endpoint. If the marker is absent it returns nil, leaving
// javarmi (500) to report the generic RMI service. If NoSQL ran AFTER javarmi,
// javarmi would match the RMI handshake and win (first non-nil result), and an
// Oracle NoSQL registry would be misidentified as generic RMI — the "bail to
// nil, let javarmi handle generic RMI" design requires NoSQL to run first.
// NoSQL still bails to nil quickly on non-NoSQL ports, so running earlier only
// reorders dispatch and adds no new probes.
//
// IMPORTANT: the "bail to nil, javarmi reports the generic RMI registry" fallback
// only holds in FULL-SWEEP mode, where the engine runs every plugin on every open
// port (so javarmi also runs on 5000). In FAST mode plugins run on their PortPriority
// default ports only, and 5000 is NOT one of javarmi's default ports (its
// commonRMIPorts are 1098/1099/9999/10000/10001/10099). So in fast mode a non-NoSQL
// RMI registry on 5000 is probed only by this plugin; when it bails to nil nothing
// else claims the port and there is simply no result — javarmi does not report it.
func (p *NoSQLPlugin) Priority() int { return 400 }

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
// NoSQL Database Proxy. Classification rests SOLELY on unambiguous product-name
// markers (nosqlProxyMarkers), matched in the body or the Location header; a bare
// 200 with no marker present is never classified. It explicitly rejects the
// ORDS/APEX surface, a different Oracle product handled by oracleords. A response
// carrying only health/status data (no product token) is deliberately not classified.
func isOracleNoSQLProxy(resp *http.Response, body string) bool {
	lb := strings.ToLower(body)
	loc := strings.ToLower(resp.Header.Get("Location"))
	// Reject Oracle REST Data Services / APEX (handled by oracleords). Match an
	// ORDS/APEX-SPECIFIC token (see ordsApexRejectRe), not a bare "ords" substring —
	// otherwise ordinary words like "records"/"keywords" in a genuine NoSQL response
	// would be wrongly rejected.
	if ordsApexRejectRe.MatchString(lb) || ordsApexRejectRe.MatchString(loc) {
		return false
	}
	// Scan both the body and the Location header: a redirect may carry the product
	// name in Location before any body is sent, so a marker there must still count.
	for _, marker := range nosqlProxyMarkers {
		if strings.Contains(lb, marker) || strings.Contains(loc, marker) {
			return true
		}
	}
	return false
}

func (p *NoSQLHTTPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := "http://" + conn.RemoteAddr().String()

	// Probe the root path: the proxy's landing/error response body and any redirect
	// Location surface the product-name markers (nosqlProxyMarkers) that
	// isOracleNoSQLProxy keys on. /V2/health returns only a status body with no product
	// token, so it is deliberately NOT used. Detection rests solely on those unambiguous
	// markers, so it is FP-safe on ANY port and needs no port gate — 80/443/custom-port
	// deployments are detected too.
	req, err := http.NewRequest("GET", baseURL+"/", nil)
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

func (p *NoSQLHTTPPlugin) PortPriority(port uint16) bool { return port == nosqlHTTPPort }
func (p *NoSQLHTTPPlugin) Name() string                  { return oracleNoSQLHTTPName }
func (p *NoSQLHTTPPlugin) Type() plugins.Protocol        { return plugins.TCP }

// Priority -1 (matches the oracleidentity HTTP plugins) so it can pre-empt the
// generic HTTP fingerprinter on shared 8080 and only claims on a NoSQL marker.
func (p *NoSQLHTTPPlugin) Priority() int { return -1 }

// ---------------------------------------------------------------------------
// TimesTen — ports 6624 (corroboration) / 6625 (primary confirmed vector)
// ---------------------------------------------------------------------------

// isTimesTenHTTPReject reports whether a reply to the \r\n\r\n probe carries the
// distinctive TimesTen httpd malformed-reject shape (nmap p/TimesTen httpd/): an
// "HTTP/1.x" status line together with the "msg=Bad%20Request&rc=<binary>" token.
// The status line is matched as HTTP/1. (not HTTP/1.0) so a future daemon that
// answers over HTTP/1.1 still matches, while the required msg=Bad%20Request&rc=
// token keeps this TimesTen-specific: a well-formed generic HTTP 400 (with
// Server:/Content-Type: headers) never produces that shape.
func isTimesTenHTTPReject(resp []byte) bool {
	return bytes.HasPrefix(resp, []byte("HTTP/1.")) &&
		bytes.Contains(resp, []byte("msg=Bad%20Request&rc="))
}

// couldBeTimesTenRejectPrefix reports whether resp is still consistent with the
// leading bytes of a TimesTen httpd malformed-reject: either resp already begins with
// the "HTTP/1." status line (the distinctive msg=Bad%20Request&rc= token may just not
// have arrived yet), or resp is itself a prefix of "HTTP/1." (the status line was
// split mid-token). Used to decide whether accumulating one more bounded read is
// worthwhile. FN-safe: it never widens acceptance (isTimesTenHTTPReject makes the
// final call), so a mis-read only under-detects.
func couldBeTimesTenRejectPrefix(resp []byte) bool {
	prefix := []byte("HTTP/1.")
	if len(resp) < len(prefix) {
		return bytes.HasPrefix(prefix, resp)
	}
	return bytes.HasPrefix(resp, prefix)
}

func (p *TimesTenPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	resp, _ := utils.SendRecv(conn, timesTenProbe, timeout)
	// On a partial-read error, SendRecv still returns the bytes received before the
	// error; the distinctive "HTTP/1. ... msg=Bad%20Request&rc=" reject prefix may
	// already be in those partial bytes, so evaluate whatever we got rather than
	// discarding it (mirrors the NoSQL round-2 partial-read handling). A single
	// empty-buffer check covers both silence and an error with no bytes at all.
	if len(resp) == 0 {
		return nil, nil // silence / error with no bytes -> not us
	}
	// TCP may split the reject so the "HTTP/1." status line and the distinctive
	// msg=Bad%20Request&rc= token land in separate segments. While the bytes so far
	// stay consistent with a reject prefix (couldBeTimesTenRejectPrefix), accumulate a
	// small, bounded number of extra reads under ONE absolute deadline (mirrors the
	// NoSQL round-2 loop) so a drip-feeding peer cannot reset the timeout per read.
	// FN-safe: a mis-read only under-detects.
	if !isTimesTenHTTPReject(resp) && couldBeTimesTenRejectPrefix(resp) {
		deadline := time.Now().Add(timeout)
		for reads := 0; reads < 2 &&
			!isTimesTenHTTPReject(resp) &&
			couldBeTimesTenRejectPrefix(resp); reads++ {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			chunk, rerr := utils.Recv(conn, remaining)
			resp = append(resp, chunk...)
			if rerr != nil || len(chunk) == 0 {
				break // partial-read error (bytes already appended) or silence/EOF -> stop
			}
		}
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
// Coherence over HTTP — ports 9612 (metrics) / 30000 (management) — PRIMARY,
// HIGH-CONFIDENCE vectors
// ---------------------------------------------------------------------------
//
// These are the reliable Coherence detectors. Live validation against a real
// Coherence CE 22.06.10 node confirmed two unmistakable HTTP surfaces:
//
//  1. Prometheus metrics (default port 9612): GET /metrics returns text/plain
//     lines like `vendor:coherence_cluster_size{cluster="...", version="22.06.10"} 1`.
//     The vendor:coherence_ metric-name prefix (and/or role="CoherenceServer") is
//     definitive, and the version="X" label carries the exact version.
//  2. Management-over-REST (default port 30000): GET /management/coherence/cluster
//     returns JSON with a version field plus Coherence markers (clusterName,
//     licenseMode, a links[].href containing management/coherence).
//
// Classification rests SOLELY on those unambiguous markers, so both detectors are
// FP-safe on ANY port and need no port gate — the ports above are only the
// fast-mode PortPriority defaults. A bare 200 with no marker is never classified.

// coherenceHTTPResult carries the metadata parsed from a positive HTTP detection.
type coherenceHTTPResult struct {
	version     string // exact Coherence version (metrics version= label or management JSON)
	clusterName string // Management-over-REST clusterName (empty for the metrics vector)
	licenseMode string // Management-over-REST licenseMode (empty for the metrics vector)
}

// coherenceMgmtResponse is the subset of the Management-over-REST cluster JSON
// this plugin reads. Only these fields are decoded; the rest of the document is
// ignored. JSON (unlike the RMI path) is safe to decode: encoding/json never
// executes attacker-controlled types.
type coherenceMgmtResponse struct {
	Version     string `json:"version"`
	ClusterName string `json:"clusterName"`
	LicenseMode string `json:"licenseMode"`
	Links       []struct {
		Href string `json:"href"`
	} `json:"links"`
}

// createCoherenceHTTPClient wraps a single net.Conn in an http.Client that does
// not follow redirects. Keep-alives are LEFT ENABLED so the management vector can
// issue its two sequential GETs (the canonical /management/coherence/cluster path
// then the /management/coherence fallback) over the one conn — mirrors the sibling
// oracleidentity / oraclegoldengate HTTP clients. It is used both for the metrics
// probe (over the framework-injected conn) and for the management probe (over a
// freshly self-dialed conn); the two probes never share a connection (see
// detectCoherenceHTTP).
func createCoherenceHTTPClient(conn net.Conn, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// drainAndClose fully drains (bounded by maxHTTPBodySize) and then closes an HTTP
// response body. Draining before Close is what lets net/http return the
// connection to a clean, reusable state; a bare Close on an unread body leaves the
// connection state indeterminate and can corrupt a later probe on that same conn.
func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHTTPBodySize))
	_ = resp.Body.Close()
}

// doGet issues a GET with the nerva User-Agent and, when host is non-empty, a
// target Host header for name-based virtual hosts (the conn is still dialed by IP
// via the client's transport). Mirrors the sibling Oracle HTTP plugins.
func doGet(client *http.Client, url string, host string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", httpUserAgent)
	if host != "" {
		req.Host = host
	}
	return client.Do(req)
}

// isSuccessStatus reports whether an HTTP status code is a 2xx success.
func isSuccessStatus(code int) bool {
	return code >= 200 && code < 300
}

// buildCoherenceCPE returns the Coherence CPE, filling the version component with
// the parsed version when known and wildcarding it otherwise. String
// concatenation avoids an fmt dependency (see itoa).
func buildCoherenceCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return "cpe:2.3:a:oracle:coherence:" + version + ":*:*:*:*:*:*:*"
}

// coherenceExposedFinding reports that an unauthenticated Coherence metrics /
// management HTTP surface is reachable. Emitted only under target.Misconfigs,
// mirroring the sibling oracleidentity findings. Evidence carries no response
// bytes.
func coherenceExposedFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-coherence-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle Coherence management/metrics HTTP surface is reachable without authentication; the Coherence Prometheus metrics and Management-over-REST endpoints are exposed to the network",
		Evidence:    "Oracle Coherence metrics/management endpoints responded without credentials",
	}
}

// detectCoherenceMetrics probes the Prometheus /metrics endpoint. It fires on the
// definitive vendor:coherence_ metric-name prefix (or the role="CoherenceServer"
// label) and, when present, parses the exact version from the version= label of a
// vendor:coherence_ line. FN-safe: any transport error or missing marker yields
// (…, false).
func detectCoherenceMetrics(client *http.Client, baseURL, host string) (coherenceHTTPResult, bool) {
	resp, err := doGet(client, baseURL+"/metrics", host)
	if err != nil {
		return coherenceHTTPResult{}, false
	}
	defer drainAndClose(resp)
	if !isSuccessStatus(resp.StatusCode) {
		return coherenceHTTPResult{}, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodySize))
	text := string(body)
	if !strings.Contains(text, "vendor:coherence_") &&
		!strings.Contains(text, `role="CoherenceServer"`) {
		return coherenceHTTPResult{}, false
	}
	res := coherenceHTTPResult{}
	if m := coherenceMetricsVersionRe.FindStringSubmatch(text); len(m) >= 2 {
		res.version = m[1]
	}
	return res, true
}

// coherenceMgmtPaths lists the Management-over-REST paths in probe order: the
// canonical cluster path first, then the bare fallback. Shared by the single-client
// detectCoherenceManagement (direct unit tests) and the per-path fresh-dial loop in
// detectCoherenceManagementFresh (production) so both agree on the ordering.
var coherenceMgmtPaths = []string{"/management/coherence/cluster", "/management/coherence"}

// tryCoherenceManagementGET issues ONE Management-over-REST GET on path over the
// given client and returns the parsed result. It fires on JSON that carries a
// version field AND a Coherence marker (clusterName, licenseMode, or a
// links[].href containing management/coherence), parsing version, clusterName and
// licenseMode; the body is drained-and-closed before returning so the connection
// is left clean. FN-safe: any transport/JSON error, non-2xx status, or missing
// marker yields (…, false). Shared by detectCoherenceManagement (single client,
// used by the direct unit tests) and probeCoherenceManagementPath (production,
// fresh conn per path) so the test and production GET/parse logic never diverge.
func tryCoherenceManagementGET(client *http.Client, baseURL, host, path string) (coherenceHTTPResult, bool) {
	resp, err := doGet(client, baseURL+path, host)
	if err != nil {
		return coherenceHTTPResult{}, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodySize))
	success := isSuccessStatus(resp.StatusCode)
	drainAndClose(resp)
	if !success {
		return coherenceHTTPResult{}, false
	}
	return parseCoherenceManagement(body)
}

// detectCoherenceManagement probes Management-over-REST over a SINGLE client/
// connection, trying the canonical /management/coherence/cluster path first, then
// the /management/coherence fallback. Production does NOT use this single-conn form
// (a non-2xx `Connection: close` on the cluster path would kill the shared conn
// before the fallback GET — see detectCoherenceManagementFresh, which re-dials a
// fresh connection per path); it is retained for the direct unit tests that inject
// a pre-built client. FN-safe: any transport/JSON error or missing marker yields
// (…, false).
func detectCoherenceManagement(client *http.Client, baseURL, host string) (coherenceHTTPResult, bool) {
	for _, path := range coherenceMgmtPaths {
		if res, ok := tryCoherenceManagementGET(client, baseURL, host, path); ok {
			return res, true
		}
	}
	return coherenceHTTPResult{}, false
}

// parseCoherenceManagement decodes the management JSON and applies the marker
// rule: a version field must be present AND at least one Coherence marker
// (clusterName, licenseMode, or a links[].href containing management/coherence).
// A bare JSON document with a version but no Coherence marker is deliberately not
// classified.
func parseCoherenceManagement(body []byte) (coherenceHTTPResult, bool) {
	var m coherenceMgmtResponse
	if err := json.Unmarshal(body, &m); err != nil {
		return coherenceHTTPResult{}, false
	}
	if m.Version == "" {
		return coherenceHTTPResult{}, false
	}
	marker := m.ClusterName != "" || m.LicenseMode != ""
	if !marker {
		for _, l := range m.Links {
			if strings.Contains(l.Href, "management/coherence") {
				marker = true
				break
			}
		}
	}
	if !marker {
		return coherenceHTTPResult{}, false
	}
	return coherenceHTTPResult{
		version:     m.Version,
		clusterName: m.ClusterName,
		licenseMode: m.LicenseMode,
	}, true
}

// detectCoherenceHTTP runs the two HTTP vectors in the fixed metrics-before-
// management order, returning the parsed metadata and whether Coherence was
// positively identified.
//
// The metrics vector runs over the framework-injected conn (it exposes the
// version in a single GET). The management vector does NOT reuse that conn: on a
// Coherence management node (Helidon) the /metrics probe returns 404 and the
// server closes the TCP connection immediately after that response, so a
// follow-up management GET reusing the same conn would land on a dead connection
// and read an empty reply. The management probe therefore self-dials a fresh
// connection to the target PER path (mirroring the weblogic console corroborator),
// keeping each attempt independent of whatever state the metrics probe left the
// injected conn in and of an earlier management path that answered `Connection:
// close` (see detectCoherenceManagementFresh).
func detectCoherenceHTTP(conn net.Conn, timeout time.Duration, target plugins.Target, useTLS bool) (coherenceHTTPResult, bool) {
	metricsClient := createCoherenceHTTPClient(conn, timeout)
	baseURL := "http://" + conn.RemoteAddr().String()
	if res, ok := detectCoherenceMetrics(metricsClient, baseURL, target.Host); ok {
		return res, true
	}
	return detectCoherenceManagementFresh(target, timeout, useTLS)
}

// detectCoherenceManagementFresh runs the Management-over-REST vector on short-lived
// connections self-dialed to the target, re-dialing a FRESH connection PER path
// (canonical /management/coherence/cluster first, then the /management/coherence
// fallback). A single shared connection is not safe here: besides a preceding
// /metrics probe that closed the framework conn, a Coherence management node
// (Helidon) answers a non-2xx on the cluster path with `Connection: close`, so a
// fallback GET reusing that same conn would land on a dead connection and never
// reach the server. Dialing fresh per path (and draining/closing between attempts)
// keeps each attempt independent. It returns on the first positive path. It is a
// no-op (…, false) when the target has no concrete routable address (e.g. an
// unspecified 0.0.0.0 from a proxied or unresolved scan), matching the weblogic
// self-dial gate rather than misdialing. FN-safe: any dial/transport/JSON error or
// missing marker yields (…, false).
func detectCoherenceManagementFresh(target plugins.Target, timeout time.Duration, useTLS bool) (coherenceHTTPResult, bool) {
	if !canSelfDialCoherence(target) {
		return coherenceHTTPResult{}, false
	}
	for _, path := range coherenceMgmtPaths {
		if res, ok := probeCoherenceManagementPath(target, timeout, useTLS, path); ok {
			return res, true
		}
	}
	return coherenceHTTPResult{}, false
}

// probeCoherenceManagementPath self-dials ONE fresh short-lived connection and
// issues a single Management-over-REST GET on path, closing that connection before
// returning (its deferred Close runs before the next path is dialed). Each path
// getting its own connection is what makes the cluster-path `Connection: close`
// (Helidon) unable to poison the fallback attempt. TLS vs plaintext follows useTLS
// via dialCoherenceConn. FN-safe: any dial/transport/JSON error, non-2xx status, or
// missing marker yields (…, false).
func probeCoherenceManagementPath(target plugins.Target, timeout time.Duration, useTLS bool, path string) (coherenceHTTPResult, bool) {
	conn, err := dialCoherenceConn(target, timeout, useTLS)
	if err != nil {
		return coherenceHTTPResult{}, false
	}
	defer func() { _ = conn.Close() }()
	client := createCoherenceHTTPClient(conn, timeout)
	baseURL := "http://" + conn.RemoteAddr().String()
	return tryCoherenceManagementGET(client, baseURL, target.Host, path)
}

// canSelfDialCoherence reports whether the target has a concrete, routable address
// for the management self-dial. When the address is unspecified we skip the
// management vector rather than misdial a wrong local address or leak scan traffic
// (mirrors weblogic's canSelfDialConsole).
func canSelfDialCoherence(target plugins.Target) bool {
	a := target.Address.Addr()
	return a.IsValid() && !a.IsUnspecified()
}

// dialCoherenceConn opens a fresh short-lived connection to the target for the
// management probe. The TLS variant mirrors the scanner's read-only cert posture
// (skip-verify) since the certificate is only used for fingerprinting (mirrors
// weblogic's dialConsoleConn).
func dialCoherenceConn(target plugins.Target, timeout time.Duration, useTLS bool) (net.Conn, error) {
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

// buildCoherenceHTTPService assembles the Service for a positive HTTP detection,
// shared by the plaintext and TLS variants. tls selects the transport and, under
// target.Misconfigs, an exposed-surface finding (plus TLS findings for the TLS
// variant) is attached with AnonymousAccess, mirroring the sibling Oracle HTTP
// plugins.
func buildCoherenceHTTPService(conn net.Conn, target plugins.Target, res coherenceHTTPResult, useTLS bool) *plugins.Service {
	payload := plugins.ServiceOracleCoherence{
		ViaHTTP:     true,
		ClusterName: res.clusterName,
		LicenseMode: res.licenseMode,
		CPEs:        []string{buildCoherenceCPE(res.version)},
	}
	transport := plugins.TCP
	if useTLS {
		transport = plugins.TCPTLS
	}
	service := plugins.CreateServiceFrom(target, payload, useTLS, res.version, transport)
	if target.Misconfigs {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, coherenceExposedFinding())
		if useTLS {
			service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
		}
	}
	return service
}

func (p *CoherenceHTTPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	res, detected := detectCoherenceHTTP(conn, timeout, target, false)
	if !detected {
		return nil, nil
	}
	return buildCoherenceHTTPService(conn, target, res, false), nil
}

func (p *CoherenceHTTPPlugin) PortPriority(port uint16) bool {
	return port == coherenceMetricsPort || port == coherenceMgmtPort
}
func (p *CoherenceHTTPPlugin) Name() string           { return oracleCoherenceHTTPName }
func (p *CoherenceHTTPPlugin) Type() plugins.Protocol { return plugins.TCP }

// Priority -1 (matches the sibling Oracle HTTP plugins) so it can pre-empt the
// generic HTTP fingerprinter on shared metrics/management ports and only claims
// on an unambiguous Coherence marker.
func (p *CoherenceHTTPPlugin) Priority() int { return -1 }

func (p *CoherenceHTTPTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	res, detected := detectCoherenceHTTP(conn, timeout, target, true)
	if !detected {
		return nil, nil
	}
	return buildCoherenceHTTPService(conn, target, res, true), nil
}

func (p *CoherenceHTTPTLSPlugin) PortPriority(port uint16) bool {
	return port == coherenceMetricsPort || port == coherenceMgmtPort
}
func (p *CoherenceHTTPTLSPlugin) Name() string           { return oracleCoherenceHTTPName }
func (p *CoherenceHTTPTLSPlugin) Type() plugins.Protocol { return plugins.TCPTLS }
func (p *CoherenceHTTPTLSPlugin) Priority() int          { return -1 }

// ---------------------------------------------------------------------------
// Coherence — port 7574 — LOW-CONFIDENCE, best-effort binary heuristic (FALLBACK)
// ---------------------------------------------------------------------------
//
// This is NOT the reliable Coherence vector, and it is DISABLED BY DEFAULT (see
// coherenceHeuristicEnabled). Live validation showed a real Coherence CE 22.06.10
// node is SILENT on 7574 (the TCMP cluster/NameService port) to naive probes and
// closes the connection, so this heuristic cannot detect a live CE node, and it is
// false-positive-prone against unrelated short length-prefixed binary services on
// 7574. The HTTP metrics (/metrics) and management (/management/coherence/cluster)
// detectors above are the dependable, supported path; this heuristic is retained
// only as an explicit opt-in for deployments that might answer the POF probe, and
// is biased hard to false-negative. It runs only on port 7574 (see
// CoherencePlugin.Run) — disjoint from the HTTP detectors' 9612/30000 — so it can
// never override a positive HTTP detection.

// coherenceHeuristicEnabled gates the ENTIRE 7574 byte heuristic and is DISABLED
// BY DEFAULT. Live validation against a real Oracle Coherence CE 22.06.10 node
// proved the 7574 cluster/NameService port is SILENT to the 0x00->POF probe (the
// heuristic detects nothing real there), while it can false-positive on any short
// length-prefixed binary service that happens to listen on 7574. The reliable,
// supported detection paths are the HTTP metrics (/metrics) and management
// (/management/coherence/cluster) vectors above; this heuristic is retained only
// as an explicit opt-in. It is a package var (not a plain func) so it stays a
// single one-line toggle: an embedder can set it to `func() bool { return true }`
// to re-enable the best-effort 7574 heuristic with zero other changes — and, being
// a var, a test can also flip it. It does NOT affect the HTTP detectors.
var coherenceHeuristicEnabled = func() bool { return false }

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

// couldBeCoherencePOFPrefix reports whether resp is a non-empty prefix still
// consistent with an as-yet-incomplete POF frame — i.e. isLikelyCoherencePOF
// fails ONLY because more bytes are needed, not because resp positively
// contradicts the POF shape. TCP may split the small NameService handshake frame
// across segments, so a single Recv can return the frame's leading bytes; this
// predicate decides whether accumulating one more bounded read is worthwhile. It
// never widens acceptance (isLikelyCoherencePOF still makes the final call), so
// detection stays FN-safe: a mis-read only under-detects.
func couldBeCoherencePOFPrefix(resp []byte) bool {
	if len(resp) == 0 {
		return false
	}
	// Already longer than a plausible handshake frame -> not a partial frame.
	if len(resp) > coherenceMaxFrame {
		return false
	}
	// Shapes that positively contradict Coherence can never become a POF frame by
	// reading more bytes.
	if looksLikeTLS(resp) || looksLikeSSH(resp) || looksLikeHTTP(resp) || looksLikeJRMP(resp) {
		return false
	}
	if bytes.Contains(resp, []byte("Coherence")) {
		return false
	}
	if isMostlyPrintable(resp) {
		return false
	}
	declaredLength, consumed, ok := decodePackedInt(resp)
	if !ok {
		// The POF packed-int length prefix itself is not yet fully present (split
		// mid-integer) -> more bytes may complete it. A genuinely malformed/overflowing
		// prefix simply never satisfies isLikelyCoherencePOF, and the read cap bounds
		// the wasted reads.
		return true
	}
	if declaredLength <= 0 || declaredLength > int64(coherenceMaxFrame) {
		return false // out-of-range length contradicts the shape
	}
	// Still short of the framed length -> a later TCP segment may complete it. An
	// exact match is already positive (isLikelyCoherencePOF true, so we are not here),
	// and an overshoot is a contradiction, so only a strict shortfall keeps reading.
	return int64(len(resp)) < int64(consumed)+declaredLength
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

	resp, _ := utils.SendRecv(conn, coherenceProbe, timeout)
	// On a partial-read error, SendRecv still returns the bytes received before the
	// error; a valid POF handshake frame may already be present when the server
	// responds and then closes (Recv surfaces io.EOF alongside those bytes). Evaluate
	// whatever we got regardless of the error and bail only on an empty buffer, so a
	// server that answers then closes is not discarded (mirrors the TimesTen/NoSQL
	// partial-read handling). The port gate and coherenceHeuristicEnabled kill switch
	// above still apply first.
	if len(resp) == 0 {
		return nil, nil // silence / error with no bytes -> not us
	}
	// TCP may split the POF handshake frame so its length prefix and body land in
	// separate segments. While the bytes so far stay consistent with an incomplete
	// POF frame (couldBeCoherencePOFPrefix), accumulate a small, bounded number of
	// extra reads under ONE absolute deadline (mirrors the TimesTen/NoSQL loops) so a
	// drip-feeding peer cannot reset the timeout per read. FN-safe: a mis-read only
	// under-detects. The port gate and coherenceHeuristicEnabled kill switch above
	// still apply first.
	if !isLikelyCoherencePOF(resp) && couldBeCoherencePOFPrefix(resp) {
		deadline := time.Now().Add(timeout)
		for reads := 0; reads < 2 &&
			!isLikelyCoherencePOF(resp) &&
			couldBeCoherencePOFPrefix(resp); reads++ {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			chunk, rerr := utils.Recv(conn, remaining)
			resp = append(resp, chunk...)
			if rerr != nil || len(chunk) == 0 {
				break // partial-read error (bytes already appended) or silence/EOF -> stop
			}
		}
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

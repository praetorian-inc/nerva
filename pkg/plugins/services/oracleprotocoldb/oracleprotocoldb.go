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
  - Every read goes through pluginutils.SendRecv/Recv (fixed 4 KB buffer per Read,
    deadline; []byte{} on timeout/refused -> treated as silence). Some paths do a
    small BOUNDED read-accumulation to tolerate TCP segmentation (a valid ack or
    reject can be split across segments): the NoSQL round-1 JRMP handshake reads at
    most 3 times and the TimesTen probe at most 2 times, each only while the bytes so
    far stay consistent with the target shape; the NoSQL round-2 registry list() loop
    reads until the marker appears or the buffer is exhausted. Coherence and NoSQL-HTTP
    still read once.
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

	// nosqlRMIPort is the Oracle NoSQL RMI registry default port. FP-safe gate:
	// the loose <store>:<resourceId>:<InterfaceType> binding triad is only trusted
	// here (see NoSQLPlugin.Run / oracleNoSQLListingMatches); the reliable oracle.kv
	// class token counts on any port. Mirrors CoherencePlugin's coherencePort gate.
	nosqlRMIPort = 5000

	// nosqlHTTPPort is the Oracle NoSQL Database Proxy default port. FP-safe gate:
	// NoSQLHTTPPlugin detection is confined to this port (see NoSQLHTTPPlugin.Run) so
	// an unrelated /V2/health beacon — or any other endpoint — reached in a full sweep
	// is never mislabeled oracle_nosql. Mirrors CoherencePlugin's coherencePort gate.
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
	// nosqlBindingRe matches an Oracle NoSQL registry binding NAME. Registry.list()
	// returns binding NAMES (not bound-object classes), so the oracle.kv class token
	// (nosqlClassRe) usually does not appear and cannot be relied on alone. Real
	// Oracle NoSQL binding names have the shape <store>:<resourceId>:<InterfaceType>,
	// where the final colon-segment is the Java InterfaceType enum rendered in
	// UPPERCASE by RegistryUtils.bindingName (e.g. myStore:rg1-rn1:ADMIN, :MAIN,
	// :MONITOR, :LOGIN, :TRUSTED_LOGIN).
	//
	// FP-safe (a): the final segment is an ANCHORED ALLOWLIST of the DOCUMENTED
	// Oracle NoSQL InterfaceType enum members ONLY — not any [A-Z][A-Z_]{2,} token.
	// The prior loose form matched ANY word:word:UPPERCASE binding, so a generic
	// non-NoSQL RMI registry with a novel uppercase role (e.g. x:y:FOO, svc:n:CACHE)
	// was misclassified as oracle_nosql — and because NoSQLPlugin runs at priority 400
	// (ahead of javarmi 500) it silently preempted the correct generic-RMI result.
	//
	// FP-safe (b): a generic RMI registry can still legitimately expose a binding
	// whose final segment collides with a real enum member (e.g. service:node:ADMIN),
	// which no regex can distinguish from a true NoSQL binding. So this loose triad is
	// ADDITIONALLY port-gated to nosqlRMIPort by the caller (see NoSQLPlugin.Run via
	// oracleNoSQLListingMatches); nosqlClassRe (oracle.kv) stays the reliable
	// cross-port marker and is NOT port-gated. The leading/trailing \b anchor the
	// word:word:ENUM triad on word boundaries; \b after the alternation keeps the enum
	// a complete token (so MAINTENANCE / ADMINX do not match). Detection stays
	// marker-gated and FN-safe.
	nosqlBindingRe = regexp.MustCompile(
		`\b[\w.-]{1,63}:[\w.-]{1,63}:(?:ADMIN|MAIN|MONITOR|LOGIN|TRUSTED_LOGIN)\b`)

	// nosqlClassRe matches an oracle.kv / oracle.kv.impl class token that leaks
	// into a serialized list() reply. Quantifier bounded per P1-3.
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
// pre-merge confirmation for this vector. The response-side markers (nosqlBindingRe's
// <store>:<resourceId>:<UPPERCASE-InterfaceType> binding triad and the /V2/health
// beacon JSON accepted by isOracleNoSQLProxy) are likewise Oracle-doc-derived and
// still merit the same live-capture confirmation. Pending that capture they are held
// FP-safe: the binding triad's final segment is now allowlisted to the documented
// InterfaceType enum members and is port-gated to nosqlRMIPort, and the /V2/health
// beacon branch is gated to nosqlHTTPPort + HTTP 200 (see nosqlBindingRe and
// isOracleNoSQLProxy).
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
// It is specific enough to trust on ANY port (see oracleNoSQLListingMatches).
func hasNoSQLClassToken(reply []byte) bool {
	return len(reply) > 0 && nosqlClassRe.Match(reply)
}

// hasNoSQLBindingTriad reports the looser <store>:<resourceId>:<InterfaceType>
// binding-name triad. It is FP-prone off the NoSQL RMI port (a generic RMI registry
// can expose a colliding enum-shaped role such as service:node:ADMIN), so callers
// port-gate it — see oracleNoSQLListingMatches / NoSQLPlugin.Run. The triad alone is
// NOT sufficient to classify: oracleNoSQLListingMatches additionally requires an
// `oracle` family token (hasOracleFamilyToken) in the same reply, so a generic RMI
// registry with a colon-triad binding never classifies on any port.
func hasNoSQLBindingTriad(reply []byte) bool {
	return len(reply) > 0 && nosqlBindingRe.Match(reply)
}

// hasOracleFamilyToken reports a case-insensitive `oracle` token anywhere in the raw
// (never deserialized) reply. It is the additional Oracle-family marker the binding
// triad path requires so a generic RMI registry — whose bindings can share the
// word:word:ENUM shape (e.g. service:node:ADMIN) — is never misclassified as
// oracle_nosql on any port. The reliable oracle.kv class token (hasNoSQLClassToken)
// still classifies alone; it contains "oracle" anyway.
func hasOracleFamilyToken(reply []byte) bool {
	return bytes.Contains(bytes.ToLower(reply), []byte("oracle"))
}

// isOracleNoSQLListing reports whether a raw (never deserialized) RMI registry
// list() reply carries ANY Oracle-NoSQL-specific marker: an oracle.kv class token
// or a <store>:<base>:<iface> binding triad. A bare JRMP ack, an empty listing,
// or only generic names (jmxrmi, org.jnp.*, JBoss/HornetQ) return false so the
// generic javarmi plugin reports it instead. This is the PORT-AGNOSTIC marker
// union; production detection is FP-safe / port-gated via oracleNoSQLListingMatches.
func isOracleNoSQLListing(reply []byte) bool {
	return hasNoSQLClassToken(reply) || hasNoSQLBindingTriad(reply)
}

// oracleNoSQLListingMatches is the FP-safe classifier used by NoSQLPlugin.Run. The
// oracle.kv class token is specific and reliable, so it classifies on ANY port; the
// looser binding triad only classifies when bindingAllowed (the connected port is
// nosqlRMIPort) AND an `oracle` family token is present in the same reply
// (hasOracleFamilyToken). Requiring the extra oracle marker on the triad path is the
// permanent fix for the recurring generic-RMI false positive (e.g. service:node:ADMIN
// on 5000): the colon-triad shape alone — even port-gated — is no longer enough, so a
// generic non-NoSQL RMI registry can never be misclassified as oracle_nosql or (at
// priority 400) preempt the generic javarmi plugin (priority 500). Kept separate from
// isOracleNoSQLListing so the pure marker union stays directly unit-testable.
func oracleNoSQLListingMatches(reply []byte, bindingAllowed bool) bool {
	if hasNoSQLClassToken(reply) {
		return true
	}
	return bindingAllowed && hasNoSQLBindingTriad(reply) && hasOracleFamilyToken(reply)
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

	// FP-safe: the reliable oracle.kv class token classifies on any port, but the
	// looser binding triad is only trusted on the NoSQL RMI default port so a generic
	// RMI registry on another port (whose bindings can share the word:word:ENUM shape)
	// cannot be misclassified as oracle_nosql. Mirrors CoherencePlugin's port gate.
	bindingAllowed := target.Address.Port() == nosqlRMIPort

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
		if oracleNoSQLListingMatches(listResp, bindingAllowed) {
			break // NoSQL marker present in the accumulated buffer -> done
		}
		if err != nil || len(chunk) == 0 {
			break // partial-read error (bytes already scanned) or silence/EOF -> stop
		}
	}
	if !oracleNoSQLListingMatches(listResp, bindingAllowed) {
		// No listing / generic RMI / mis-framed / blocked / silence -> not us. An empty
		// buffer also lands here (isOracleNoSQLListing returns false), so the ambiguous
		// "error with no bytes" case is covered too. Let javarmi report generic RMI.
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
// NoSQL Database Proxy. It requires a NoSQL-proxy-specific token (never a bare
// 200) and explicitly rejects the ORDS/APEX surface, which is a different product.
// As a second positive signal, a /V2/health response carrying the documented JSON
// health beacon (a "beacon" key together with a GREEN/RED/YELLOW status) also
// corroborates the proxy — HTTP 200 alone is never sufficient.
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
	// Positive /V2/health beacon signal (Codex P2): Oracle documents the NoSQL proxy
	// answering GET /V2/health with a JSON health beacon such as
	// {"beacon":"GREEN","info":"ALL OK"} — none of the product-name markers above
	// appear in that body, so a healthy stock proxy on 8080 would otherwise be missed.
	// FP-safe: this branch classifies ONLY when ALL of (a) the connected port is
	// nosqlHTTPPort — enforced by NoSQLHTTPPlugin.Run before this runs, so a full-sweep
	// hit on some other port's /V2/health is never reached; (b) the HTTP status is 200;
	// and (c) the /V2/health path body carries BOTH the "beacon" key AND a
	// GREEN/RED/YELLOW status, so this is unmistakably the proxy health shape — never a
	// bare 200, and never a stray "beacon" mention on its own. The path is read from the
	// populated client Request (nil when a bare *http.Response is constructed, e.g. in
	// unit tests). HTTP status is used only as an additional guard, never keyed on alone.
	if resp.StatusCode == http.StatusOK &&
		resp.Request != nil && resp.Request.URL != nil &&
		resp.Request.URL.Path == "/V2/health" &&
		strings.Contains(lb, "beacon") &&
		(strings.Contains(lb, "green") || strings.Contains(lb, "red") || strings.Contains(lb, "yellow")) {
		return true
	}
	return false
}

func (p *NoSQLHTTPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Port gate: confine the ENTIRE NoSQL HTTP probe to the proxy default port. In
	// full-sweep scans the engine runs every plugin on every open port (PortPriority
	// only governs fast-mode ordering), so without this gate the /V2/health beacon
	// branch — and even the product-name marker path — could fire against an unrelated
	// HTTP service on some other port and mislabel it oracle_nosql. Mirrors
	// CoherencePlugin's coherencePort confinement.
	if target.Address.Port() != nosqlHTTPPort {
		return nil, nil
	}

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

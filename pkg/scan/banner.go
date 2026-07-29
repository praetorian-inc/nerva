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

// Package scan: banner.go implements a lightweight, best-effort banner
// pre-read and protocol-family classifier used to narrow the plugin search
// space before running the full plugin list against a connection.
//
// This module intentionally does NOT modify SimpleScanTarget or any other
// scan entry point (see LAB-5301 for wiring this into the scan pipeline).
// It only provides the primitives: ReadBanner, ClassifyBanner, and
// FilterPluginsByFamily.
package scan

import (
	"bytes"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

// ProtocolFamily is a coarse classification of a connection's protocol,
// derived from a short, unauthenticated read of the bytes a service sends
// immediately after a TCP connection is established. It is used to narrow
// the set of plugins attempted against a given port.
type ProtocolFamily int

const (
	// ProtocolFamilyUnknown means the banner did not match any known family,
	// or no banner was read at all (e.g. the service waits for client input).
	// Callers MUST treat Unknown as "no narrowing" and try all plugins.
	ProtocolFamilyUnknown ProtocolFamily = iota
	ProtocolFamilySSH
	ProtocolFamilyHTTP
	ProtocolFamilyMySQL
	ProtocolFamilyTLS
	ProtocolFamilySMTP
	ProtocolFamilyFTP
	ProtocolFamilyTelnet
)

// String returns a human-readable name for the protocol family, useful for
// logging and debugging.
func (f ProtocolFamily) String() string {
	switch f {
	case ProtocolFamilySSH:
		return "SSH"
	case ProtocolFamilyHTTP:
		return "HTTP"
	case ProtocolFamilyMySQL:
		return "MySQL"
	case ProtocolFamilyTLS:
		return "TLS"
	case ProtocolFamilySMTP:
		return "SMTP"
	case ProtocolFamilyFTP:
		return "FTP"
	case ProtocolFamilyTelnet:
		return "Telnet"
	default:
		return "Unknown"
	}
}

// DefaultBannerReadTimeout bounds how long ReadBanner waits for a service to
// send its initial bytes. It is intentionally short: services that speak
// first (SSH, FTP, SMTP, MySQL) typically respond in milliseconds, and
// services that wait for client input (HTTP, TLS) are expected to time out.
const DefaultBannerReadTimeout = 300 * time.Millisecond

// ReadBanner performs a single best-effort read of whatever bytes a service
// sends immediately after connecting, without writing anything to the
// connection. It is intended purely for protocol-family classification via
// ClassifyBanner, and must never be relied upon to capture a complete
// protocol banner.
//
// Behavior:
//   - Services that send a banner immediately (SSH, FTP, SMTP, MySQL)
//     return their initial bytes.
//   - Services that wait for client input (HTTP, TLS) will hit the read
//     deadline and return an empty slice and nil error.
//   - Partial reads and connection resets return whatever bytes were read
//     before the error, alongside the error, so callers can still attempt
//     classification on partial data if desired.
//
// timeout <= 0 uses DefaultBannerReadTimeout.
func ReadBanner(conn net.Conn, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = DefaultBannerReadTimeout
	}
	return utils.Recv(conn, timeout)
}

// maxMySQLVersionScan bounds how far past the protocol version byte
// ClassifyBanner will scan looking for the null terminator of the server
// version string in a MySQL initial handshake packet. This keeps
// classification of malformed/garbage input bounded and cheap.
const maxMySQLVersionScan = 32

// ClassifyBanner inspects raw bytes read from a connection (see ReadBanner)
// and returns the ProtocolFamily they most likely belong to. Classification
// is conservative: when the evidence is ambiguous or insufficient, it
// returns ProtocolFamilyUnknown rather than guessing, so callers never
// narrow the plugin search space incorrectly.
func ClassifyBanner(banner []byte) ProtocolFamily {
	if len(banner) == 0 {
		return ProtocolFamilyUnknown
	}

	if isSSHBanner(banner) {
		return ProtocolFamilySSH
	}
	if isTLSHandshake(banner) {
		return ProtocolFamilyTLS
	}
	if isTelnetIAC(banner) {
		return ProtocolFamilyTelnet
	}
	if isMySQLGreeting(banner) {
		return ProtocolFamilyMySQL
	}
	if bytes.HasPrefix(banner, []byte("220")) {
		text := string(banner)
		if ftpKeywordPattern.MatchString(text) {
			return ProtocolFamilyFTP
		}
		if smtpKeywordPattern.MatchString(text) {
			return ProtocolFamilySMTP
		}
		return ProtocolFamilyUnknown
	}
	if bytes.HasPrefix(banner, []byte("HTTP/")) {
		return ProtocolFamilyHTTP
	}

	return ProtocolFamilyUnknown
}

// isSSHBanner reports whether banner begins with the SSH identification
// prefix "SSH-" (0x53 0x53 0x48 0x2d), per RFC 4253 Section 4.2.
func isSSHBanner(banner []byte) bool {
	return bytes.HasPrefix(banner, []byte("SSH-"))
}

// isTLSHandshake reports whether banner begins with a TLS record header for
// a handshake message (content type 0x16) using a TLS/SSL 3.x version
// (major version byte 0x03).
func isTLSHandshake(banner []byte) bool {
	if len(banner) < 2 {
		return false
	}
	return banner[0] == 0x16 && banner[1] == 0x03
}

// telnetCommandBytes are the RFC 854 command bytes that may legitimately
// follow an IAC (0xff) byte at the start of a Telnet negotiation.
var telnetCommandBytes = map[byte]bool{
	251: true, // WILL
	252: true, // WONT
	253: true, // DO
	254: true, // DONT
}

// isTelnetIAC reports whether banner begins with a Telnet IAC (0xff) byte
// followed by a recognized negotiation command byte.
func isTelnetIAC(banner []byte) bool {
	if len(banner) < 2 {
		return false
	}
	if banner[0] != 0xff {
		return false
	}
	return telnetCommandBytes[banner[1]]
}

// isMySQLGreeting reports whether banner looks like the start of a MySQL
// initial handshake packet: a protocol version byte of 0x0a at offset 4,
// followed by a non-empty, printable-ASCII, null-terminated server version
// string starting at offset 5. It does not validate the 3-byte little-endian
// payload length or the 1-byte sequence id that precede the version byte in
// a real handshake packet.
//
// The real MySQL handshake parser (pkg/plugins/services/mysql) requires at
// least 35 bytes for a full handshake packet, but a short banner pre-read
// may not contain that much data. minMySQLGreetingLen is a lower bound
// chosen to be long enough to hold a plausible version string (e.g.
// "5.7.0\x00") while still rejecting most short garbage reads that happen
// to have 0x0a at offset 4.
func isMySQLGreeting(banner []byte) bool {
	const (
		versionByteOffset   = 4
		versionStart        = 5
		minMySQLGreetingLen = 10
	)
	if len(banner) < minMySQLGreetingLen {
		return false
	}
	if banner[versionByteOffset] != 0x0a {
		return false
	}

	limit := len(banner)
	if limit > versionStart+maxMySQLVersionScan {
		limit = versionStart + maxMySQLVersionScan
	}

	for i := versionStart; i < limit; i++ {
		if banner[i] == 0x00 {
			// Reject an empty version string; real servers always report one.
			return i > versionStart
		}
		if banner[i] < 0x20 || banner[i] > 0x7e {
			// Non-printable byte where a version string is expected.
			return false
		}
	}
	// No null terminator found within the scan window.
	return false
}

// ftpKeywordPattern matches banner text that identifies an FTP server,
// mirroring the whitelist approach used by the FTP plugin
// (pkg/plugins/services/ftp) to avoid misclassifying SMTP "220" banners.
var ftpKeywordPattern = regexp.MustCompile(`(?i)(ftpd?|ftp\s+(server|service)|filezilla|proftpd|vsftpd)`)

// smtpKeywordPattern matches banner text that identifies an SMTP server.
var smtpKeywordPattern = regexp.MustCompile(`(?i)(esmtp|smtp|mail\s+(server|service|transfer)|postfix|sendmail|exim)`)

// FilterPluginsByFamily narrows candidates (e.g. the sorted TCP or TCPTLS
// plugin list) down to the plugins relevant to family, matching against each
// plugin's Name() case-insensitively.
//
// ProtocolFamilyUnknown and ProtocolFamilyTLS are safe fallbacks that return
// candidates unmodified: Unknown because there is no reliable signal to
// narrow on, and TLS because TLS-wrapped services still need their
// protocol-specific plugin to run inside the TLS session.
//
// If a recognized family has no matching plugins in candidates (which would
// indicate a bug in the name mapping below, not a real scan condition), the
// full candidate list is returned rather than an empty one, so a
// classification mismatch can never cause a port to go unscanned.
func FilterPluginsByFamily(candidates []plugins.Plugin, family ProtocolFamily) []plugins.Plugin {
	if family == ProtocolFamilyUnknown || family == ProtocolFamilyTLS {
		return candidates
	}

	names, ok := protocolFamilyPluginNames[family]
	if !ok {
		return candidates
	}

	filtered := make([]plugins.Plugin, 0, len(candidates))
	for _, p := range candidates {
		if names[strings.ToLower(p.Name())] {
			filtered = append(filtered, p)
		}
	}

	if len(filtered) == 0 {
		return candidates
	}
	return filtered
}

// protocolFamilyPluginNames maps each narrowable ProtocolFamily to the set
// of plugin Name() values (lowercased) relevant to it. ProtocolFamilyUnknown
// and ProtocolFamilyTLS are handled directly in FilterPluginsByFamily and do
// not need entries here.
var protocolFamilyPluginNames = map[ProtocolFamily]map[string]bool{
	ProtocolFamilySSH:    {"ssh": true},
	ProtocolFamilyHTTP:   {"http": true, "https": true},
	ProtocolFamilyMySQL:  {"mysql": true},
	ProtocolFamilySMTP:   {"smtp": true, "smtps": true},
	ProtocolFamilyFTP:    {"ftp": true},
	ProtocolFamilyTelnet: {"telnet": true},
}

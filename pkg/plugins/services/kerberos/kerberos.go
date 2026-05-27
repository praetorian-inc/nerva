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
Package kerberos implements a Kerberos v5 service detection plugin for Nerva.

Detection Strategy:

The plugin uses a two-phase approach to detect Kerberos services:

Phase 1 - Service Detection (detectKerberos):
  - Sends a minimal AS-REQ (Authentication Service Request) for realm "NM" and principal "NM"
  - This is the same probe used by Nmap's kerberos-sec scanner
  - For TCP, the AS-REQ is prefixed with a 4-byte big-endian length (113 = 0x71)
  - Validates the response by checking:
    1. Response length (minimum 10 bytes: 4-byte TCP length + 6 bytes Kerberos data)
    2. Kerberos message type (0x7E for KRB-ERROR or 0x6B for AS-REP)
    3. Protocol version (pvno=5 pattern: \xa0\x03\x02\x01\x05)

Phase 2 - Metadata Extraction (parseKerberosError):
  - Parses the KRB-ERROR response for additional information
  - Extracts error-code field (context tag [6])
  - Extracts realm field (context tag [9])
  - Extracts optional e-text field (context tag [11])
  - All extractions are best-effort with defensive bounds checking

The AS-REQ probe structure (113 bytes DER-encoded):
  - Application tag 0x6A (AS-REQ)
  - Contains realm "NM" (0x4E 0x4D)
  - Contains principal "krbtgt/NM"
  - Timestamp: 1970-01-01 00:00:00Z (epoch)
  - Random nonce: 0x1f1eb9d9
  - Supported encryption types: 18, 17, 16, 23, 1, 3, 2

This probe is proven by Nmap and triggers consistent responses from Kerberos KDCs.
*/
package kerberos

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type KerberosPlugin struct{}

const KERBEROS = "kerberos"

const (
	tagKRBError       = 0x7E // APPLICATION 30, constructed
	tagASREP          = 0x6B // APPLICATION 11, constructed
	kdcErrEtypeNosupp = 14   // KDC_ERR_ETYPE_NOSUPP
)

const preauthPrincipal = "administrator"

// ambiguousErrorCodes lists KRB-ERROR codes where the KDC response does not
// reliably indicate whether the requested etype was evaluated. With the
// detected realm from phase 1, WRONG_REALM is the only remaining ambiguous
// case (it shouldn't occur but we handle it defensively). Other error codes
// like C_PRINCIPAL_UNKNOWN (6) indicate the KDC processed past etype
// validation — most implementations (MIT, Heimdal, AD 2012+) check etype
// before principal lookup.
var ambiguousErrorCodes = map[int]bool{
	68: true, // KDC_ERR_WRONG_REALM
}

// rc4OnlyProbe is a 92-byte AS-REQ that requests only etype 23 (RC4-HMAC).
// Used to probe whether a KDC accepts RC4-HMAC when other etypes are not offered.
// If the KDC responds without KDC_ERR_ETYPE_NOSUPP (error 14), RC4-HMAC is supported.
var rc4OnlyProbe = []byte{
	0x6a, 0x5a,                                           // APPLICATION 10, length 90
	0x30, 0x58,                                           // SEQUENCE, length 88
	0xa1, 0x03, 0x02, 0x01, 0x05,                         // pvno = 5
	0xa2, 0x03, 0x02, 0x01, 0x0a,                         // msg-type = 10 (AS-REQ)
	0xa4, 0x4c,                                           // context [4], length 76
	0x30, 0x4a,                                           // SEQUENCE, length 74
	0xa0, 0x07, 0x03, 0x05, 0x00, 0x50, 0x80, 0x00, 0x10, // kdc-options
	0xa2, 0x04, 0x1b, 0x02, 0x4e, 0x4d,                  // realm "NM"
	0xa3, 0x17, 0x30, 0x15,                               // sname
	0xa0, 0x03, 0x02, 0x01, 0x00,
	0xa1, 0x0e, 0x30, 0x0c,
	0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67, 0x74, // "krbtgt"
	0x1b, 0x02, 0x4e, 0x4d,                           // "NM"
	0xa5, 0x11, 0x18, 0x0f,                           // till (GeneralizedTime)
	0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31,
	0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
	0xa7, 0x06, 0x02, 0x04, 0x1f, 0x1e, 0xb9, 0xd9, // nonce
	0xa8, 0x05, 0x30, 0x03,                           // etype SEQUENCE, length 3
	0x02, 0x01, 0x17,                                 // INTEGER 23 (rc4-hmac)
}

// The raw AS-REQ bytes (113 bytes) - proven by Nmap
var asReqProbe = []byte{
	0x6a, 0x81, 0x6e, 0x30, 0x81, 0x6b, 0xa1, 0x03,
	0x02, 0x01, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x0a,
	0xa4, 0x81, 0x5e, 0x30, 0x5c, 0xa0, 0x07, 0x03,
	0x05, 0x00, 0x50, 0x80, 0x00, 0x10, 0xa2, 0x04,
	0x1b, 0x02, 0x4e, 0x4d, 0xa3, 0x17, 0x30, 0x15,
	0xa0, 0x03, 0x02, 0x01, 0x00, 0xa1, 0x0e, 0x30,
	0x0c, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67,
	0x74, 0x1b, 0x02, 0x4e, 0x4d, 0xa5, 0x11, 0x18,
	0x0f, 0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30,
	0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
	0xa7, 0x06, 0x02, 0x04, 0x1f, 0x1e, 0xb9, 0xd9,
	0xa8, 0x17, 0x30, 0x15, 0x02, 0x01, 0x12, 0x02,
	0x01, 0x11, 0x02, 0x01, 0x10, 0x02, 0x01, 0x17,
	0x02, 0x01, 0x01, 0x02, 0x01, 0x03, 0x02, 0x01,
	0x02,
}

// pvno=5 pattern to search for: context tag [1] + length 3 + INTEGER tag + length 1 + value 5
var pvnoPattern = []byte{0xa0, 0x03, 0x02, 0x01, 0x05}

func init() {
	plugins.RegisterPlugin(&KerberosPlugin{})
}

// detectKerberos sends an AS-REQ probe and validates the response
// Returns: (detected bool, response bytes, error)
func detectKerberos(conn net.Conn, timeout time.Duration) (bool, []byte, error) {
	// For TCP, prepend 4-byte big-endian length
	tcpProbe := make([]byte, 4+len(asReqProbe))
	binary.BigEndian.PutUint32(tcpProbe[0:4], uint32(len(asReqProbe))) // #nosec G115 -- asReqProbe is a fixed 113-byte literal; cannot overflow uint32
	copy(tcpProbe[4:], asReqProbe)

	response, err := utils.SendRecv(conn, tcpProbe, timeout)
	if err != nil {
		return false, nil, err
	}

	// Response must be at least 10 bytes (4-byte TCP length + 6 bytes Kerberos minimum)
	if len(response) < 10 {
		return false, response, nil
	}

	// Skip the 4-byte TCP length prefix
	kerberosData := response[4:]

	// Check the Kerberos message byte (should be KRB-ERROR or AS-REP)
	if len(kerberosData) < 1 {
		return false, response, nil
	}
	messageType := kerberosData[0]
	if messageType != tagKRBError && messageType != tagASREP {
		return false, response, nil
	}

	// Search for pvno=5 pattern in the response
	if !bytes.Contains(kerberosData, pvnoPattern) {
		return false, response, nil
	}

	return true, response, nil
}

// parseDERLength parses a DER length field and returns (length, bytesConsumed).
// Short form: single byte (0-127)
// Long form: first byte = 0x80 | N, followed by N bytes of length
func parseDERLength(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 0
	}
	if data[0] < 0x80 {
		return int(data[0]), 1
	}
	numBytes := int(data[0] & 0x7f)
	if numBytes == 0 || numBytes > 3 || len(data) < 1+numBytes {
		return 0, 0
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}
	return length, 1 + numBytes
}

// parseKerberosError extracts metadata from a KRB-ERROR response.
// Returns: (realm string, errorCode int, errorText string)
func parseKerberosError(response []byte) (string, int, string) {
	if len(response) < 4 {
		return "", 0, ""
	}

	// Skip TCP length prefix
	data := response[4:]
	if len(data) < 2 {
		return "", 0, ""
	}

	// Skip APPLICATION 30 wrapper (0x7E + length)
	if data[0] != tagKRBError {
		return "", 0, ""
	}
	_, consumed := parseDERLength(data[1:])
	if consumed == 0 {
		return "", 0, ""
	}
	data = data[1+consumed:]

	// Skip SEQUENCE wrapper (0x30 + length)
	if len(data) < 2 || data[0] != 0x30 {
		return "", 0, ""
	}
	_, consumed = parseDERLength(data[1:])
	if consumed == 0 {
		return "", 0, ""
	}
	data = data[1+consumed:]

	// Now walk the context-tagged fields inside the SEQUENCE
	var realm string
	var errorCode int
	var errorText string

	for len(data) > 2 {
		tag := data[0]
		fieldLen, consumed := parseDERLength(data[1:])
		if consumed == 0 || 1+consumed+fieldLen > len(data) {
			break
		}
		fieldData := data[1+consumed : 1+consumed+fieldLen]

		switch tag {
		case 0xa6: // context tag [6] - error-code
			// error-code wraps an INTEGER
			if len(fieldData) >= 3 && fieldData[0] == 0x02 {
				intLen := int(fieldData[1])
				if 2+intLen <= len(fieldData) {
					for j := 0; j < intLen; j++ {
						errorCode = (errorCode << 8) | int(fieldData[2+j])
					}
				}
			}
		case 0xa9: // context tag [9] - realm
			// realm wraps a GeneralString
			if len(fieldData) >= 3 && fieldData[0] == 0x1b {
				strLen := int(fieldData[1])
				if 2+strLen <= len(fieldData) {
					realm = string(fieldData[2 : 2+strLen])
				}
			}
		case 0xab: // context tag [11] - e-text
			// e-text wraps a GeneralString
			if len(fieldData) >= 3 && fieldData[0] == 0x1b {
				strLen := int(fieldData[1])
				if 2+strLen <= len(fieldData) {
					errorText = string(fieldData[2 : 2+strLen])
				}
			}
		}

		// Move to next field
		data = data[1+consumed+fieldLen:]
	}

	return realm, errorCode, errorText
}

// buildRC4Probe builds an AS-REQ with only etype 23 (RC4-HMAC) for the given realm.
// It falls back to the static rc4OnlyProbe when realm is empty or too long (>20 bytes),
// which avoids long-form DER encoding.
func buildRC4Probe(realm string) []byte {
	r := []byte(realm)
	// Cap realm length to keep all DER length fields in short form (< 128).
	// With 2×len(r) in the body, the outermost wrapper length is 86+2×len(r);
	// byte(86+2×20) = 126 is the last value that fits a single-byte DER length.
	if len(r) == 0 || len(r) > 20 {
		return rc4OnlyProbe // fall back to static probe
	}

	var body []byte
	// [0] kdc-options
	body = append(body, 0xa0, 0x07, 0x03, 0x05, 0x00, 0x50, 0x80, 0x00, 0x10)
	// [2] realm = GeneralString(realm)
	body = append(body, 0xa2, byte(2+len(r)), 0x1b, byte(len(r))) // #nosec G115 -- realm capped at 20 bytes
	body = append(body, r...)
	// [3] sname = PrincipalName { name-type=0, name-string=["krbtgt", realm] }
	krbtgt := []byte("krbtgt")
	nameStrSeqLen := 2 + len(krbtgt) + 2 + len(r)
	snameInnerLen := 5 + 2 + 2 + nameStrSeqLen // name-type(5) + a1 wrapper(2) + 30 wrapper(2) + contents
	body = append(body, 0xa3, byte(2+snameInnerLen), 0x30, byte(snameInnerLen)) // #nosec G115 -- realm capped at 20 bytes
	body = append(body, 0xa0, 0x03, 0x02, 0x01, 0x00) // name-type = 0
	body = append(body, 0xa1, byte(2+nameStrSeqLen), 0x30, byte(nameStrSeqLen)) // #nosec G115 -- realm capped at 20 bytes
	body = append(body, 0x1b, byte(len(krbtgt))) // #nosec G115 -- realm capped at 20 bytes
	body = append(body, krbtgt...)
	body = append(body, 0x1b, byte(len(r))) // #nosec G115 -- realm capped at 20 bytes
	body = append(body, r...)
	// [5] till = GeneralizedTime "19700101000000Z"
	body = append(body, 0xa5, 0x11, 0x18, 0x0f)
	body = append(body, []byte("19700101000000Z")...)
	// [7] nonce
	body = append(body, 0xa7, 0x06, 0x02, 0x04, 0x1f, 0x1e, 0xb9, 0xd9)
	// [8] etype = SEQUENCE { INTEGER 23 (rc4-hmac) }
	body = append(body, 0xa8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x17)

	// Wrap body in [4] SEQUENCE
	var reqBody []byte
	reqBody = append(reqBody, 0xa4, byte(2+len(body)), 0x30, byte(len(body))) // #nosec G115 -- realm capped at 20 bytes
	reqBody = append(reqBody, body...)

	// Outer SEQUENCE: pvno + msg-type + req-body
	var seq []byte
	seq = append(seq, 0xa1, 0x03, 0x02, 0x01, 0x05) // pvno = 5
	seq = append(seq, 0xa2, 0x03, 0x02, 0x01, 0x0a) // msg-type = 10 (AS-REQ)
	seq = append(seq, reqBody...)

	// Wrap in SEQUENCE
	var outer []byte
	outer = append(outer, 0x30, byte(len(seq))) // #nosec G115 -- realm capped at 20 bytes
	outer = append(outer, seq...)

	// Wrap in APPLICATION 10
	var app []byte
	app = append(app, 0x6a, byte(len(outer))) // #nosec G115 -- realm capped at 20 bytes
	app = append(app, outer...)

	return app
}

// probeRC4Support sends an AS-REQ with only etype 23 (RC4-HMAC) for the given realm
// and returns true if the KDC accepts RC4-HMAC.
func probeRC4Support(conn net.Conn, timeout time.Duration, realm string) bool {
	probe := buildRC4Probe(realm)
	tcpProbe := make([]byte, 4+len(probe))
	binary.BigEndian.PutUint32(tcpProbe[0:4], uint32(len(probe))) // #nosec G115 -- probe is at most ~200 bytes; cannot overflow uint32
	copy(tcpProbe[4:], probe)

	response, err := utils.SendRecv(conn, tcpProbe, timeout)
	if err != nil {
		return false
	}

	// Response must be at least 10 bytes (4-byte TCP length + 6 bytes Kerberos minimum)
	if len(response) < 10 {
		return false
	}

	// Skip 4-byte TCP prefix and verify Kerberos message type
	kerberosData := response[4:]
	if kerberosData[0] != tagKRBError && kerberosData[0] != tagASREP {
		return false
	}

	// AS-REP means the KDC authenticated the request using RC4-HMAC — even more concerning
	if kerberosData[0] == tagASREP {
		return true
	}

	// For KRB-ERROR responses, extract the error code
	_, errorCode, _ := parseKerberosError(response)

	// errorCode 0 from a KRB-ERROR means the parser failed to extract the code.
	// Our probe uses an invalid principal, so a real KDC always returns a non-zero
	// error code. Default to "not vulnerable" on parse failure rather than false positive.
	if errorCode == 0 {
		return false
	}

	// KDC_ERR_ETYPE_NOSUPP means the KDC explicitly rejected RC4-HMAC.
	if errorCode == kdcErrEtypeNosupp {
		return false
	}

	// Some KDCs validate the principal name before checking the etype list.
	// These error codes don't tell us whether RC4-HMAC is accepted or not.
	if ambiguousErrorCodes[errorCode] {
		return false
	}

	// Any other error code means the KDC processed the request past etype
	// validation, indicating RC4-HMAC is supported.
	return true
}

// checkWeakEtypes probes for RC4-HMAC support on the existing connection.
func checkWeakEtypes(conn net.Conn, timeout time.Duration, realm string) bool {
	return probeRC4Support(conn, timeout, realm)
}

// kerberosWeakEtypesFinding returns a SecurityFinding for a KDC that accepts RC4-HMAC.
func kerberosWeakEtypesFinding(realm string) plugins.SecurityFinding {
	evidence := "RC4-HMAC (etype 23) accepted by KDC"
	if realm != "" {
		evidence = fmt.Sprintf("RC4-HMAC (etype 23) accepted by KDC in realm %q", realm)
	}
	return plugins.SecurityFinding{
		ID:          "kerberos-weak-etypes",
		Severity:    plugins.SeverityMedium,
		Description: "Kerberos KDC supports RC4-HMAC (etype 23) — enables Kerberoasting attacks",
		Evidence:    evidence,
	}
}

// derWrap encodes tag + DER length + content. Supports long-form length (0x81 prefix)
// for lengths 128-255. Returns nil for content exceeding 255 bytes to prevent silent truncation.
func derWrap(tag byte, content []byte) []byte {
	if content == nil {
		return nil
	}
	out := []byte{tag}
	n := len(content)
	if n < 128 {
		out = append(out, byte(n)) // #nosec G115 -- n < 128, fits in byte
	} else if n <= 255 {
		out = append(out, 0x81, byte(n)) // #nosec G115 -- n <= 255, guarded above
	} else {
		return nil
	}
	return append(out, content...)
}

// buildPreauthProbe builds an AS-REQ for the given realm and principal with no padata
// (no pre-authentication data). Returns nil if realm or principal is empty or too long.
// Both realm and principal are capped at 40 bytes to keep DER lengths within the range
// supported by derWrap (max 255 bytes per field).
func buildPreauthProbe(realm, principal string) []byte {
	r := []byte(realm)
	p := []byte(principal)
	if len(r) == 0 || len(r) > 40 || len(p) == 0 || len(p) > 40 {
		return nil
	}

	var body []byte
	// [0] kdc-options
	body = append(body, 0xa0, 0x07, 0x03, 0x05, 0x00, 0x50, 0x80, 0x00, 0x10)

	// [1] cname = PrincipalName { name-type=1 (KRB_NT_PRINCIPAL), name-string=[principal] }
	nameStrSeq := derWrap(0x1b, p) // GeneralString(principal)
	nameStrSeqWrapped := derWrap(0x30, nameStrSeq)
	cnameInner := append([]byte{0xa0, 0x03, 0x02, 0x01, 0x01}, // name-type = 1
		derWrap(0xa1, nameStrSeqWrapped)...)
	body = append(body, derWrap(0xa1, derWrap(0x30, cnameInner))...)

	// [2] realm = GeneralString(realm)
	body = append(body, derWrap(0xa2, derWrap(0x1b, r))...)

	// [3] sname = PrincipalName { name-type=0, name-string=["krbtgt", realm] }
	krbtgt := []byte("krbtgt")
	snameStrSeq := append(derWrap(0x1b, krbtgt), derWrap(0x1b, r)...)
	snameStrSeqWrapped := derWrap(0x30, snameStrSeq)
	snameInner := append([]byte{0xa0, 0x03, 0x02, 0x01, 0x00}, // name-type = 0
		derWrap(0xa1, snameStrSeqWrapped)...)
	body = append(body, derWrap(0xa3, derWrap(0x30, snameInner))...)

	// [5] till = GeneralizedTime "20370913024805Z"
	body = append(body, 0xa5, 0x11, 0x18, 0x0f)
	body = append(body, []byte("20370913024805Z")...)

	// [7] nonce
	body = append(body, 0xa7, 0x06, 0x02, 0x04, 0x1f, 0x1e, 0xb9, 0xd9)

	// [8] etype = SEQUENCE { INTEGER 18, INTEGER 17, INTEGER 23 }
	body = append(body, 0xa8, 0x0b, 0x30, 0x09,
		0x02, 0x01, 0x12, // 18 (AES256-CTS-HMAC-SHA1-96)
		0x02, 0x01, 0x11, // 17 (AES128-CTS-HMAC-SHA1-96)
		0x02, 0x01, 0x17) // 23 (RC4-HMAC)

	// Wrap body in [4] req-body context tag
	reqBodyContent := derWrap(0x30, body)
	reqBody := derWrap(0xa4, reqBodyContent)

	// Outer SEQUENCE: pvno + msg-type + req-body (no padata — intentional)
	var seq []byte
	seq = append(seq, 0xa1, 0x03, 0x02, 0x01, 0x05) // pvno = 5
	seq = append(seq, 0xa2, 0x03, 0x02, 0x01, 0x0a) // msg-type = 10 (AS-REQ)
	seq = append(seq, reqBody...)

	return derWrap(0x6a, derWrap(0x30, seq))
}

// checkPreauthNotRequired probes whether the KDC issues an AS-REP for the
// "administrator" principal without pre-authentication. Returns true only if
// the KDC responds with an AS-REP (tag 0x6B).
func checkPreauthNotRequired(conn net.Conn, timeout time.Duration, realm string) bool {
	probe := buildPreauthProbe(realm, preauthPrincipal)
	if probe == nil {
		return false
	}
	tcpProbe := make([]byte, 4+len(probe))
	binary.BigEndian.PutUint32(tcpProbe[0:4], uint32(len(probe))) // #nosec G115 -- probe is at most a few hundred bytes; cannot overflow uint32
	copy(tcpProbe[4:], probe)

	response, err := utils.SendRecv(conn, tcpProbe, timeout)
	if err != nil {
		return false
	}
	if len(response) < 10 {
		return false
	}
	// AS-REP (tag 0x6B) means the KDC issued a ticket without pre-auth.
	return response[4] == tagASREP
}

// kerberosPreauthNotRequiredFinding returns a SecurityFinding for a KDC that does
// not require Kerberos pre-authentication, enabling AS-REP roasting.
func kerberosPreauthNotRequiredFinding(realm, account string) plugins.SecurityFinding {
	var evidence string
	if account != "" && realm != "" {
		evidence = fmt.Sprintf("KDC issued AS-REP for account %q in realm %q without pre-authentication", account, realm)
	} else if realm != "" {
		evidence = fmt.Sprintf("KDC in realm %q issued AS-REP without pre-authentication (unknown principal)", realm)
	} else {
		evidence = "KDC issued AS-REP without pre-authentication"
	}
	return plugins.SecurityFinding{
		ID:          "kerberos-preauth-not-required",
		Severity:    plugins.SeverityHigh,
		Description: "Kerberos pre-authentication not required — enables AS-REP roasting (MITRE ATT&CK T1558.004)",
		Evidence:    evidence,
	}
}

var (
	cgnatPrefix     = netip.MustParsePrefix("100.64.0.0/10")   // RFC 6598 Shared Address Space (CGNAT)
	testNet1        = netip.MustParsePrefix("192.0.2.0/24")    // RFC 5737 TEST-NET-1
	testNet2        = netip.MustParsePrefix("198.51.100.0/24") // RFC 5737 TEST-NET-2
	testNet3        = netip.MustParsePrefix("203.0.113.0/24")  // RFC 5737 TEST-NET-3
	doc6Prefix      = netip.MustParsePrefix("2001:db8::/32")   // RFC 3849 IPv6 documentation
	benchmarkPrefix = netip.MustParsePrefix("198.18.0.0/15")   // RFC 2544 benchmarking
	broadcastAddr   = netip.MustParseAddr("255.255.255.255")   // IPv4 limited broadcast
)

// isInternetRoutable returns true if addr is a publicly routable IP address
// (not private, loopback, link-local, unspecified, CGNAT, or documentation range).
func isInternetRoutable(addr netip.Addr) bool {
	return !addr.IsPrivate() &&
		!addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsMulticast() &&
		!addr.IsUnspecified() &&
		!cgnatPrefix.Contains(addr) &&
		!testNet1.Contains(addr) &&
		!testNet2.Contains(addr) &&
		!testNet3.Contains(addr) &&
		!doc6Prefix.Contains(addr) &&
		!benchmarkPrefix.Contains(addr) &&
		addr != broadcastAddr
}

// kerberosInternetExposedFinding returns a SecurityFinding for a KDC accessible
// from a publicly routable IP address.
func kerberosInternetExposedFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "kerberos-internet-exposed",
		Severity:    plugins.SeverityMedium,
		Description: "Kerberos KDC accessible from the internet — exposes AD infrastructure",
		Evidence:    "KDC listening on a publicly routable IP address",
	}
}

func (p *KerberosPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	detected, response, err := detectKerberos(conn, timeout)
	if err != nil {
		return nil, err
	}

	if !detected {
		return nil, nil
	}

	// Extract metadata from the response
	realm, errorCode, errorText := parseKerberosError(response)

	payload := plugins.ServiceKerberos{
		Realm:     realm,
		ErrorCode: errorCode,
		ErrorText: errorText,
	}

	// Kerberos version is always "5" for Kerberos v5
	service := plugins.CreateServiceFrom(target, payload, false, "5", plugins.TCP)

	if target.Misconfigs {
		var findings []plugins.SecurityFinding

		// Check if the initial detection probe received an AS-REP — this means the
		// KDC issues tickets to unknown principals without pre-authentication.
		initialASREP := len(response) >= 5 && response[4] == tagASREP
		if initialASREP {
			findings = append(findings, kerberosPreauthNotRequiredFinding(realm, ""))
		} else if realm != "" {
			// KDCs (including MIT KDC) close the TCP connection after the first
			// request. Dial a fresh connection for each misconfig probe.
			if preauthConn, dialErr := net.DialTimeout("tcp", target.Address.String(), timeout); dialErr == nil {
				if checkPreauthNotRequired(preauthConn, timeout, realm) {
					findings = append(findings, kerberosPreauthNotRequiredFinding(realm, preauthPrincipal))
				}
				_ = preauthConn.Close()
			}
		}

		if weakConn, dialErr := net.DialTimeout("tcp", target.Address.String(), timeout); dialErr == nil {
			if checkWeakEtypes(weakConn, timeout, realm) {
				findings = append(findings, kerberosWeakEtypesFinding(realm))
			}
			_ = weakConn.Close()
		}

		if isInternetRoutable(target.Address.Addr()) {
			findings = append(findings, kerberosInternetExposedFinding())
		}

		service.SecurityFindings = findings
	}

	return service, nil
}

func (p *KerberosPlugin) PortPriority(port uint16) bool {
	return port == 88
}

func (p *KerberosPlugin) Name() string {
	return KERBEROS
}

func (p *KerberosPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *KerberosPlugin) Priority() int {
	return 175
}

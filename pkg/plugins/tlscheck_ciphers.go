// Copyright 2026 Praetorian Security, Inc.
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

package plugins

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	findingTLSAnonCipher   = "tls-anon-cipher"
	findingTLSNullCipher   = "tls-null-cipher"
	findingTLSExportCipher = "tls-export-cipher"
	weakCipherProbeTimeout = 3 * time.Second
)

type weakClass uint8

const (
	weakNone weakClass = iota
	weakAnon
	weakNull
	weakExport
)

// IANA TLS 1.0–1.2 suites that are anonymous, NULL, or EXPORT.
// Go's stdlib client will not offer these; the probe sends them raw.
// RFC 2246 / 4346 / 4492 IANA IDs for ADH, AECDH, NULL, and EXPORT.
var weakCipherSuites = []struct {
	id    uint16
	class weakClass
}{
	{0x0001, weakNull},   // TLS_RSA_WITH_NULL_MD5
	{0x0002, weakNull},   // TLS_RSA_WITH_NULL_SHA
	{0x003B, weakNull},   // TLS_RSA_WITH_NULL_SHA256
	{0xC001, weakNull},   // TLS_ECDH_ECDSA_WITH_NULL_SHA
	{0xC006, weakNull},   // TLS_ECDHE_ECDSA_WITH_NULL_SHA
	{0xC00B, weakNull},   // TLS_ECDH_RSA_WITH_NULL_SHA
	{0xC010, weakNull},   // TLS_ECDHE_RSA_WITH_NULL_SHA
	{0xC015, weakNull},   // TLS_ECDH_anon_WITH_NULL_SHA
	{0x0003, weakExport}, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
	{0x0006, weakExport}, // TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
	{0x0008, weakExport}, // TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
	{0x000B, weakExport}, // TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
	{0x000E, weakExport}, // TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
	{0x0011, weakExport}, // TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
	{0x0014, weakExport}, // TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
	{0x0017, weakExport}, // TLS_DH_anon_EXPORT_WITH_RC4_40_MD5
	{0x0019, weakExport}, // TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
	{0x0018, weakAnon},   // TLS_DH_anon_WITH_RC4_128_MD5
	{0x001A, weakAnon},   // TLS_DH_anon_WITH_DES_CBC_SHA
	{0x001B, weakAnon},   // TLS_DH_anon_WITH_3DES_EDE_CBC_SHA
	{0x0034, weakAnon},   // TLS_DH_anon_WITH_AES_128_CBC_SHA
	{0x003A, weakAnon},   // TLS_DH_anon_WITH_AES_256_CBC_SHA
	{0x006C, weakAnon},   // TLS_DH_anon_WITH_AES_128_CBC_SHA256
	{0x006D, weakAnon},   // TLS_DH_anon_WITH_AES_256_CBC_SHA256
	{0x00A6, weakAnon},   // TLS_DH_anon_WITH_AES_128_GCM_SHA256
	{0x00A7, weakAnon},   // TLS_DH_anon_WITH_AES_256_GCM_SHA384
	{0xC016, weakAnon},   // TLS_ECDH_anon_WITH_RC4_128_SHA
	{0xC017, weakAnon},   // TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
	{0xC018, weakAnon},   // TLS_ECDH_anon_WITH_AES_128_CBC_SHA
	{0xC019, weakAnon},   // TLS_ECDH_anon_WITH_AES_256_CBC_SHA
}

func classOfSuite(id uint16) weakClass {
	for _, s := range weakCipherSuites {
		if s.id == id {
			return s.class
		}
	}
	return weakNone
}

func tcpRemoteAddr(conn net.Conn) string {
	addr := conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.String()
	}
	return ""
}

type rawTCPDialer interface {
	DialRawTCP() (net.Conn, error)
}

type probeSNIProvider interface {
	ProbeSNI() string
}

func unwrapConn(conn net.Conn) net.Conn {
	cur := conn
	for i := 0; i < 8; i++ {
		u, ok := cur.(interface{ Unwrap() net.Conn })
		if !ok {
			return cur
		}
		next := u.Unwrap()
		if next == nil || next == cur {
			return cur
		}
		cur = next
	}
	return cur
}

func resolveRawDial(conn net.Conn) func() (net.Conn, error) {
	cur := conn
	for i := 0; i < 8 && cur != nil; i++ {
		if d, ok := cur.(rawTCPDialer); ok {
			return func() (net.Conn, error) { return d.DialRawTCP() }
		}
		u, ok := cur.(interface{ Unwrap() net.Conn })
		if !ok {
			break
		}
		cur = u.Unwrap()
	}
	addr := tcpRemoteAddr(unwrapConn(conn))
	if addr == "" {
		return nil
	}
	return func() (net.Conn, error) {
		d := net.Dialer{Timeout: weakCipherProbeTimeout}
		return d.Dial("tcp", addr)
	}
}

func resolveProbeSNI(conn net.Conn) string {
	cur := conn
	for i := 0; i < 8 && cur != nil; i++ {
		if p, ok := cur.(probeSNIProvider); ok {
			if s := p.ProbeSNI(); s != "" {
				return s
			}
		}
		u, ok := cur.(interface{ Unwrap() net.Conn })
		if !ok {
			break
		}
		cur = u.Unwrap()
	}
	if tlsConn, ok := unwrapConn(conn).(*tls.Conn); ok {
		return tlsConn.ConnectionState().ServerName
	}
	return ""
}

// ProbeWeakCiphers dials via dial and offers only anonymous, NULL, or EXPORT
// suites — one ClientHello per class. Go's stdlib handshake cannot do this.
// Used when a peer TLS alert proves the port is TLS but no *tls.Conn exists
// (the server offers only weak suites). Probe errors emit nothing.
func ProbeWeakCiphers(dial func() (net.Conn, error), sni string) []SecurityFinding {
	if dial == nil {
		return nil
	}
	var findings []SecurityFinding
	for _, class := range []weakClass{weakAnon, weakNull, weakExport} {
		if f := probeWeakClass(dial, sni, class); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings
}

// probeWeakCiphers dials a new connection to the same peer (via the scan dialer
// when present, otherwise RemoteAddr) and offers only anonymous, NULL, or
// EXPORT suites. Non-TCP peers (net.Pipe tests) are skipped.
func probeWeakCiphers(conn net.Conn) []SecurityFinding {
	return ProbeWeakCiphers(resolveRawDial(conn), resolveProbeSNI(conn))
}

func probeWeakClass(dial func() (net.Conn, error), sni string, class weakClass) *SecurityFinding {
	c, err := dial()
	if err != nil {
		return nil
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(weakCipherProbeTimeout))
	hello := buildWeakClientHello(class, sni)
	if _, err := c.Write(hello); err != nil {
		return nil
	}
	rec, err := readTLSRecord(c)
	if err != nil || len(rec) < 6 {
		return nil
	}
	if rec[0] != 0x16 {
		return nil
	}
	suite, ok := selectedCipherFromHandshakeRecord(rec)
	if !ok || classOfSuite(suite) != class {
		return nil
	}
	fs := findingForWeakSuite(suite)
	if len(fs) == 0 {
		return nil
	}
	return &fs[0]
}

func findingForWeakSuite(suite uint16) []SecurityFinding {
	class := classOfSuite(suite)
	evidence := fmt.Sprintf("selected_cipher=0x%04x", suite)
	switch class {
	case weakAnon:
		return []SecurityFinding{{
			ID:          findingTLSAnonCipher,
			Severity:    SeverityHigh,
			Description: "Server selected an anonymous (ADH/AECDH) TLS cipher suite",
			Evidence:    evidence,
		}}
	case weakNull:
		return []SecurityFinding{{
			ID:          findingTLSNullCipher,
			Severity:    SeverityHigh,
			Description: "Server selected a NULL TLS cipher suite",
			Evidence:    evidence,
		}}
	case weakExport:
		return []SecurityFinding{{
			ID:          findingTLSExportCipher,
			Severity:    SeverityHigh,
			Description: "Server selected an EXPORT TLS cipher suite",
			Evidence:    evidence,
		}}
	default:
		return nil
	}
}

func suitesForClass(class weakClass) []uint16 {
	out := make([]uint16, 0, len(weakCipherSuites))
	for _, s := range weakCipherSuites {
		if s.class == class {
			out = append(out, s.id)
		}
	}
	return out
}

func buildWeakClientHello(class weakClass, sni string) []byte {
	var body []byte
	// RFC 4346 forbids negotiating EXPORT in TLS 1.1+. Offer TLS 1.0 for
	// that class so stacks that still enable EXPORT can select it.
	if class == weakExport {
		body = append(body, 0x03, 0x01) // client_version TLS 1.0
	} else {
		body = append(body, 0x03, 0x03) // client_version TLS 1.2
	}
	var rnd [32]byte
	_, _ = rand.Read(rnd[:])
	body = append(body, rnd[:]...)
	body = append(body, 0x00) // session_id length

	ids := suitesForClass(class)
	cs := make([]byte, 2+2*len(ids))
	binary.BigEndian.PutUint16(cs, uint16(2*len(ids)))
	for i, id := range ids {
		binary.BigEndian.PutUint16(cs[2+2*i:], id)
	}
	body = append(body, cs...)
	body = append(body, 0x01, 0x00) // compression methods: null

	ext := weakClientHelloExtensions(sni)
	body = append(body, ext...)

	hs := []byte{0x01} // handshake type client_hello
	hs = appendUint24(hs, len(body))
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01}
	rec = appendUint16(rec, len(hs))
	rec = append(rec, hs...)
	return rec
}

func weakClientHelloExtensions(sni string) []byte {
	// supported_groups (0x000a): secp256r1, secp384r1 — needed for AECDH
	groups := []byte{
		0x00, 0x0a,
		0x00, 0x06,
		0x00, 0x04,
		0x00, 0x17, // secp256r1
		0x00, 0x18, // secp384r1
	}
	// ec_point_formats (0x000b): uncompressed
	points := []byte{
		0x00, 0x0b,
		0x00, 0x02,
		0x01, 0x00,
	}
	inner := append(groups, points...)
	// RFC 6066 forbids IP literals in SNI host_name.
	if sni != "" && net.ParseIP(sni) == nil {
		inner = append(inner, serverNameExtension(sni)...)
	}
	out := make([]byte, 2+len(inner))
	binary.BigEndian.PutUint16(out, uint16(len(inner)))
	copy(out[2:], inner)
	return out
}

func serverNameExtension(hostname string) []byte {
	host := []byte(hostname)
	// server_name list: name_type host_name (0) + host
	name := make([]byte, 3+len(host))
	name[0] = 0
	binary.BigEndian.PutUint16(name[1:3], uint16(len(host)))
	copy(name[3:], host)
	list := make([]byte, 2+len(name))
	binary.BigEndian.PutUint16(list, uint16(len(name)))
	copy(list[2:], name)
	ext := make([]byte, 4+len(list))
	binary.BigEndian.PutUint16(ext[0:2], 0x0000) // server_name
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(list)))
	copy(ext[4:], list)
	return ext
}

func appendUint16(b []byte, n int) []byte {
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], uint16(n))
	return append(b, tmp[:]...)
}

func appendUint24(b []byte, n int) []byte {
	return append(b, byte(n>>16), byte(n>>8), byte(n))
}

func readTLSRecord(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n < 0 || n > 16384+2048 {
		return nil, io.ErrUnexpectedEOF
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

func cipherSuitesFromClientHelloRecord(rec []byte) ([]uint16, bool) {
	if len(rec) < 5 || rec[0] != 0x16 {
		return nil, false
	}
	payload := rec[5:]
	if len(payload) < 4 || payload[0] != 0x01 {
		return nil, false
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	body := payload[4:]
	if hsLen > len(body) {
		hsLen = len(body)
	}
	body = body[:hsLen]
	if len(body) < 35 {
		return nil, false
	}
	sidLen := int(body[34])
	off := 35 + sidLen
	if len(body) < off+2 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if n%2 != 0 || len(body) < off+n {
		return nil, false
	}
	out := make([]uint16, n/2)
	for i := 0; i < len(out); i++ {
		out[i] = binary.BigEndian.Uint16(body[off+2*i : off+2*i+2])
	}
	return out, true
}

func clientHelloIsWeakOnly(rec []byte) bool {
	suites, ok := cipherSuitesFromClientHelloRecord(rec)
	if !ok || len(suites) == 0 {
		return false
	}
	for _, s := range suites {
		if classOfSuite(s) == weakNone {
			return false
		}
	}
	return true
}

func selectedCipherFromHandshakeRecord(rec []byte) (uint16, bool) {
	if len(rec) < 5 {
		return 0, false
	}
	payload := rec[5:]
	if len(payload) < 4 || payload[0] != 0x02 { // server_hello
		return 0, false
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	body := payload[4:]
	if hsLen > len(body) {
		hsLen = len(body)
	}
	body = body[:hsLen]
	// server_version (2) + random (32) + session_id_len (1)
	if len(body) < 35 {
		return 0, false
	}
	sidLen := int(body[34])
	off := 35 + sidLen
	if len(body) < off+2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(body[off : off+2]), true
}

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
	"net"
	"time"
)

// SSL 3.0 wire version. Go's crypto/tls no longer exports VersionSSL30.
const versionSSL30 uint16 = 0x0300

const (
	findingTLSWeakVersionSSL3 = "tls-weak-version-ssl3"
	findingTLSWeakSignature   = "tls-weak-signature"
	findingTLSCNMismatch      = "tls-cn-mismatch"
	findingTLSUntrustedCA     = "tls-untrusted-ca"
)

// Suites old stacks still select. EXPORT/ADH/NULL stay on ProbeWeakCiphers.
var offeredVersionSuites = []uint16{
	0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
	0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
	0x000a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	0x0005, // TLS_RSA_WITH_RC4_128_SHA
	0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
}

var offeredVersions = []uint16{
	versionSSL30,
	tls.VersionTLS10,
	tls.VersionTLS11,
}

// ProbeTLSMisconfigs runs offered-version and weak-cipher probes on the same dialer.
func ProbeTLSMisconfigs(dial func() (net.Conn, error), sni string) []SecurityFinding {
	return mergeFindingsByID(ProbeOfferedTLSVersions(dial, sni), ProbeWeakCiphers(dial, sni))
}

// ProbeOfferedTLSVersions dials via dial and sends a ClientHello whose
// client_version is SSL 3.0, TLS 1.0, or TLS 1.1. A ServerHello is enough to
// record that the version is offered, including mixed stacks that also speak
// TLS 1.2. Probe errors emit nothing.
func ProbeOfferedTLSVersions(dial func() (net.Conn, error), sni string) []SecurityFinding {
	if dial == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var findings []SecurityFinding
	for _, ver := range offeredVersions {
		f := probeOfferedVersion(dial, sni, ver)
		if f == nil {
			continue
		}
		if _, ok := seen[f.ID]; ok {
			continue
		}
		seen[f.ID] = struct{}{}
		findings = append(findings, *f)
	}
	return findings
}

func probeOfferedVersions(conn net.Conn) []SecurityFinding {
	return ProbeOfferedTLSVersions(resolveRawDial(conn), resolveProbeSNI(conn))
}

func probeOfferedVersion(dial func() (net.Conn, error), sni string, clientVersion uint16) *SecurityFinding {
	c, err := dial()
	if err != nil {
		return nil
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(weakCipherProbeTimeout))
	hello := buildVersionClientHello(clientVersion, sni)
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
	selected, ok := selectedVersionFromHandshakeRecord(rec)
	if !ok {
		return nil
	}
	return checkWeakTLSVersion(selected)
}

func buildVersionClientHello(clientVersion uint16, sni string) []byte {
	var body []byte
	body = append(body, byte(clientVersion>>8), byte(clientVersion))
	var rnd [32]byte
	_, _ = rand.Read(rnd[:])
	body = append(body, rnd[:]...)
	body = append(body, 0x00) // session_id length

	cs := make([]byte, 2+2*len(offeredVersionSuites))
	binary.BigEndian.PutUint16(cs, uint16(2*len(offeredVersionSuites)))
	for i, id := range offeredVersionSuites {
		binary.BigEndian.PutUint16(cs[2+2*i:], id)
	}
	body = append(body, cs...)
	body = append(body, 0x01, 0x00) // compression: null

	if clientVersion >= tls.VersionTLS10 {
		ext := weakClientHelloExtensions(sni)
		body = append(body, ext...)
	}

	hs := []byte{0x01}
	hs = appendUint24(hs, len(body))
	hs = append(hs, body...)

	recVer := clientVersion
	if recVer < tls.VersionTLS10 {
		recVer = versionSSL30
	} else if recVer > tls.VersionTLS10 {
		recVer = tls.VersionTLS10 // record layer 0x0301 as in the cipher probe
	}
	rec := []byte{0x16, byte(recVer >> 8), byte(recVer)}
	rec = appendUint16(rec, len(hs))
	rec = append(rec, hs...)
	return rec
}

func selectedVersionFromHandshakeRecord(rec []byte) (uint16, bool) {
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
	if len(body) < 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(body[0:2]), true
}

func mergeFindingsByID(base []SecurityFinding, extra []SecurityFinding) []SecurityFinding {
	seen := make(map[string]struct{}, len(base))
	for _, f := range base {
		seen[f.ID] = struct{}{}
	}
	out := base
	for _, f := range extra {
		if _, ok := seen[f.ID]; ok {
			continue
		}
		seen[f.ID] = struct{}{}
		out = append(out, f)
	}
	return out
}

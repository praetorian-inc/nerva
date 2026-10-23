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

package scan

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// IANA ADH/AECDH/NULL/EXPORT IDs — mirrored from plugins.weakCipherSuites so
// this scan-level mock can tell a weak-only ClientHello from Go's stdlib hello.
var weakOnlySuiteIDs = map[uint16]struct{}{
	0x0001: {}, 0x0002: {}, 0x003B: {}, 0xC001: {}, 0xC006: {}, 0xC00B: {}, 0xC010: {}, 0xC015: {},
	0x0003: {}, 0x0006: {}, 0x0008: {}, 0x000B: {}, 0x000E: {}, 0x0011: {}, 0x0014: {}, 0x0017: {}, 0x0019: {},
	0x0018: {}, 0x001A: {}, 0x001B: {}, 0x0034: {}, 0x003A: {}, 0x006C: {}, 0x006D: {}, 0x00A6: {}, 0x00A7: {},
	0xC016: {}, 0xC017: {}, 0xC018: {}, 0xC019: {},
}

func readTLSRecordForTest(r io.Reader) ([]byte, error) {
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

func cipherSuitesFromClientHelloForTest(rec []byte) ([]uint16, bool) {
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

func clientHelloIsWeakOnlyForTest(rec []byte) bool {
	suites, ok := cipherSuitesFromClientHelloForTest(rec)
	if !ok || len(suites) == 0 {
		return false
	}
	for _, s := range suites {
		if _, ok := weakOnlySuiteIDs[s]; !ok {
			return false
		}
	}
	return true
}

func writeRawServerHelloForTest(w io.Writer, suite uint16) error {
	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	var cs [2]byte
	binary.BigEndian.PutUint16(cs[:], suite)
	body = append(body, cs[:]...)
	body = append(body, 0x00)
	hs := []byte{0x02, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x03, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	_, err := w.Write(rec)
	return err
}

// startWeakOnlyTLSServer rejects a modern ClientHello with handshake_failure
// and selects suite only for a weak-only ClientHello. Go's stdlib client
// cannot complete a handshake against it.
func startWeakOnlyTLSServer(t *testing.T, suite uint16) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				rec, err := readTLSRecordForTest(c)
				if err != nil {
					return
				}
				if clientHelloIsWeakOnlyForTest(rec) {
					offered, ok := cipherSuitesFromClientHelloForTest(rec)
					if ok {
						for _, id := range offered {
							if id == suite {
								_ = writeRawServerHelloForTest(c, suite)
								return
							}
						}
					}
					return
				}
				_, _ = c.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28})
			}(c)
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func TestSimpleScanTarget_WeakOnlyTLSEmitsCipherFindings(t *testing.T) {
	cases := []struct {
		name  string
		suite uint16
		id    string
	}{
		{name: "ADH", suite: 0x0034, id: "tls-anon-cipher"},
		{name: "NULL", suite: 0x0002, id: "tls-null-cipher"},
		{name: "EXPORT", suite: 0x0003, id: "tls-export-cipher"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port := startWeakOnlyTLSServer(t, tc.suite)
			if anyPluginClaimsPort(port) {
				t.Skipf("ephemeral port %d is claimed by a priority plugin", port)
			}
			config := &Config{DefaultTimeout: 2 * time.Second, Misconfigs: true}
			target := plugins.Target{
				Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port),
			}
			services, err := config.SimpleScanTarget(target)
			if err != nil {
				t.Fatalf("SimpleScanTarget: %v", err)
			}
			if len(services) != 1 {
				t.Fatalf("SimpleScanTarget returned %d services, want 1 with %s", len(services), tc.id)
			}
			found := false
			for _, f := range services[0].SecurityFindings {
				if f.ID == tc.id {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("missing %s in %+v", tc.id, services[0].SecurityFindings)
			}
			if !services[0].TLS {
				t.Fatal("expected TLS=true on weak-only misconfig service")
			}
		})
	}
}

func TestSimpleScanTarget_WeakOnlyTLSSilentWithoutMisconfigs(t *testing.T) {
	port := startWeakOnlyTLSServer(t, 0x0034)
	if anyPluginClaimsPort(port) {
		t.Skipf("ephemeral port %d is claimed by a priority plugin", port)
	}
	config := &Config{DefaultTimeout: 2 * time.Second, Misconfigs: false}
	target := plugins.Target{
		Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port),
	}
	services, err := config.SimpleScanTarget(target)
	if err != nil {
		t.Fatalf("SimpleScanTarget: %v", err)
	}
	if len(services) != 0 {
		t.Fatalf("SimpleScanTarget returned %d services without --misconfigs, want none", len(services))
	}
}

func TestSimpleScanTarget_TLSAlertModernServerNoWeakCipherFindings(t *testing.T) {
	port, _ := startSNIRequiredTLSServer(t)
	if anyPluginClaimsPort(port) {
		t.Skipf("ephemeral port %d is claimed by a priority plugin", port)
	}
	config := &Config{DefaultTimeout: 2 * time.Second, Misconfigs: true}
	target := plugins.Target{
		Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port),
	}
	services, err := config.SimpleScanTarget(target)
	if err != nil {
		t.Fatalf("SimpleScanTarget: %v", err)
	}
	for _, svc := range services {
		for _, f := range svc.SecurityFindings {
			switch f.ID {
			case "tls-anon-cipher", "tls-null-cipher", "tls-export-cipher":
				t.Fatalf("modern TLS-alert server emitted %s: %+v", f.ID, svc.SecurityFindings)
			}
		}
	}
}

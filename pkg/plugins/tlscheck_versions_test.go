// Copyright 2026 Praetorian Security, Inc.

package plugins

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func serverHelloRecord(version uint16) []byte {
	body := []byte{byte(version >> 8), byte(version)}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x2f)
	body = append(body, 0x00)
	hs := []byte{0x02}
	hs = appendUint24(hs, len(body))
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01}
	rec = appendUint16(rec, len(hs))
	rec = append(rec, hs...)
	return rec
}

func clientHelloVersion(rec []byte) (uint16, bool) {
	if len(rec) < 11 || rec[0] != 0x16 {
		return 0, false
	}
	payload := rec[5:]
	if payload[0] != 0x01 || len(payload) < 6 {
		return 0, false
	}
	return binary.BigEndian.Uint16(payload[4:6]), true
}

func startOfferedVersionServer(t *testing.T, pick func(clientVer uint16) (uint16, bool)) (dial func() (net.Conn, error), closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				rec, err := readTLSRecord(c)
				if err != nil {
					return
				}
				cv, ok := clientHelloVersion(rec)
				if !ok {
					return
				}
				sv, reply := pick(cv)
				if !reply {
					return
				}
				_, _ = c.Write(serverHelloRecord(sv))
			}(c)
		}
	}()
	addr := ln.Addr().String()
	return func() (net.Conn, error) {
		d := net.Dialer{Timeout: time.Second}
		return d.Dial("tcp", addr)
	}, func() { _ = ln.Close() }
}

func TestProbeOfferedTLSVersions_SSL3Only(t *testing.T) {
	dial, closeFn := startOfferedVersionServer(t, func(cv uint16) (uint16, bool) {
		return versionSSL30, cv == versionSSL30
	})
	t.Cleanup(closeFn)
	got := ProbeOfferedTLSVersions(dial, "")
	if len(got) != 1 || got[0].ID != findingTLSWeakVersionSSL3 {
		t.Fatalf("SSL3-only: got %+v, want tls-weak-version-ssl3", got)
	}
}

func TestProbeOfferedTLSVersions_TLS10Only(t *testing.T) {
	dial, closeFn := startOfferedVersionServer(t, func(cv uint16) (uint16, bool) {
		return tls.VersionTLS10, cv == tls.VersionTLS10
	})
	t.Cleanup(closeFn)
	got := ProbeOfferedTLSVersions(dial, "")
	if len(got) != 1 || got[0].ID != "tls-weak-version-10" {
		t.Fatalf("TLS1.0-only: got %+v, want tls-weak-version-10", got)
	}
}

func TestProbeOfferedTLSVersions_Mixed10And12(t *testing.T) {
	dial, closeFn := startOfferedVersionServer(t, func(cv uint16) (uint16, bool) {
		if cv <= tls.VersionTLS10 {
			return tls.VersionTLS10, true
		}
		return 0x0303, true
	})
	t.Cleanup(closeFn)
	got := ProbeOfferedTLSVersions(dial, "")
	found10 := false
	for _, f := range got {
		if f.ID == "tls-weak-version-10" {
			found10 = true
		}
		if f.ID == "tls-weak-version-11" {
			t.Errorf("mixed 1.0+1.2 should not emit TLS 1.1, got %+v", got)
		}
	}
	if !found10 {
		t.Fatalf("mixed 1.0+1.2: got %+v, want tls-weak-version-10", got)
	}
}

func TestProbeOfferedTLSVersions_NilDial(t *testing.T) {
	if got := ProbeOfferedTLSVersions(nil, ""); got != nil {
		t.Errorf("nil dial = %+v, want nil", got)
	}
}

func TestCheckWeakTLSVersion_SSL3(t *testing.T) {
	got := checkWeakTLSVersion(versionSSL30)
	if got == nil || got.ID != findingTLSWeakVersionSSL3 {
		t.Fatalf("SSL3 = %+v, want tls-weak-version-ssl3", got)
	}
}

func TestTLSVersionName_SSL3(t *testing.T) {
	if got := TLSVersionName(versionSSL30); got != "SSL 3.0" {
		t.Errorf("TLSVersionName(0x0300) = %q, want SSL 3.0", got)
	}
}

func TestSelectedVersionFromHandshakeRecord(t *testing.T) {
	rec := serverHelloRecord(tls.VersionTLS10)
	got, ok := selectedVersionFromHandshakeRecord(rec)
	if !ok || got != tls.VersionTLS10 {
		t.Fatalf("selected version = %04x ok=%v", got, ok)
	}
	if _, ok := selectedVersionFromHandshakeRecord([]byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}); ok {
		t.Fatal("alert record must not parse as ServerHello")
	}
}

func TestCheckWeakSignature(t *testing.T) {
	sha1 := &x509.Certificate{SignatureAlgorithm: x509.SHA1WithRSA, Subject: pkix.Name{CommonName: "sha1.example"}}
	got := checkWeakSignature(sha1)
	if got == nil || got.ID != findingTLSWeakSignature {
		t.Fatalf("SHA-1: %+v", got)
	}
	md5 := &x509.Certificate{SignatureAlgorithm: x509.MD5WithRSA}
	got = checkWeakSignature(md5)
	if got == nil || got.ID != findingTLSWeakSignature {
		t.Fatalf("MD5: %+v", got)
	}
	if checkWeakSignature(&x509.Certificate{SignatureAlgorithm: x509.SHA256WithRSA}) != nil {
		t.Fatal("SHA-256 should not be weak")
	}
}

func TestCheckHostnameMismatch(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{"other.example"}}
	got := checkHostnameMismatch(cert, "app.example")
	if got == nil || got.ID != findingTLSCNMismatch {
		t.Fatalf("mismatch: %+v", got)
	}
	if checkHostnameMismatch(cert, "") != nil {
		t.Fatal("empty SNI is not a mismatch")
	}
}

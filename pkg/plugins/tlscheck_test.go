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

package plugins

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers (local to this package – do not import from http sub-package)
// ---------------------------------------------------------------------------

// generateSelfSignedTLSCert creates an in-memory self-signed TLS certificate
// backed by an ECDSA P-256 key.  The result is ready for use as a
// tls.Config.Certificates entry.
func generateSelfSignedTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generateSelfSignedTLSCert: GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("generateSelfSignedTLSCert: CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("generateSelfSignedTLSCert: MarshalECPrivateKey: %v", err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatalf("generateSelfSignedTLSCert: X509KeyPair: %v", err)
	}
	return cert
}

// makeTLSConn performs an in-process TLS handshake over net.Pipe() at the
// requested TLS version and returns the client-side *tls.Conn.
// TLS 1.0/1.1 require GODEBUG=tls10server=1 in the process environment.
func makeTLSConn(t *testing.T, cert tls.Certificate, version uint16) *tls.Conn {
	t.Helper()
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   version,
		MaxVersion:   version,
	}
	clientCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test-only self-signed cert
		MinVersion:         version,
		MaxVersion:         version,
	}

	srvPipe, cliPipe := net.Pipe()
	t.Cleanup(func() {
		srvPipe.Close()
		cliPipe.Close()
	})

	srvHandshakeErr := make(chan error, 1)
	go func() {
		srv := tls.Server(srvPipe, serverCfg)
		srvHandshakeErr <- srv.Handshake()
	}()

	cliConn := tls.Client(cliPipe, clientCfg)
	if err := cliConn.Handshake(); err != nil {
		t.Fatalf("makeTLSConn: client handshake for version 0x%04x: %v", version, err)
	}
	if err := <-srvHandshakeErr; err != nil {
		t.Fatalf("makeTLSConn: server handshake for version 0x%04x: %v", version, err)
	}
	return cliConn
}

// makeTLSCertWithKey builds a self-signed tls.Certificate using the supplied
// private key so callers can exercise specific key types and sizes.
// IsCA and KeyUsageCertSign are set so that leaf.CheckSignatureFrom(leaf) passes,
// which is required for the self-signed detection logic.
func makeTLSCertWithKey(t *testing.T, privKey interface{}, pubKey interface{}) tls.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-key"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pubKey, privKey)
	if err != nil {
		t.Fatalf("makeTLSCertWithKey: CreateCertificate: %v", err)
	}

	var keyDER []byte
	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		keyDER = x509.MarshalPKCS1PrivateKey(k)
	case *ecdsa.PrivateKey:
		keyDER, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatalf("makeTLSCertWithKey: MarshalECPrivateKey: %v", err)
		}
	case ed25519.PrivateKey:
		keyDER, err = x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatalf("makeTLSCertWithKey: MarshalPKCS8PrivateKey: %v", err)
		}
	default:
		t.Fatalf("makeTLSCertWithKey: unsupported key type %T", privKey)
	}

	var blockType string
	switch privKey.(type) {
	case *rsa.PrivateKey:
		blockType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		blockType = "EC PRIVATE KEY"
	default:
		blockType = "PRIVATE KEY"
	}

	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: keyDER}),
	)
	if err != nil {
		t.Fatalf("makeTLSCertWithKey: X509KeyPair: %v", err)
	}
	return cert
}

// selfSignedX509Cert creates a *x509.Certificate that is genuinely
// self-signed (leaf.CheckSignatureFrom(leaf) == nil).
func selfSignedX509Cert(t *testing.T, subject string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("selfSignedX509Cert: GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: subject},
		Issuer:                pkix.Name{CommonName: subject},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("selfSignedX509Cert: CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("selfSignedX509Cert: ParseCertificate: %v", err)
	}
	return cert
}

// expiredX509Cert creates a *x509.Certificate whose NotAfter is in the past.
func expiredX509Cert(t *testing.T, expiredAgo time.Duration) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("expiredX509Cert: GenerateKey: %v", err)
	}
	notAfter := time.Now().Add(-expiredAgo)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "expired.example.com"},
		NotBefore:    notAfter.Add(-24 * time.Hour),
		NotAfter:     notAfter,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("expiredX509Cert: CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("expiredX509Cert: ParseCertificate: %v", err)
	}
	return cert
}

// validX509Cert creates a *x509.Certificate whose NotAfter is in the future.
func validX509Cert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("validX509Cert: GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(5),
		Subject:      pkix.Name{CommonName: "valid.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("validX509Cert: CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("validX509Cert: ParseCertificate: %v", err)
	}
	return cert
}

// x509CertWithPublicKey creates a *x509.Certificate signed by a P-256 CA but
// embedding the provided pubKey so callers can test checkWeakKey without a TLS
// handshake.
func x509CertWithPublicKey(t *testing.T, pubKey interface{}) *x509.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("x509CertWithPublicKey: GenerateKey CA: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(6),
		Subject:      pkix.Name{CommonName: "key-test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pubKey, caKey)
	if err != nil {
		t.Fatalf("x509CertWithPublicKey: CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("x509CertWithPublicKey: ParseCertificate: %v", err)
	}
	return cert
}

// ---------------------------------------------------------------------------
// TestCheckTLS_NonTLSConn
// ---------------------------------------------------------------------------

// TestCheckTLS_NonTLSConn verifies that a plain net.Conn (not a *tls.Conn)
// causes CheckTLS to return nil without panicking.
func TestCheckTLS_NonTLSConn(t *testing.T) {
	srvPipe, cliPipe := net.Pipe()
	t.Cleanup(func() {
		srvPipe.Close()
		cliPipe.Close()
	})

	findings := CheckTLS(cliPipe)
	if findings != nil {
		t.Errorf("CheckTLS(plain net.Conn) = %+v, want nil", findings)
	}
}

// ---------------------------------------------------------------------------
// TestCheckWeakTLSVersion
// ---------------------------------------------------------------------------

// TestCheckWeakTLSVersion exercises checkWeakTLSVersion directly for each
// known version and confirms the correct finding ID, severity, and
// description keywords.
func TestCheckWeakTLSVersion(t *testing.T) {
	tests := []struct {
		name         string
		version      uint16
		wantNil      bool
		wantID       string
		wantSeverity Severity
		wantDescHint string
	}{
		{
			name:         "TLS 1.0 produces Medium finding with BEAST reference",
			version:      tls.VersionTLS10,
			wantNil:      false,
			wantID:       "tls-weak-version",
			wantSeverity: SeverityMedium,
			wantDescHint: "BEAST",
		},
		{
			name:         "TLS 1.1 produces Low finding with RFC 8996 reference",
			version:      tls.VersionTLS11,
			wantNil:      false,
			wantID:       "tls-weak-version",
			wantSeverity: SeverityLow,
			wantDescHint: "RFC 8996",
		},
		{
			name:    "TLS 1.2 produces no finding",
			version: tls.VersionTLS12,
			wantNil: true,
		},
		{
			name:    "TLS 1.3 produces no finding",
			version: tls.VersionTLS13,
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := checkWeakTLSVersion(tc.version)

			if tc.wantNil {
				if got != nil {
					t.Errorf("checkWeakTLSVersion(0x%04x) = %+v, want nil", tc.version, got)
				}
				return
			}

			if got == nil {
				t.Fatalf("checkWeakTLSVersion(0x%04x) = nil, want non-nil finding", tc.version)
			}
			if got.ID != tc.wantID {
				t.Errorf("finding.ID = %q, want %q", got.ID, tc.wantID)
			}
			if got.Severity != tc.wantSeverity {
				t.Errorf("finding.Severity = %q, want %q", got.Severity, tc.wantSeverity)
			}
			if !strings.Contains(got.Description, tc.wantDescHint) {
				t.Errorf("finding.Description = %q, want it to contain %q", got.Description, tc.wantDescHint)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestCheckExpiredCert
// ---------------------------------------------------------------------------

// TestCheckExpiredCert exercises checkExpiredCert directly for expired and
// valid certificates, including the boundary case of a cert that expired
// less than 24 hours ago (days_since_expiry=0).
func TestCheckExpiredCert(t *testing.T) {
	t.Run("expired cert produces finding with days_since_expiry", func(t *testing.T) {
		// Expired 72 hours ago → days_since_expiry=3
		cert := expiredX509Cert(t, 72*time.Hour)
		got := checkExpiredCert(cert)
		if got == nil {
			t.Fatal("checkExpiredCert(expired cert) = nil, want non-nil finding")
		}
		if got.ID != "tls-certificate-expired" {
			t.Errorf("finding.ID = %q, want %q", got.ID, "tls-certificate-expired")
		}
		if got.Severity != SeverityLow {
			t.Errorf("finding.Severity = %q, want %q", got.Severity, SeverityLow)
		}
		if !strings.Contains(got.Evidence, "days_since_expiry") {
			t.Errorf("finding.Evidence = %q, want it to contain %q", got.Evidence, "days_since_expiry")
		}
	})

	t.Run("valid cert produces no finding", func(t *testing.T) {
		cert := validX509Cert(t)
		got := checkExpiredCert(cert)
		if got != nil {
			t.Errorf("checkExpiredCert(valid cert) = %+v, want nil", got)
		}
	})

	t.Run("just-expired cert has days_since_expiry=0", func(t *testing.T) {
		// Expired 1 hour ago – within the same calendar day.
		cert := expiredX509Cert(t, time.Hour)
		got := checkExpiredCert(cert)
		if got == nil {
			t.Fatal("checkExpiredCert(just-expired cert) = nil, want non-nil finding")
		}
		if !strings.Contains(got.Evidence, "days_since_expiry=0") {
			t.Errorf("finding.Evidence = %q, want it to contain %q", got.Evidence, "days_since_expiry=0")
		}
	})
}

// ---------------------------------------------------------------------------
// TestCheckSelfSignedCert
// ---------------------------------------------------------------------------

// TestCheckSelfSignedCert exercises checkSelfSignedCert directly.
// A genuinely self-signed certificate (chain length 1, passes
// leaf.CheckSignatureFrom(leaf)) must produce the tls-self-signed finding.
// A chain of length > 1 must always return nil regardless of the leaf.
func TestCheckSelfSignedCert(t *testing.T) {
	t.Run("chain length 1 with genuine self-sig produces Info finding", func(t *testing.T) {
		leaf := selfSignedX509Cert(t, "self-signed.example.com")
		chain := []*x509.Certificate{leaf}

		got := checkSelfSignedCert(leaf, chain)
		if got == nil {
			t.Fatal("checkSelfSignedCert(self-signed) = nil, want non-nil finding")
		}
		if got.ID != "tls-self-signed" {
			t.Errorf("finding.ID = %q, want %q", got.ID, "tls-self-signed")
		}
		if got.Severity != SeverityInfo {
			t.Errorf("finding.Severity = %q, want %q", got.Severity, SeverityInfo)
		}
	})

	t.Run("chain length > 1 produces no finding even if leaf looks self-signed", func(t *testing.T) {
		leaf := selfSignedX509Cert(t, "leaf.example.com")
		// Simulate a chain with a second certificate present (e.g. an intermediate).
		// The actual content of the second cert doesn't matter – only chain length does.
		intermediate := selfSignedX509Cert(t, "intermediate.example.com")
		chain := []*x509.Certificate{leaf, intermediate}

		got := checkSelfSignedCert(leaf, chain)
		if got != nil {
			t.Errorf("checkSelfSignedCert(chain len 2) = %+v, want nil", got)
		}
	})

	t.Run("chain length 1 but cert is not self-signed produces no finding", func(t *testing.T) {
		// Build a cert that cannot verify its own signature (signed by a different key).
		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey CA: %v", err)
		}
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey leaf: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(99),
			Subject:      pkix.Name{CommonName: "ca-signed.example.com"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		// Sign with CA key → CheckSignatureFrom(leaf) will fail.
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &leafKey.PublicKey, caKey)
		if err != nil {
			t.Fatalf("CreateCertificate: %v", err)
		}
		leaf, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}
		chain := []*x509.Certificate{leaf}

		got := checkSelfSignedCert(leaf, chain)
		if got != nil {
			t.Errorf("checkSelfSignedCert(CA-signed, chain len 1) = %+v, want nil", got)
		}
	})

	t.Run("chain length 1 with non-CA self-signed cert produces Info finding", func(t *testing.T) {
		// Create a self-signed cert WITHOUT IsCA or BasicConstraintsValid set.
		// The old CheckSignatureFrom path would miss this; the new path detects it.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(100),
			Subject:      pkix.Name{CommonName: "leaf-self-signed.example.com"},
			Issuer:       pkix.Name{CommonName: "leaf-self-signed.example.com"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			IsCA:         false,
			KeyUsage:     0,
		}
		certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			t.Fatalf("CreateCertificate: %v", err)
		}
		leaf, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}
		chain := []*x509.Certificate{leaf}

		got := checkSelfSignedCert(leaf, chain)
		if got == nil {
			t.Fatal("checkSelfSignedCert(non-CA self-signed) = nil, want non-nil finding")
		}
		if got.ID != "tls-self-signed" {
			t.Errorf("finding.ID = %q, want %q", got.ID, "tls-self-signed")
		}
		if got.Severity != SeverityInfo {
			t.Errorf("finding.Severity = %q, want %q", got.Severity, SeverityInfo)
		}
	})
}

// ---------------------------------------------------------------------------
// TestCheckWeakKey
// ---------------------------------------------------------------------------

// TestCheckWeakKey exercises checkWeakKey for RSA, ECDSA, and Ed25519 keys at
// various bit lengths. We generate actual keys to exercise the real code path.
func TestCheckWeakKey(t *testing.T) {
	// ---- RSA ----------------------------------------------------------------

	t.Run("RSA 1024-bit key produces Medium finding", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("rsa.GenerateKey(1024): %v", err)
		}
		cert := x509CertWithPublicKey(t, &key.PublicKey)
		got := checkWeakKey(cert)
		if got == nil {
			t.Fatal("checkWeakKey(RSA-1024) = nil, want non-nil finding")
		}
		if got.ID != "tls-weak-key" {
			t.Errorf("finding.ID = %q, want %q", got.ID, "tls-weak-key")
		}
		if got.Severity != SeverityMedium {
			t.Errorf("finding.Severity = %q, want %q", got.Severity, SeverityMedium)
		}
		if !strings.Contains(got.Evidence, "RSA") {
			t.Errorf("finding.Evidence = %q, want it to contain %q", got.Evidence, "RSA")
		}
		if !strings.Contains(got.Evidence, "1024") {
			t.Errorf("finding.Evidence = %q, want it to contain %q", got.Evidence, "1024")
		}
	})

	t.Run("RSA 2048-bit key produces no finding", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey(2048): %v", err)
		}
		cert := x509CertWithPublicKey(t, &key.PublicKey)
		got := checkWeakKey(cert)
		if got != nil {
			t.Errorf("checkWeakKey(RSA-2048) = %+v, want nil", got)
		}
	})

	t.Run("RSA 4096-bit key produces no finding", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			t.Fatalf("rsa.GenerateKey(4096): %v", err)
		}
		cert := x509CertWithPublicKey(t, &key.PublicKey)
		got := checkWeakKey(cert)
		if got != nil {
			t.Errorf("checkWeakKey(RSA-4096) = %+v, want nil", got)
		}
	})

	// ---- ECDSA --------------------------------------------------------------

	t.Run("ECDSA P-224 (224 bits) produces Medium finding", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey(P-224): %v", err)
		}
		cert := x509CertWithPublicKey(t, &key.PublicKey)
		got := checkWeakKey(cert)
		if got == nil {
			t.Fatal("checkWeakKey(ECDSA-P224) = nil, want non-nil finding")
		}
		if got.ID != "tls-weak-key" {
			t.Errorf("finding.ID = %q, want %q", got.ID, "tls-weak-key")
		}
		if got.Severity != SeverityMedium {
			t.Errorf("finding.Severity = %q, want %q", got.Severity, SeverityMedium)
		}
		if !strings.Contains(got.Evidence, "EC") {
			t.Errorf("finding.Evidence = %q, want it to contain %q", got.Evidence, "EC")
		}
		if !strings.Contains(got.Evidence, "224") {
			t.Errorf("finding.Evidence = %q, want it to contain %q", got.Evidence, "224")
		}
	})

	t.Run("ECDSA P-256 (256 bits) produces no finding", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey(P-256): %v", err)
		}
		cert := x509CertWithPublicKey(t, &key.PublicKey)
		got := checkWeakKey(cert)
		if got != nil {
			t.Errorf("checkWeakKey(ECDSA-P256) = %+v, want nil", got)
		}
	})

	// ---- Ed25519 ------------------------------------------------------------

	t.Run("Ed25519 key produces no finding", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		cert := x509CertWithPublicKey(t, pubKey)
		got := checkWeakKey(cert)
		if got != nil {
			t.Errorf("checkWeakKey(Ed25519) = %+v, want nil", got)
		}
	})

	// ---- DSA ----------------------------------------------------------------

	t.Run("DSA key produces Medium finding", func(t *testing.T) {
		params := new(dsa.Parameters)
		if err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160); err != nil {
			t.Fatalf("dsa.GenerateParameters: %v", err)
		}
		key := new(dsa.PrivateKey)
		key.Parameters = *params
		if err := dsa.GenerateKey(key, rand.Reader); err != nil {
			t.Fatalf("dsa.GenerateKey: %v", err)
		}
		cert := &x509.Certificate{PublicKey: &key.PublicKey}
		got := checkWeakKey(cert)
		if got == nil {
			t.Fatal("checkWeakKey(DSA) = nil, want non-nil finding")
		}
		if got.ID != "tls-weak-key" {
			t.Errorf("finding.ID = %q, want %q", got.ID, "tls-weak-key")
		}
		if got.Severity != SeverityMedium {
			t.Errorf("finding.Severity = %q, want %q", got.Severity, SeverityMedium)
		}
		if !strings.Contains(got.Evidence, "DSA") {
			t.Errorf("finding.Evidence = %q, want it to contain %q", got.Evidence, "DSA")
		}
	})
}

// ---------------------------------------------------------------------------
// TestTLSVersionName
// ---------------------------------------------------------------------------

// TestTLSVersionName verifies the human-readable label returned for each
// known TLS version constant and for an unrecognised value.
func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		version  uint16
		wantName string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0300, "unknown (0x0300)"}, // SSL 3.0 – unrecognised
		{0xffff, "unknown (0xffff)"}, // arbitrary unknown value
	}

	for _, tc := range tests {
		got := TLSVersionName(tc.version)
		if got != tc.wantName {
			t.Errorf("TLSVersionName(0x%04x) = %q, want %q", tc.version, got, tc.wantName)
		}
	}
}

// ---------------------------------------------------------------------------
// TestCheckTLS_Integration
// ---------------------------------------------------------------------------

// TestCheckTLS_Integration runs CheckTLS against real in-process TLS
// connections and verifies the combined set of findings.
func TestCheckTLS_Integration(t *testing.T) {
	t.Run("self-signed cert with TLS 1.2 and P256 key produces exactly 1 finding (self-signed only)", func(t *testing.T) {
		cert := generateSelfSignedTLSCert(t)
		conn := makeTLSConn(t, cert, tls.VersionTLS12)

		findings := CheckTLS(conn)

		// We expect exactly one finding: tls-self-signed.
		// TLS 1.2 is not weak, and P-256 is not a weak key.
		if len(findings) != 1 {
			t.Fatalf("CheckTLS() returned %d findings, want 1: %+v", len(findings), findings)
		}
		if findings[0].ID != "tls-self-signed" {
			t.Errorf("findings[0].ID = %q, want %q", findings[0].ID, "tls-self-signed")
		}
	})

	t.Run("self-signed cert with TLS 1.0 produces 2 findings (weak version + self-signed)", func(t *testing.T) {
		cert := generateSelfSignedTLSCert(t)
		conn := makeTLSConn(t, cert, tls.VersionTLS10)

		findings := CheckTLS(conn)

		if len(findings) != 2 {
			t.Fatalf("CheckTLS() returned %d findings, want 2: %+v", len(findings), findings)
		}

		ids := make(map[string]bool)
		for _, f := range findings {
			ids[f.ID] = true
		}
		if !ids["tls-weak-version"] {
			t.Errorf("expected tls-weak-version finding in: %+v", findings)
		}
		if !ids["tls-self-signed"] {
			t.Errorf("expected tls-self-signed finding in: %+v", findings)
		}
	})

	t.Run("self-signed cert with TLS 1.1 produces 2 findings (weak version + self-signed)", func(t *testing.T) {
		cert := generateSelfSignedTLSCert(t)
		conn := makeTLSConn(t, cert, tls.VersionTLS11)

		findings := CheckTLS(conn)

		if len(findings) != 2 {
			t.Fatalf("CheckTLS() returned %d findings, want 2: %+v", len(findings), findings)
		}

		ids := make(map[string]bool)
		for _, f := range findings {
			ids[f.ID] = true
		}
		if !ids["tls-weak-version"] {
			t.Errorf("expected tls-weak-version finding in: %+v", findings)
		}
		if !ids["tls-self-signed"] {
			t.Errorf("expected tls-self-signed finding in: %+v", findings)
		}
	})

	t.Run("self-signed cert with TLS 1.3 produces exactly 1 finding (self-signed only)", func(t *testing.T) {
		cert := generateSelfSignedTLSCert(t)
		conn := makeTLSConn(t, cert, tls.VersionTLS13)

		findings := CheckTLS(conn)

		if len(findings) != 1 {
			t.Fatalf("CheckTLS() returned %d findings, want 1: %+v", len(findings), findings)
		}
		if findings[0].ID != "tls-self-signed" {
			t.Errorf("findings[0].ID = %q, want %q", findings[0].ID, "tls-self-signed")
		}
	})

	t.Run("weak RSA key with TLS 1.2 produces tls-weak-key and tls-self-signed", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("rsa.GenerateKey(1024): %v", err)
		}
		cert := makeTLSCertWithKey(t, key, &key.PublicKey)
		conn := makeTLSConn(t, cert, tls.VersionTLS12)

		findings := CheckTLS(conn)

		ids := make(map[string]bool)
		for _, f := range findings {
			ids[f.ID] = true
		}
		if !ids["tls-weak-key"] {
			t.Errorf("expected tls-weak-key finding in: %+v", findings)
		}
		if !ids["tls-self-signed"] {
			t.Errorf("expected tls-self-signed finding in: %+v", findings)
		}
	})
}

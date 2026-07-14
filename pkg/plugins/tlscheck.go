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
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// CheckTLS inspects the TLS connection state and returns security findings for
// weak versions, expired certificates, self-signed certificates, and weak keys.
// Returns nil if conn is not a *tls.Conn or no issues are found.
func CheckTLS(conn net.Conn) []SecurityFinding {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}
	state := tlsConn.ConnectionState()

	var findings []SecurityFinding

	if f := checkWeakTLSVersion(state.Version); f != nil {
		findings = append(findings, *f)
	}

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		if f := checkExpiredCert(leaf); f != nil {
			findings = append(findings, *f)
		}
		if f := checkSelfSignedCert(leaf, state.PeerCertificates); f != nil {
			findings = append(findings, *f)
		}
		if f := checkWeakKey(leaf); f != nil {
			findings = append(findings, *f)
		}
	}

	if len(findings) == 0 {
		return nil
	}
	return findings
}

// TLSVersionName returns a human-readable label for a TLS version constant.
// Exported because HTTP's http.go uses it too.
func TLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}

func checkWeakTLSVersion(version uint16) *SecurityFinding {
	switch version {
	case tls.VersionTLS10:
		return &SecurityFinding{
			ID:          "tls-weak-version",
			Severity:    SeverityMedium,
			Description: "Server negotiated TLS 1.0, which has known vulnerabilities (BEAST, POODLE)",
			Evidence:    "negotiated_version=" + TLSVersionName(version),
		}
	case tls.VersionTLS11:
		return &SecurityFinding{
			ID:          "tls-weak-version",
			Severity:    SeverityLow,
			Description: "Server negotiated TLS 1.1, which is deprecated (RFC 8996)",
			Evidence:    "negotiated_version=" + TLSVersionName(version),
		}
	default:
		return nil
	}
}

func checkExpiredCert(cert *x509.Certificate) *SecurityFinding {
	now := time.Now()
	if cert.NotAfter.After(now) {
		return nil
	}
	daysSince := int(now.Sub(cert.NotAfter).Hours() / 24)
	return &SecurityFinding{
		ID:          "tls-certificate-expired",
		Severity:    SeverityLow,
		Description: "TLS certificate has expired, indicating an abandoned or unmaintained service",
		Evidence:    fmt.Sprintf("subject=%q, expired=%s, days_since_expiry=%d", cert.Subject.CommonName, cert.NotAfter.UTC().Format("2006-01-02"), daysSince),
	}
}

func checkSelfSignedCert(leaf *x509.Certificate, chain []*x509.Certificate) *SecurityFinding {
	if len(chain) != 1 {
		return nil
	}
	if !bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
		return nil
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		return nil
	}
	return &SecurityFinding{
		ID:          "tls-self-signed",
		Severity:    SeverityInfo,
		Description: "TLS certificate is self-signed, which may indicate trust chain issues or potential for MITM attacks",
		Evidence:    fmt.Sprintf("subject=%q, issuer=%q", leaf.Subject.CommonName, leaf.Issuer.CommonName),
	}
}

func checkWeakKey(cert *x509.Certificate) *SecurityFinding {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return &SecurityFinding{
				ID:          "tls-weak-key",
				Severity:    SeverityMedium,
				Description: "TLS certificate uses an RSA key smaller than the NIST recommended minimum of 2048 bits",
				Evidence:    fmt.Sprintf("key_type=RSA, key_size=%d", key.N.BitLen()),
			}
		}
	case *ecdsa.PublicKey:
		if key.Curve.Params().BitSize < 256 {
			return &SecurityFinding{
				ID:          "tls-weak-key",
				Severity:    SeverityMedium,
				Description: "TLS certificate uses an EC key smaller than the NIST recommended minimum of 256 bits",
				Evidence:    fmt.Sprintf("key_type=EC, key_size=%d", key.Curve.Params().BitSize),
			}
		}
	case *dsa.PublicKey:
		return &SecurityFinding{
			ID:          "tls-weak-key",
			Severity:    SeverityMedium,
			Description: "TLS certificate uses a DSA key, which is deprecated (NIST FIPS 186-5)",
			Evidence:    fmt.Sprintf("key_type=DSA, key_size=%d", key.P.BitLen()),
		}
	}
	return nil
}

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
Package anydesk implements service detection for AnyDesk remote desktop via TLS certificate inspection.

# Detection Strategy

AnyDesk listens on TCP 7070 with immediate TLS (no plaintext banner).
Every AnyDesk installation generates a self-signed certificate with:

  - Subject CN: "AnyDesk Client"
  - Issuer CN:  "AnyDesk Client" (self-signed)
  - Validity:   ~50 years
  - Key:        RSA 2048-bit

Detection is performed by completing a TLS handshake and inspecting the
peer certificate's Subject CommonName. This is the same method used by
Shodan and Censys for AnyDesk detection.

Version is not extractable from the protocol or certificate.

# Security Relevance

  - Unauthorized remote access capability
  - Commonly used by threat actors for persistence and lateral movement
  - Credential theft via saved connection profiles
  - Often exposed without strong authentication

# Ports

  - 7070: Default TCP/TLS port (primary detection target)
  - 6568: Alternative relay port
*/
package anydesk

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const ANYDESK = "anydesk"

// AnyDeskPlugin detects AnyDesk remote desktop via TLS certificate CN.
type AnyDeskPlugin struct{}

func init() {
	plugins.RegisterPlugin(&AnyDeskPlugin{})
}

func (p *AnyDeskPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// The scanner's DialTLS already completed the TLS handshake.
	// Type-assert to access certificate data.
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, nil
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, nil
	}

	cert := state.PeerCertificates[0]

	// AnyDesk uses "AnyDesk Client" as the Subject CN on its self-signed cert.
	if cert.Subject.CommonName != "AnyDesk Client" {
		return nil, nil
	}

	// Confirm self-signed: issuer CN matches subject CN.
	selfSigned := cert.Issuer.CommonName == "AnyDesk Client"

	payload := plugins.ServiceAnyDesk{
		CertSubject: cert.Subject.CommonName,
		SelfSigned:  selfSigned,
		CPEs:        []string{buildAnyDeskCPE("")},
	}

	return plugins.CreateServiceFrom(target, payload, true, "", plugins.TCPTLS), nil
}

func (p *AnyDeskPlugin) PortPriority(port uint16) bool {
	return port == 7070 || port == 6568
}

func (p *AnyDeskPlugin) Name() string {
	return ANYDESK
}

func (p *AnyDeskPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *AnyDeskPlugin) Priority() int {
	return 175
}

func buildAnyDeskCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:anydesk:anydesk:%s:*:*:*:*:*:*:*", version)
}

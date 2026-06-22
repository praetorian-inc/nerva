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

package smbudp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// SMB over QUIC detection plugin.
//
// Uses quic-go to perform a QUIC handshake with ALPN "smb" (MS-SMB2 spec).
// This definitively identifies SMB over QUIC services, distinguishing them
// from HTTP/3 or other QUIC applications on port 443/UDP.
//
// References:
//   - MS-SMB2 Standards Assignments: ALPN "smb" (0x73 0x6D 0x62)
//   - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/7c797860-a3e3-4b47-a45d-625462a1fdf3

const (
	smbudpPort     = 443
	smbudpPriority = 2099 // Before generic QUIC plugin (2100); more specific check runs first
	alpnSMB        = "smb"
)

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return smbudpPriority
}

func (p *Plugin) PortPriority(port uint16) bool {
	return port == smbudpPort
}

func (p *Plugin) Name() string {
	return "smbudp"
}

// Run attempts a QUIC connection with ALPN "smb" to detect SMB over QUIC.
//
// The passed net.Conn is not used because quic-go manages its own UDP transport.
// Instead, we dial directly using the target address.
func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	addr := target.Address.String()
	if addr == "" {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	tlsConf := &tls.Config{ //nolint:gosec // G402: InsecureSkipVerify required for scanning unknown hosts
		NextProtos:         []string{alpnSMB},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13, // QUIC mandates TLS 1.3
	}

	quicConn, err := quic.DialAddr(ctx, addr, tlsConf, nil)
	if err != nil {
		// Connection failed -- either no QUIC, or QUIC is there but ALPN
		// "smb" is not supported (e.g., it's HTTP/3 with ALPN "h3").
		return nil, nil
	}
	defer quicConn.CloseWithError(0, "")

	// Extract TLS state for metadata
	tlsState := quicConn.ConnectionState().TLS

	metadata := plugins.ServiceSMBUDP{}

	// Require explicit ALPN "smb" negotiation to avoid false positives
	if tlsState.NegotiatedProtocol != alpnSMB {
		return nil, nil
	}

	// Extract certificate information
	if len(tlsState.PeerCertificates) > 0 {
		cert := tlsState.PeerCertificates[0]
		metadata.CertSubject = cert.Subject.String()
		metadata.CertIssuer = cert.Issuer.String()
	}

	// Report supported QUIC versions from the connection
	metadata.QUICVersions = []string{fmt.Sprintf("0x%08X", quicConn.ConnectionState().Version)}

	return plugins.CreateServiceFrom(target, metadata, true, "", plugins.UDP), nil
}

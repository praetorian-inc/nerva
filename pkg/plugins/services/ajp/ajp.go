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
Package ajp implements service detection for Apache JServ Protocol (AJPv13).

Detection Strategy:
 1. Sends a 5-byte CPing frame (code 0x0A): 0x12 0x34 0x00 0x01 0x0A
 2. Validates the 5-byte CPong response (code 0x09): 0x41 0x42 0x00 0x01 0x09
 3. Returns Service with Apache Tomcat wildcard CPE if CPong is received.

Security invariant: this plugin only validates the 5-byte CPong magic and
MUST NOT parse AJP payload bytes. It never sends FORWARD_REQUEST (code 2),
which is the Ghostcat (CVE-2020-1938) code path. CPing is a documented
keepalive that is explicitly not gated by secretRequired.

Connection lifecycle: the scan engine (pkg/scan/simple_scan.go) owns the
connection and calls defer conn.Close() unconditionally after Run returns.
This plugin MUST NOT call conn.Close(), conn.SetDeadline, conn.SetReadDeadline,
or conn.SetWriteDeadline.
*/
package ajp

import (
	"bytes"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	// AJPCPEMatch is the Apache Tomcat wildcard CPE emitted on AJP detection.
	// CPong carries no version data, so the version field is always wildcarded.
	AJPCPEMatch = "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"
)

// cpingProbe is the 5-byte AJPv13 CPing frame (code 0x0A).
// Client-to-server magic: 0x12 0x34. Payload length: 1. Code: 0x0A (CPING).
var cpingProbe = []byte{0x12, 0x34, 0x00, 0x01, 0x0a}

// cpongExpected is the 5-byte AJPv13 CPong frame (code 0x09) we expect.
// Server-to-client magic: 0x41 0x42 ("AB"). Payload length: 1. Code: 0x09 (CPONG_REPLY).
var cpongExpected = []byte{0x41, 0x42, 0x00, 0x01, 0x09}

// Plugin implements TCP AJP service detection.
type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// DetectAJP probes conn with a CPing frame and validates the CPong response.
// Returns (true, nil) on a valid CPong; (false, nil) on any non-AJP response;
// (false, err) on a transport-level error that the caller should propagate.
func DetectAJP(conn net.Conn, timeout time.Duration) (bool, error) {
	resp, err := utils.SendRecv(conn, cpingProbe, timeout)
	if err != nil {
		return false, err
	}

	// Empty read: server closed immediately or is not AJP.
	if len(resp) == 0 {
		return false, nil
	}

	// Guard against short reads before indexing — the single most important
	// guardrail against a panic on a truncated response.
	if len(resp) < 5 {
		return false, nil
	}

	// Validate first 5 bytes against the exact CPong magic.
	// bytes.Equal checks all 5 bytes atomically, including the length field
	// (bytes 2-3 == 0x00 0x01) and code byte (byte 4 == 0x09).
	// Extra trailing bytes are intentionally ignored.
	if !bytes.Equal(resp[:5], cpongExpected) {
		return false, nil
	}

	return true, nil
}

// Run implements plugins.Plugin for AJP service detection.
func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	detected, err := DetectAJP(conn, timeout)
	if err != nil {
		// Swallow all "not-this-protocol" sentinels including transport errors
		// (ReadError/WriteError) that indicate the server closed early without
		// speaking AJP. This mirrors the security review "simple form":
		// any error from SendRecv means the service is not AJP.
		if _, ok := err.(*utils.ServerNotEnable); ok {
			return nil, nil
		}
		if _, ok := err.(*utils.InvalidResponseError); ok {
			return nil, nil
		}
		if _, ok := err.(*utils.ReadError); ok {
			return nil, nil
		}
		if _, ok := err.(*utils.WriteError); ok {
			return nil, nil
		}
		return nil, err
	}

	if !detected {
		return nil, nil
	}

	// CPong code 0x09 (CPONG_REPLY) is AJPv13-specific, so a successful
	// match implies protocol version "1.3". CPingEnabled is always true on a
	// positive detection — documents the detection method for downstream
	// risk rules and honors the LAB-1842 "Metadata to Extract" spec.
	payload := plugins.ServiceAJP{
		ProtocolVersion: "1.3",
		CPingEnabled:    true,
		CPEs:            []string{AJPCPEMatch},
	}

	return plugins.CreateServiceFrom(target, payload, false, "1.3", plugins.TCP), nil
}

// PortPriority returns true for the standard AJP port 8009.
func (p *Plugin) PortPriority(port uint16) bool {
	return port == 8009
}

// Name returns the protocol identifier for this plugin.
func (p *Plugin) Name() string {
	return plugins.ProtoAJP
}

// Type returns the transport protocol (TCP).
func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the plugin priority (100, matching cassandra/activemq).
func (p *Plugin) Priority() int {
	return 100
}

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

// Package mikrotikwinbox detects MikroTik RouterOS Winbox and API services.
//
// Detection Strategy:
//
// Port 8291 (Winbox):
// Winbox is MikroTik's proprietary management protocol. On connection, the server
// sends a 2-byte magic identifier: 0x4D ('M'), 0x32 ('2') — the "M2" framing header.
// Detection reads the initial bytes and checks for this magic.
//
// Port 8728 (API):
// The MikroTik API uses a sentence-based wire protocol. Each sentence consists of
// words delimited by length-prefixed strings terminated with zero-length end-of-sentence
// words. A minimal probe "/\x00" (word "/" followed by empty end-of-sentence) triggers
// a response that contains zero bytes as sentence terminators.
//
// Security Risks:
//   - CVE-2018-14847: Winbox (port 8291) allows unauthenticated credential disclosure
//   - Exposed API port allows brute-force of credentials
//   - Default admin account with empty password is common
//   - RouterOS < 6.49.7 / 7.x < 7.8 have known RCE vulnerabilities
package mikrotikwinbox

import (
	"bytes"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/plugins/fingerprinters"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

// MikroTik service constants.
const (
	MIKROTIK_WINBOX    = "mikrotik-winbox"
	DefaultWinboxPort  = 8291
	DefaultAPIPort     = 8728
)

// Winbox M2 magic bytes: the first two bytes of a Winbox server response.
const (
	winboxMagicByte0 = 0x4D // 'M'
	winboxMagicByte1 = 0x32 // '2'
)

// MikroTikWinboxPlugin detects MikroTik RouterOS Winbox and API services.
type MikroTikWinboxPlugin struct{}

func init() {
	plugins.RegisterPlugin(&MikroTikWinboxPlugin{})
}

// Run performs two-phase detection based on port.
// Phase 1: Detect protocol (Winbox M2 magic or API sentence framing).
// Phase 2: Return service with sub_protocol metadata.
func (p *MikroTikWinboxPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	port := target.Address.Port()

	switch port {
	case DefaultWinboxPort:
		return detectWinbox(conn, timeout, target)
	case DefaultAPIPort:
		return detectAPI(conn, timeout, target)
	default:
		// Do not attempt detection on non-priority ports to avoid false positives.
		// The M2 magic (2 bytes) is too weak for reliable detection on arbitrary ports.
		return nil, nil
	}
}

// detectWinbox reads initial bytes and checks for the M2 magic header.
func detectWinbox(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		// Treat read errors (including EOF on empty connections) as no match.
		return nil, nil
	}

	if len(response) < 2 {
		return nil, nil
	}

	// Check for M2 magic: first byte == 'M' (0x4D), second byte == '2' (0x32).
	if response[0] != winboxMagicByte0 || response[1] != winboxMagicByte1 {
		return nil, nil
	}

	payload := plugins.ServiceMikroTikWinbox{
		SubProtocol: "winbox",
		CPEs:        []string{fingerprinters.BuildMikroTikRouterOSCPE("")},
	}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

// detectAPI sends a minimal probe and checks for MikroTik API reply words.
// Sending an invalid command "/" triggers a !trap response with error details.
func detectAPI(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Minimal probe: word "/" followed by zero-length end-of-sentence.
	// Length prefix 0x01 = 1 byte, "/" is the word, 0x00 = end of sentence.
	probe := []byte{0x01, '/', 0x00}

	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		// Treat read errors (including EOF on empty connections) as no match.
		return nil, nil
	}

	if len(response) == 0 {
		return nil, nil
	}

	// MikroTik API responds to invalid commands with !trap or valid commands with !done.
	// These reply words are length-prefixed: 0x05 followed by "!trap" or "!done".
	// Checking for these specific words avoids false positives from other binary protocols
	// that happen to contain zero bytes.
	if !bytes.Contains(response, []byte("!trap")) && !bytes.Contains(response, []byte("!done")) {
		return nil, nil
	}

	payload := plugins.ServiceMikroTikWinbox{
		SubProtocol: "api",
		CPEs:        []string{fingerprinters.BuildMikroTikRouterOSCPE("")},
	}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}


func (p *MikroTikWinboxPlugin) PortPriority(port uint16) bool {
	return port == DefaultWinboxPort || port == DefaultAPIPort
}

func (p *MikroTikWinboxPlugin) Name() string {
	return MIKROTIK_WINBOX
}

func (p *MikroTikWinboxPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *MikroTikWinboxPlugin) Priority() int {
	return 100
}

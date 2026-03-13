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
Package citrixica implements service detection for Citrix ICA (Independent Computing Architecture).

# Detection Strategy

Citrix ICA is a server-speaks-first protocol on TCP port 1494. Upon TCP connection,
the server immediately sends the banner bytes:

	\x7f\x7f ICA \x00 (repeated)

The pattern is two DEL bytes (0x7F), the ASCII string "ICA", and a null terminator,
repeated continuously. This is the same signature used by nmap's NULL probe:

	match citrix-ica m|^\x7f\x7fICA\0\x7f\x7fICA\0|

No client probe packet is needed — detection is pure banner-grab.

# Security Relevance

  - VDI access — potential entry to corporate desktops
  - Known CVEs — CVE-2023-3519 (RCE), CVE-2023-3466, CVE-2023-3467
  - Credential harvesting — login pages for brute-force
  - Network pivot — gateway to internal networks

# Ports

  - 1494: Default ICA listener (primary detection target)
  - 2598: CGP (Common Gateway Protocol) for session reliability
*/
package citrixica

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const CITRIXICA = "citrix-ica"

// icaSignature is the 6-byte ICA banner unit: 0x7F 0x7F "ICA" 0x00
var icaSignature = []byte{0x7f, 0x7f, 0x49, 0x43, 0x41, 0x00}

// CitrixICAPlugin detects Citrix ICA via banner-grab on port 1494.
type CitrixICAPlugin struct{}

func init() {
	plugins.RegisterPlugin(&CitrixICAPlugin{})
}

func (p *CitrixICAPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// ICA is server-speaks-first — just read the banner.
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Match the ICA signature at the start of the response.
	// Minimum 6 bytes: \x7f\x7f ICA \x00
	if len(response) < len(icaSignature) {
		return nil, nil
	}
	if !bytes.HasPrefix(response, icaSignature) {
		return nil, nil
	}

	// Check for the repeated pattern (12 bytes) for higher confidence.
	doubleMatch := len(response) >= 2*len(icaSignature) &&
		bytes.Equal(response[len(icaSignature):2*len(icaSignature)], icaSignature)

	payload := plugins.ServiceCitrixICA{
		BannerMatch: doubleMatch,
		CPEs:        []string{buildCitrixCPE("")},
	}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

func (p *CitrixICAPlugin) PortPriority(port uint16) bool {
	return port == 1494 || port == 2598
}

func (p *CitrixICAPlugin) Name() string {
	return CITRIXICA
}

func (p *CitrixICAPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *CitrixICAPlugin) Priority() int {
	return 175
}

func buildCitrixCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:citrix:virtual_apps_and_desktops:%s:*:*:*:*:*:*:*", version)
}

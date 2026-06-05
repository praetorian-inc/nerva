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
OpenVPN Management Interface Detection

The OpenVPN management interface is a TCP service that exposes runtime control
of an OpenVPN process. It is intended for local administration and is frequently
misconfigured to listen on all interfaces.

Detection Strategy:
  The management interface sends a banner immediately on connection:
    >INFO:OpenVPN Management Interface Version 5 -- type 'help' for more information

  No probe is required. The plugin reads the banner and checks for the
  >INFO:OpenVPN Management Interface substring.

Security Relevance:
  - Allows unauthenticated enumeration of VPN state (clients, routes, status)
  - Can be used to disconnect clients or inject routes depending on configuration
  - Exposure indicates the VPN process itself is directly reachable

Ports:
  - 7505: Default management port
  - 1195: Alternative port used in some deployments
*/
package openvpn

import (
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

var mgmtBannerRegex = regexp.MustCompile(`>INFO:OpenVPN Management Interface Version (\d+)`)

// ManagementPlugin detects the OpenVPN management interface via its TCP banner.
type ManagementPlugin struct{}

func init() {
	plugins.RegisterPlugin(&ManagementPlugin{})
}

func (p *ManagementPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Management interface sends banner immediately on connect — no probe needed.
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	banner := string(response)
	if !strings.Contains(banner, ">INFO:OpenVPN Management Interface") {
		return nil, nil
	}

	var version string
	if matches := mgmtBannerRegex.FindStringSubmatch(banner); len(matches) >= 2 {
		version = matches[1]
	}

	sanitized := sanitizePrintable(strings.TrimSpace(banner))

	payload := plugins.ServiceOpenVPNManagement{
		Version: version,
		Banner:  sanitized,
		CPEs:    []string{buildOpenVPNCPE("")},
	}

	service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)
	if target.Misconfigs {
		service.SecurityFindings = []plugins.SecurityFinding{{
			ID:          "openvpn-management-exposed",
			Severity:    plugins.SeverityHigh,
			Description: "OpenVPN management interface exposed to the network",
			Evidence:    sanitized,
		}}
	}
	return service, nil
}

func sanitizePrintable(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x20 && s[i] < 0x7F {
			b = append(b, s[i])
		}
	}
	return string(b)
}

func (p *ManagementPlugin) PortPriority(port uint16) bool {
	return port == 7505 || port == 1195
}

func (p *ManagementPlugin) Name() string {
	return plugins.ProtoOpenVPNManagement
}

func (p *ManagementPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *ManagementPlugin) Priority() int {
	return 100
}

func buildOpenVPNCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return "cpe:2.3:a:openvpn:openvpn:" + version + ":*:*:*:*:*:*:*"
}

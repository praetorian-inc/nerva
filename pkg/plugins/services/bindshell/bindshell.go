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

// Package bindshell fingerprints unauthenticated bind-shell banners and
// nmap-style BACKDOOR service labels. Detection is receive-only: the plugin
// never writes to the connection (no probes, no exploit commands).
package bindshell

import (
	"bytes"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	protocolName = "bind-shell"
	findingID    = "malware-backdoor"
)

var (
	noJobControl = []byte("no job control in this shell")
	nmapBackdoor = []byte("**BACKDOOR**")
	// Line-anchored bash prompt (ticket fixture bash-*#). Unanchored matching
	// would fire on package tags and Server headers.
	bashPrompt = regexp.MustCompile(`(?m)^bash-[0-9][\w.-]*#`)
)

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Name() string { return protocolName }

func (p *Plugin) Type() plugins.Protocol { return plugins.TCP }

// Priority is negative so this Recv-only detector runs before HTTP/Echo
// probes that write to the connection (simple_scan sorts ascending).
func (p *Plugin) Priority() int { return -1 }

// PortPriority is always false: bind-shells and BACKDOOR labels are not a
// well-known port identity.
func (p *Plugin) PortPriority(uint16) bool { return false }

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	kind, ok := classify(response)
	if !ok {
		return nil, nil
	}

	payload := plugins.ServiceBindShell{
		Banner: string(bytes.TrimSpace(response)),
		Kind:   kind,
		CPEs:   []string{"cpe:2.3:a:*:bind_shell:-:*:*:*:*:*:*:*"},
	}
	if kind == "backdoor" {
		payload.CPEs = []string{"cpe:2.3:a:*:backdoor:-:*:*:*:*:*:*:*"}
	}

	service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)
	service.SecurityFindings = []plugins.SecurityFinding{{
		ID:          findingID,
		Severity:    plugins.SeverityCritical,
		Description: "Unauthenticated bind-shell or BACKDOOR service label on the wire",
		Evidence:    payload.Banner,
	}}
	return service, nil
}

func classify(banner []byte) (kind string, ok bool) {
	if bytes.Contains(bytes.ToLower(banner), noJobControl) {
		return "bind-shell", true
	}
	if bashPrompt.Match(banner) {
		return "bind-shell", true
	}
	if bytes.Contains(bytes.ToUpper(banner), nmapBackdoor) {
		return "backdoor", true
	}
	// Ticket AC: Port service label is `backdoor` — the whole trimmed banner,
	// not a word embedded in a MOTD or hostname.
	if strings.EqualFold(strings.TrimSpace(string(banner)), "backdoor") {
		return "backdoor", true
	}
	return "", false
}

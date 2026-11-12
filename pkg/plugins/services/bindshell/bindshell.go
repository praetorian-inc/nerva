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
	"unicode"

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
	bashPrompt   = regexp.MustCompile(`bash-[^\s]*#`)
)

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Name() string { return protocolName }

func (p *Plugin) Type() plugins.Protocol { return plugins.TCP }

func (p *Plugin) Priority() int { return 80 }

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
	lower := bytes.ToLower(banner)
	if bytes.Contains(lower, bytes.ToLower(noJobControl)) {
		return "bind-shell", true
	}
	if bashPrompt.Match(banner) {
		return "bind-shell", true
	}
	if bytes.Contains(bytes.ToUpper(banner), nmapBackdoor) {
		return "backdoor", true
	}
	if hasBackdoorWord(string(lower)) {
		return "backdoor", true
	}
	return "", false
}

func hasBackdoorWord(lower string) bool {
	const word = "backdoor"
	for {
		i := strings.Index(lower, word)
		if i < 0 {
			return false
		}
		leftOK := i == 0 || !unicode.IsLetter(rune(lower[i-1]))
		right := i + len(word)
		rightOK := right == len(lower) || !unicode.IsLetter(rune(lower[right]))
		if leftOK && rightOK {
			return true
		}
		lower = lower[i+len(word):]
	}
}

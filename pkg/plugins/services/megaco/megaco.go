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

package megaco

import (
	"bytes"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const MEGACO = "megaco"

// Plugin implements the fingerprintx plugin interface for MEGACO/H.248
// media gateway control protocol detection via text-mode ServiceChange probe.
type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// probeMessage is a MEGACO/1 ServiceChange request in text mode (pretty format).
// It mimics a Media Gateway cold boot registration to an MGC.
var probeMessage = []byte("MEGACO/1 [0.0.0.0]\nTransaction = 1 {\n  Context = - {\n    ServiceChange = ROOT {\n      Services {\n        Method = Restart,\n        Reason = \"901 Cold Boot\"\n      }\n    }\n  }\n}\n")

// prettyPattern matches MEGACO pretty format: MEGACO/<version> [<mid>]
var prettyPattern = regexp.MustCompile(`(?i)^MEGACO/(\d+)\s*\[([^\]]*)\]`)

// compactPattern matches MEGACO compact format: !/<version> [<mid>]
var compactPattern = regexp.MustCompile(`^!/(\d+)\s*\[([^\]]*)\]`)

// profilePattern extracts Profile from response
var profilePattern = regexp.MustCompile(`(?i)(?:Profile|PF)\s*=\s*([^\s,}]+)`)

// errorPattern extracts error code from response
var errorPattern = regexp.MustCompile(`(?i)(?:Error|ER)\s*=\s*(\d+)`)

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.SendRecv(conn, probeMessage, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	result := parseMegacoResponse(response)
	if result == nil {
		return nil, nil
	}

	return plugins.CreateServiceFrom(target, *result, false, result.Version, plugins.UDP), nil
}

func (p *Plugin) PortPriority(port uint16) bool {
	return port == 2944 || port == 2945
}

func (p *Plugin) Name() string {
	return MEGACO
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 90
}

// parseMegacoResponse checks if a response is a valid MEGACO message
// and extracts version, MID, profile, and error code.
func parseMegacoResponse(data []byte) *plugins.ServiceMegaco {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil
	}

	var version, mid string

	// Try pretty format first: MEGACO/<version> [<mid>]
	if matches := prettyPattern.FindSubmatch(trimmed); matches != nil {
		version = string(matches[1])
		mid = string(matches[2])
	} else if matches := compactPattern.FindSubmatch(trimmed); matches != nil {
		// Try compact format: !/<version> [<mid>]
		version = string(matches[1])
		mid = string(matches[2])
	} else {
		return nil
	}

	result := &plugins.ServiceMegaco{
		Version: version,
		MID:     strings.TrimSpace(mid),
	}

	// Extract profile if present
	if matches := profilePattern.FindSubmatch(trimmed); matches != nil {
		result.Profile = string(matches[1])
	}

	// Extract error code if present
	if matches := errorPattern.FindSubmatch(trimmed); matches != nil {
		if code, err := strconv.Atoi(string(matches[1])); err == nil {
			result.ErrorCode = code
		}
	}

	return result
}

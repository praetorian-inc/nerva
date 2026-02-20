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

package mgcp

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

// Plugin detects MGCP (Media Gateway Control Protocol) on UDP ports
// 2427 (gateway) and 2727 (call agent) via AUEP probe.
type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// probe sends an AUEP (Audit Endpoint) command with wildcard endpoint and
// transaction ID 9 to elicit any valid MGCP response.
var probe = []byte("AUEP 9 * MGCP 1.0\r\n\r\n")

// responsePattern validates that the first line of the response is a valid
// MGCP response: 3-digit code, space, transaction ID 9, optional commentary.
var responsePattern = regexp.MustCompile(`^\d{3}\s+9(\s+.*)?$`)

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	lines := strings.Split(string(response), "\r\n")
	if len(lines) == 0 {
		return nil, nil
	}

	firstLine := strings.TrimSpace(lines[0])
	if !responsePattern.MatchString(firstLine) {
		return nil, nil
	}

	// Parse the 3-digit response code from the first line.
	fields := strings.Fields(firstLine)
	if len(fields) < 2 {
		return nil, nil
	}
	responseCode, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil, nil
	}

	payload := plugins.ServiceMGCP{
		ResponseCode: responseCode,
	}

	// Parse remaining lines for Z: (endpoint) and L: (local connection options) headers.
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "Z: ") {
			endpoint := strings.TrimPrefix(line, "Z: ")
			endpoint = strings.TrimSpace(endpoint)
			if endpoint != "" {
				payload.Endpoints = append(payload.Endpoints, endpoint)
			}
		} else if strings.HasPrefix(line, "L: ") {
			// Extract v: parameter value from the L: line and split on ; for packages.
			lValue := strings.TrimPrefix(line, "L: ")
			for _, param := range strings.Split(lValue, ",") {
				param = strings.TrimSpace(param)
				if strings.HasPrefix(param, "v:") {
					vValue := strings.TrimPrefix(param, "v:")
					vValue = strings.TrimSpace(vValue)
					if vValue != "" {
						payload.Packages = strings.Split(vValue, ";")
					}
					break
				}
			}
		}
	}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
}

func (p *Plugin) PortPriority(port uint16) bool {
	return port == 2427 || port == 2727
}

func (p *Plugin) Name() string {
	return plugins.ProtoMGCP
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 90
}

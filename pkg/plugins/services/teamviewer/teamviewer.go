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

package teamviewer

import (
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type TeamViewerPlugin struct{}

const TEAMVIEWER = "TeamViewer"

// Known TeamViewer command bytes
const (
	cmdPing   = 0x10 // CMD_PING
	cmdPingOK = 0x11 // CMD_PINGOK
	cmdHelo   = 0x16 // CMD_HELO
	cmdHeloOK = 0x17 // CMD_HELOOK
)

// CMD_PING probe for TeamViewer detection
// Magic (0x1724) + CMD_PING (0x10) + Length (0x04) + Padding (0x00000000)
var cmdPingProbe = []byte{0x17, 0x24, 0x10, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}

// checkTeamViewer validates the response matches TeamViewer protocol
// TeamViewer uses magic bytes 0x1724 (primary) or 0x1130 (secondary)
// at bytes 0-1, followed by a command byte
func checkTeamViewer(data []byte) error {
	if len(data) < 3 {
		return &utils.InvalidResponseErrorInfo{
			Service: TEAMVIEWER,
			Info:    "response too short",
		}
	}

	// Check primary magic bytes (0x17 0x24)
	if data[0] == 0x17 && data[1] == 0x24 {
		switch data[2] {
		case cmdPing, cmdPingOK, cmdHelo, cmdHeloOK:
			return nil
		default:
			return &utils.InvalidResponseErrorInfo{
				Service: TEAMVIEWER,
				Info:    "unknown command byte",
			}
		}
	}

	// Check secondary magic bytes (0x11 0x30)
	if data[0] == 0x11 && data[1] == 0x30 {
		switch data[2] {
		case cmdPing, cmdPingOK, cmdHelo, cmdHeloOK:
			return nil
		default:
			return &utils.InvalidResponseErrorInfo{
				Service: TEAMVIEWER,
				Info:    "unknown command byte",
			}
		}
	}

	return &utils.InvalidResponseErrorInfo{
		Service: TEAMVIEWER,
		Info:    "invalid magic bytes",
	}
}

func init() {
	plugins.RegisterPlugin(&TeamViewerPlugin{})
}

func (p *TeamViewerPlugin) PortPriority(port uint16) bool {
	return port == 5938
}

func (p *TeamViewerPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Send CMD_PING probe and receive response
	response, err := utils.SendRecv(conn, cmdPingProbe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	err = checkTeamViewer(response)
	if err != nil {
		return nil, nil
	}

	return plugins.CreateServiceFrom(target, plugins.ServiceTeamViewer{
		CPEs: []string{"cpe:2.3:a:teamviewer:teamviewer:*:*:*:*:*:*:*:*"},
	}, false, "", plugins.TCP), nil
}

func (p *TeamViewerPlugin) Name() string {
	return TEAMVIEWER
}

func (p *TeamViewerPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *TeamViewerPlugin) Priority() int {
	return 100
}

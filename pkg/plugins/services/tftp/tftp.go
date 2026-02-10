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

package tftp

import (
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const TFTP = "tftp"

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Extract the target address before closing - needed because TFTP servers
	// respond from an ephemeral port, not port 69, so we need to create an
	// unconnected socket but still know where to send the probe.
	targetAddr := conn.RemoteAddr()
	conn.Close()

	// Create an unconnected UDP socket to accept responses from any source port
	pconn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}
	defer pconn.Close()

	// TFTP RRQ (Read Request) for non-existent file
	// RFC 1350: RRQ format: [opcode=0x00,0x01][filename][0x00][mode="octet"][0x00]
	probe := []byte{
		0x00, 0x01, // Opcode: RRQ (Read Request)
		// Filename: "nerva-probe.txt"
		0x6e, 0x65, 0x72, 0x76, 0x61, 0x2d, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x2e, 0x74, 0x78, 0x74,
		0x00, // Null terminator for filename
		// Mode: "octet"
		0x6f, 0x63, 0x74, 0x65, 0x74,
		0x00, // Null terminator for mode
	}

	response, _, err := utils.SendRecvFrom(pconn, probe, targetAddr, timeout)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, nil
	}

	// Check if response is TFTP ERROR packet (opcode 5)
	// TFTP ERROR format: [0x00,0x05][error_code_2bytes][error_msg][0x00]
	if len(response) >= 4 && response[0] == 0x00 && response[1] == 0x05 {
		// Extract error message (skip opcode and error code, find null terminator)
		errorMsg := ""
		if len(response) > 4 {
			// Error message starts at byte 4, find null terminator
			for i := 4; i < len(response); i++ {
				if response[i] == 0x00 {
					errorMsg = string(response[4:i])
					break
				}
			}
			// If no null terminator found, take rest of message
			if errorMsg == "" {
				errorMsg = string(response[4:])
			}
		}

		payload := plugins.ServiceTFTP{
			ErrorMessage: errorMsg,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
	}

	return nil, nil
}

func (p *Plugin) PortPriority(i uint16) bool {
	return i == 69
}

func (p *Plugin) Name() string {
	return TFTP
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 800
}

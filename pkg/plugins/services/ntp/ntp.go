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

package ntp

import (
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const NTP = "ntp"

type Plugin struct{}

var ModeServer uint8 = 4

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// reference: https://datatracker.ietf.org/doc/html/rfc5905#section-7.3
	InitialConnectionPackage := []byte{
		0xe3, 0x00, 0x0a, 0xf8, // LI/VN/Mode | Stratum | Poll | Precision
		0x00, 0x00, 0x00, 0x00, // Root Delay
		0x00, 0x00, 0x00, 0x00, // Root Dispersion
		0x00, 0x00, 0x00, 0x00, // Reference Identifier
		0x00, 0x00, 0x00, 0x00, // Reference Timestamp
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // Origin Timestamp
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // Receive Timestamp
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // Transmit Timestamp
		0x00, 0x00, 0x00, 0x00,
	}

	response, err := utils.SendRecv(conn, InitialConnectionPackage, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// check if response is valid NTP packet
	if response[0]&0x07 == ModeServer && len(response) == len(InitialConnectionPackage) {
		service := plugins.CreateServiceFrom(target, plugins.ServiceNTP{}, false, "", plugins.UDP)
		if target.Misconfigs {
			finding, err := checkMonlist(conn, timeout)
			if err == nil && finding != nil {
				service.SecurityFindings = []plugins.SecurityFinding{*finding}
			}
		}
		return service, nil
	}
	return nil, nil
}

// monlistRequest is a NTP mode 7 (private) REQ_MON_GETLIST_1 packet.
// Byte 0: 0x17 = Response=0, More=0, Version=2, Mode=7
// Byte 1: 0x00 = Auth=0, Sequence=0
// Byte 2: 0x03 = Implementation=3 (ntpd)
// Byte 3: 0x2a = Request code 42 (REQ_MON_GETLIST_1)
// Bytes 4-47: padding zeros
var monlistRequest = func() []byte {
	pkt := make([]byte, 48)
	pkt[0] = 0x17
	pkt[1] = 0x00
	pkt[2] = 0x03
	pkt[3] = 0x2a
	return pkt
}()

// checkMonlist sends a monlist (mode 7) probe and returns a SecurityFinding if
// the server responds with monlist data. A valid monlist response has the mode 7
// bits set (byte 0 & 0x07 == 7) and the response bit set (byte 0 & 0x80 != 0).
func checkMonlist(conn net.Conn, timeout time.Duration) (*plugins.SecurityFinding, error) {
	response, err := utils.SendRecv(conn, monlistRequest, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < 4 {
		return nil, nil
	}

	// Response bit (0x80) must be set, mode must be 7 (0x07), and error bit
	// (0x40) must NOT be set — an error reply means monlist was refused.
	if response[0]&0x80 == 0 || response[0]&0x07 != 7 || response[0]&0x40 != 0 {
		return nil, nil
	}

	return &plugins.SecurityFinding{
		ID:          "ntp-monlist",
		Severity:    plugins.SeverityMedium,
		Description: "NTP monlist command enabled; amplification factor up to 556x enables DDoS attacks",
		Evidence:    fmt.Sprintf("monlist response received (%d bytes)", len(response)),
	}, nil
}

func (p *Plugin) PortPriority(i uint16) bool {
	return i == 123
}

func (p *Plugin) Name() string {
	return NTP
}
func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 800
}

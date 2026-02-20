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

package iax2

import (
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const IAX2 = "iax2"

// IAX2 frame types
const (
	frameTypeIAXControl = 0x06
)

// IAX2 subclasses for IAX Control frames
const (
	subclassPONG      = 0x03
	subclassACK       = 0x04
	subclassCALLTOKEN = 0x28
)

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	/**
	 * IAX2 (Inter-Asterisk eXchange v2) Protocol Detection
	 * https://datatracker.ietf.org/doc/html/rfc5456
	 *
	 * Sends POKE packet (IAX Control frame)
	 * Validates response contains correct frame type and valid subclass
	 */

	// POKE packet (12 bytes)
	pokePacket := []byte{
		0x80, 0x00,             // Source call number (high bit set = full frame)
		0x00, 0x00,             // Dest call number (0 for new call)
		0x00, 0x00, 0x00, 0x00, // Timestamp
		0x00, // oseqno (outbound sequence number)
		0x00, // iseqno (inbound sequence number)
		0x06, // Frame type: IAX Control
		0x1e, // Subclass: POKE (30 decimal)
	}

	response, err := utils.SendRecv(conn, pokePacket, timeout)
	if err != nil {
		return nil, err
	}

	if !validateIAX2Response(response) {
		return nil, nil
	}

	// Create service payload
	payload := plugins.ServiceIAX2{
		Detected: true,
	}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
}

func validateIAX2Response(response []byte) bool {
	// Check minimum length (12 bytes for IAX2 header)
	if len(response) < 12 {
		return false
	}

	// Byte 10: Frame type must be IAX Control (0x06)
	frameType := response[10]
	if frameType != frameTypeIAXControl {
		return false
	}

	// Byte 11: Subclass must be PONG, ACK, or CALLTOKEN
	subclass := response[11]
	validSubclasses := map[byte]bool{
		subclassPONG:      true,
		subclassACK:       true,
		subclassCALLTOKEN: true,
	}

	return validSubclasses[subclass]
}

func (p *Plugin) PortPriority(port uint16) bool {
	return port == 4569
}

func (p *Plugin) Name() string {
	return IAX2
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 2000
}

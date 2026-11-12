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

package openvpn

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const OPENVPN = "OpenVPN"

type Plugin struct{}

type TCPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
	plugins.RegisterPlugin(&TCPPlugin{})
}

func detectOpenVPN(conn net.Conn, timeout time.Duration, target plugins.Target, transport plugins.Protocol) (*plugins.Service, error) {
	/**
	 * https://build.openvpn.net/doxygen/ssl__pkt_8h_source.html
	 * https://openvpn.net/community-resources/openvpn-protocol/
	 *
	 * Send CLIENT_RESET control message, expect back valid SERVER_RESET message from server
	 * Checks if SERVER_RESET opcode is received, along with whether remote session ID is contained in response
	 * NOTE: Does not work if tls-auth is enabled in OpenVPN config (drops connection due to HMAC error)
	 */

	var POpcodeShift uint8 = 3
	var PControlHardResetClientV2 uint8 = 7
	var PControlHardResetServerV2 uint8 = 8
	var SessionIDLength = 8

	InitialConnectionPackage := []byte{
		PControlHardResetClientV2 << POpcodeShift, // opcode/key_id
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // Session ID (64-bit),
		0x0,                // Message Packet-ID Array Length
		0x0, 0x0, 0x0, 0x0, // Message Packet-ID
	}
	_, err := rand.Read(
		InitialConnectionPackage[1 : 1+SessionIDLength],
	) // generate random session ID
	if err != nil {
		return nil, &utils.RandomizeError{Message: "session ID"}
	}

	response, err := sendRecvOpenVPN(conn, InitialConnectionPackage, timeout, transport == plugins.TCP)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// check if response is valid OpenVPN packet
	if (response[0] >> POpcodeShift) == PControlHardResetServerV2 {
		for i := 0; i < len(response)-SessionIDLength; i++ {
			if reflect.DeepEqual(
				response[i:i+SessionIDLength],
				InitialConnectionPackage[1:1+SessionIDLength],
			) {
				service := plugins.CreateServiceFrom(target, plugins.ServiceOpenVPN{}, false, "", transport)
				if target.Misconfigs {
					service.SecurityFindings = []plugins.SecurityFinding{{
						ID:          "openvpn-exposed",
						Severity:    plugins.SeverityLow,
						Description: "OpenVPN tunnel listener exposed to the network",
						Evidence:    "CLIENT_RESET answered with SERVER_RESET",
					}}
				}
				return service, nil
			}
		}
	}
	return nil, nil
}

// sendRecvOpenVPN exchanges one OpenVPN control packet. TCP mode prepends and
// strips the 2-byte big-endian length prefix required by the OpenVPN stream
// protocol; UDP mode sends the datagram as-is.
func sendRecvOpenVPN(conn net.Conn, pkt []byte, timeout time.Duration, tcp bool) ([]byte, error) {
	if !tcp {
		return utils.SendRecv(conn, pkt, timeout)
	}
	if len(pkt) == 0 || len(pkt) > 0xffff {
		return nil, nil
	}
	framed := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(pkt)))
	copy(framed[2:], pkt)
	if err := utils.Send(conn, framed, timeout); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return []byte{}, nil
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 || n > 2048 {
		return nil, nil
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return []byte{}, nil
	}
	return body, nil
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectOpenVPN(conn, timeout, target, plugins.UDP)
}

func (p *TCPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectOpenVPN(conn, timeout, target, plugins.TCP)
}

func (p *Plugin) PortPriority(i uint16) bool {
	return i == 1194
}

func (p *Plugin) Name() string {
	return OPENVPN
}
func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 708
}

func (p *TCPPlugin) PortPriority(i uint16) bool {
	return i == 1194
}

func (p *TCPPlugin) Name() string {
	return OPENVPN
}

func (p *TCPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *TCPPlugin) Priority() int {
	return 708
}

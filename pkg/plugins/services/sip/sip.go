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

package sip

import (
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const (
	SIP            = "sip"
	SIPS           = "sips"
	DefaultSIPPort = 5060
	DefaultSIPSPort = 5061
)

type UDPPlugin struct{}
type TCPPlugin struct{}
type TLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&UDPPlugin{})
	plugins.RegisterPlugin(&TCPPlugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

func (p *UDPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return nil, nil
}

func (p *UDPPlugin) PortPriority(port uint16) bool {
	return port == DefaultSIPPort
}

func (p *UDPPlugin) Name() string {
	return SIP
}

func (p *UDPPlugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *UDPPlugin) Priority() int {
	return 50
}

func (p *TCPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return nil, nil
}

func (p *TCPPlugin) PortPriority(port uint16) bool {
	return port == DefaultSIPPort
}

func (p *TCPPlugin) Name() string {
	return SIP
}

func (p *TCPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *TCPPlugin) Priority() int {
	return 50
}

func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return nil, nil
}

func (p *TLSPlugin) PortPriority(port uint16) bool {
	return port == DefaultSIPSPort
}

func (p *TLSPlugin) Name() string {
	return SIPS
}

func (p *TLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *TLSPlugin) Priority() int {
	return 51
}

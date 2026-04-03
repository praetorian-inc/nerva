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

// Package smartinstall detects Cisco Smart Install protocol (port 4786).
//
// Cisco Smart Install is a plug-and-play configuration protocol for Cisco
// switches. It is critically dangerous when exposed — an attacker can extract
// the running config (including credentials) or overwrite it entirely, without
// any authentication.
//
// CVE-2018-0171: Remote code execution via Smart Install.
// CISA has published multiple advisories warning about exposed Smart Install.
//
// Detection sends the standard 24-byte Smart Install probe and validates the
// 24-byte response per the Cisco-Talos smi_check specification.
package smartinstall

import (
	"bytes"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	SMARTINSTALL = "smart-install"
	DefaultPort  = 4786
	probeLen     = 24
	respLen      = 24
)

// Smart Install probe: 24 bytes per Cisco-Talos smi_check
var smiProbe = []byte{
	0x00, 0x00, 0x00, 0x01, // type: 1
	0x00, 0x00, 0x00, 0x01, // length: 1
	0x00, 0x00, 0x00, 0x04, // data: 4
	0x00, 0x00, 0x00, 0x08, // data: 8
	0x00, 0x00, 0x00, 0x01, // data: 1
	0x00, 0x00, 0x00, 0x00, // data: 0
}

// Expected response prefix: first 4 bytes must be 0x00000004
var smiResponsePrefix = []byte{0x00, 0x00, 0x00, 0x04}

type SmartInstallPlugin struct{}

func init() {
	plugins.RegisterPlugin(&SmartInstallPlugin{})
}

func (p *SmartInstallPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.SendRecv(conn, smiProbe, timeout)
	if err != nil {
		return nil, nil
	}

	if !isValidSmartInstallResponse(response) {
		return nil, nil
	}

	payload := plugins.ServiceSmartInstall{
		CPEs: []string{"cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*"},
	}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

// isValidSmartInstallResponse validates the Smart Install response.
// A valid response is exactly 24 bytes and starts with 0x00000004.
func isValidSmartInstallResponse(response []byte) bool {
	if len(response) != respLen {
		return false
	}
	return bytes.HasPrefix(response, smiResponsePrefix)
}

func (p *SmartInstallPlugin) PortPriority(port uint16) bool {
	return port == DefaultPort
}

func (p *SmartInstallPlugin) Name() string {
	return SMARTINSTALL
}

func (p *SmartInstallPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *SmartInstallPlugin) Priority() int {
	return 200
}

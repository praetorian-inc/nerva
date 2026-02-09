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

package iec104

import (
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	startByte   = 0x68
	apciLength  = 0x04
	testfrAct   = 0x43
	testfrCon   = 0x83
	minFrameLen = 6
)

type IEC104Plugin struct{}

func init() {
	plugins.RegisterPlugin(&IEC104Plugin{})
}

const IEC104 = "iec104"

func (p *IEC104Plugin) PortPriority(port uint16) bool {
	return port == 2404
}

// Run detects IEC 60870-5-104 by sending a TESTFR ACT frame and validating
// the TESTFR CON response. TESTFR is a pure connectivity test that does not
// modify device state or trigger any control operations.
func (p *IEC104Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	testfrActFrame := []byte{startByte, apciLength, testfrAct, 0x00, 0x00, 0x00}

	response, err := utils.SendRecv(conn, testfrActFrame, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < minFrameLen {
		return nil, nil
	}

	if response[0] == startByte && response[1] == apciLength && response[2] == testfrCon {
		return plugins.CreateServiceFrom(target, plugins.ServiceIEC104{}, false, "", plugins.TCP), nil
	}

	return nil, nil
}

func (p *IEC104Plugin) Name() string {
	return IEC104
}

func (p *IEC104Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *IEC104Plugin) Priority() int {
	return 500
}

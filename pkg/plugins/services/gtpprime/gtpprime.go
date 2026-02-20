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

package gtpprime

import (
	"io"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// GTP Prime (GTP') Protocol - 3GPP TS 32.295
// GTP' is used for charging interfaces in telecom networks
// Port 3386/UDP, uses GTP header format with PT=0

var gtpPrimeEchoRequest = [8]byte{
	//
	// GTP Header (8 bytes minimum)
	// Byte 0: Flags - Version(3b)=1, PT(1b)=0, E(1b)=0, S(1b)=0, PN(1b)=0
	// Version=1: bits 7-5 = 001, so 0x20
	// PT=0 for GTP' (distinguishes from GTP-C which uses PT=1)
	//
	0x20,

	//
	// Byte 1: Message Type = 0x01 (Echo Request)
	//
	0x01,

	//
	// Bytes 2-3: Length = 0x0000 (no payload for Echo)
	//
	0x00, 0x00,

	//
	// Bytes 4-7: TEID = 0x00000000 (path management messages use TEID 0)
	//
	0x00, 0x00, 0x00, 0x00,
}

type GTPPrimePlugin struct{}

const GTPPRIME = "gtpprime"

func isGTPPrime(conn net.Conn, timeout time.Duration) (bool, error) {
	_, err := conn.Write(gtpPrimeEchoRequest[:])
	if err != nil {
		return false, err
	}

	// Response should be at least 8 bytes (GTP header minimum)
	response := make([]byte, 8)

	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false, err
	}

	_, err = io.ReadFull(conn, response)
	if err != nil {
		return false, err
	}

	// Validate GTP' Echo Response:
	// Byte 0: Version (bits 7-5) should be 1, PT (bit 4) should be 0
	// Version=1 means bits 7-5 = 001 (0x20 masked)
	// PT=0 means bit 4 = 0
	// Check version: (response[0] >> 5) & 0x07 == 1
	// Check PT: (response[0] >> 4) & 0x01 == 0
	version := (response[0] >> 5) & 0x07
	pt := (response[0] >> 4) & 0x01

	if version != 1 {
		return false, nil
	}

	if pt != 0 {
		return false, nil
	}

	// Byte 1: Message Type should be 0x02 (Echo Response)
	if response[1] != 0x02 {
		return false, nil
	}

	return true, nil
}

func init() {
	plugins.RegisterPlugin(&GTPPrimePlugin{})
}

func (p *GTPPrimePlugin) PortPriority(port uint16) bool {
	return port == 3386
}

func (p *GTPPrimePlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	if isGTPPrime, err := isGTPPrime(conn, timeout); !isGTPPrime || err != nil {
		return nil, nil
	}
	payload := plugins.ServiceGTPPrime{}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
}

func (p *GTPPrimePlugin) Name() string {
	return GTPPRIME
}

func (p *GTPPrimePlugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *GTPPrimePlugin) Priority() int {
	return 80
}

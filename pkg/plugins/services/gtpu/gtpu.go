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

package gtpu

import (
	"io"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// GTP-U (User Plane) Protocol - 3GPP TS 29.281
// GTP-U carries actual user data traffic in mobile networks (3G/4G/5G)
// Port 2152/UDP, uses GTPv1 header format with PT=1

var gtpuEchoRequest = [12]byte{
	//
	// GTP Header (8 bytes minimum, 12 bytes with sequence number)
	// Byte 0: Flags - Version(3b)=1, PT(1b)=1, E(1b)=0, S(1b)=1, PN(1b)=0
	// Version=1: bits 7-5 = 001, so 0x20
	// PT=1 for GTP-U (distinguishes from GTP' which uses PT=0)
	// S=1: sequence number present
	// Combined: 0x32 (0011 0010)
	//
	0x32,

	//
	// Byte 1: Message Type = 0x01 (Echo Request)
	//
	0x01,

	//
	// Bytes 2-3: Length = 0x0004 (4 bytes for seq+npdu+next when S=1)
	//
	0x00, 0x04,

	//
	// Bytes 4-7: TEID = 0x00000000 (path management messages use TEID 0)
	//
	0x00, 0x00, 0x00, 0x00,

	//
	// Bytes 8-9: Sequence Number (present when S=1)
	//
	0x00, 0x00,

	//
	// Byte 10: N-PDU Number (always present when S=1)
	//
	0x00,

	//
	// Byte 11: Next Extension Header Type (always present when S=1)
	//
	0x00,
}

type GTPUPlugin struct{}

const GTPU = "gtpu"

func isGTPU(conn net.Conn, timeout time.Duration) (bool, error) {
	_, err := conn.Write(gtpuEchoRequest[:])
	if err != nil {
		return false, err
	}

	// Response should be at least 12 bytes (8 byte header + 4 byte extension when S=1)
	response := make([]byte, 12)

	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false, err
	}

	_, err = io.ReadFull(conn, response)
	if err != nil {
		return false, err
	}

	// Validate GTP-U Echo Response:
	// Byte 0: Version (bits 7-5) should be 1, PT (bit 4) should be 1
	// Version=1 means bits 7-5 = 001 (0x20 masked)
	// PT=1 means bit 4 = 1 (GTP-U, not GTP')
	// Check version: (response[0] >> 5) & 0x07 == 1
	// Check PT: (response[0] >> 4) & 0x01 == 1
	version := (response[0] >> 5) & 0x07
	pt := (response[0] >> 4) & 0x01

	if version != 1 {
		return false, nil
	}

	if pt != 1 {
		return false, nil
	}

	// Byte 1: Message Type should be 0x02 (Echo Response)
	if response[1] != 0x02 {
		return false, nil
	}

	return true, nil
}

func init() {
	plugins.RegisterPlugin(&GTPUPlugin{})
}

func (p *GTPUPlugin) PortPriority(port uint16) bool {
	return port == 2152
}

func (p *GTPUPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	if isGTPU, err := isGTPU(conn, timeout); !isGTPU || err != nil {
		return nil, nil
	}
	payload := plugins.ServiceGTPU{}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
}

func (p *GTPUPlugin) Name() string {
	return GTPU
}

func (p *GTPUPlugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *GTPUPlugin) Priority() int {
	return 81
}

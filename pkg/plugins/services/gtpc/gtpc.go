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

package gtpc

import (
	"io"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// GTP-C (GTP Control Plane) Protocol - 3GPP TS 29.274 (GTPv2-C) and 3GPP TS 29.060 (GTPv1-C)
// GTP-C is used for control signaling in 3G/4G/5G mobile networks
// Port 2123/UDP, supports both GTPv1-C (flag 0x32) and GTPv2-C (flag 0x40)

// GTPv2-C Echo Request (8 bytes, no TEID when T=0)
var gtpv2EchoRequest = [8]byte{
	//
	// GTPv2-C Header (8 bytes for Echo Request)
	// Byte 0: Flags - Version(3b)=2, P(1b)=0, T(1b)=0, Spare(3b)=0
	// Version=2: bits 7-5 = 010, so 0x40
	// P=0: Piggybacking flag not set
	// T=0: TEID flag not set (no TEID for path management)
	//
	0x40,

	//
	// Byte 1: Message Type = 0x01 (Echo Request)
	//
	0x01,

	//
	// Bytes 2-3: Message Length = 0x0004 (4 bytes after header)
	//
	0x00, 0x04,

	//
	// Bytes 4-6: Sequence Number = 0x000001
	//
	0x00, 0x00, 0x01,

	//
	// Byte 7: Spare = 0x00
	//
	0x00,
}

// GTPv1-C Echo Request (12 bytes with sequence number)
var gtpv1EchoRequest = [12]byte{
	//
	// GTPv1-C Header (12 bytes minimum)
	// Byte 0: Flags - Version(3b)=1, PT(1b)=1, E(1b)=0, S(1b)=1, PN(1b)=0
	// Version=1: bits 7-5 = 001
	// PT=1: Protocol Type (distinguishes from GTP Prime which uses PT=0)
	// S=1: Sequence number present
	// Resulting flag: 0x32
	//
	0x32,

	//
	// Byte 1: Message Type = 0x01 (Echo Request)
	//
	0x01,

	//
	// Bytes 2-3: Length = 0x0004 (length after fixed header)
	//
	0x00, 0x04,

	//
	// Bytes 4-7: TEID = 0x00000000 (path management uses TEID 0)
	//
	0x00, 0x00, 0x00, 0x00,

	//
	// Bytes 8-9: Sequence Number = 0x0001
	//
	0x00, 0x01,

	//
	// Byte 10: N-PDU Number = 0x00
	//
	0x00,

	//
	// Byte 11: Next Extension Header Type = 0x00
	//
	0x00,
}

type GTPCPlugin struct{}

const GTPC = "gtpc"

// tryGTPv2 attempts to detect GTPv2-C by sending Echo Request and validating response
func tryGTPv2(conn net.Conn, timeout time.Duration) (bool, error) {
	_, err := conn.Write(gtpv2EchoRequest[:])
	if err != nil {
		return false, err
	}

	// GTPv2-C Echo Response should be at least 8 bytes
	response := make([]byte, 8)

	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false, err
	}

	_, err = io.ReadFull(conn, response)
	if err != nil {
		return false, err
	}

	// Validate GTPv2-C Echo Response:
	// Byte 0: Version (bits 7-5) should be 2
	// Version=2 means bits 7-5 = 010 (0x40 masked)
	version := (response[0] >> 5) & 0x07

	if version != 2 {
		return false, nil
	}

	// Byte 1: Message Type should be 0x02 (Echo Response)
	if response[1] != 0x02 {
		return false, nil
	}

	return true, nil
}

// tryGTPv1 attempts to detect GTPv1-C by sending Echo Request and validating response
func tryGTPv1(conn net.Conn, timeout time.Duration) (bool, error) {
	_, err := conn.Write(gtpv1EchoRequest[:])
	if err != nil {
		return false, err
	}

	// GTPv1-C Echo Response should be at least 12 bytes
	response := make([]byte, 12)

	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false, err
	}

	_, err = io.ReadFull(conn, response)
	if err != nil {
		return false, err
	}

	// Validate GTPv1-C Echo Response:
	// Byte 0: Version (bits 7-5) should be 1, PT (bit 4) should be 1
	// Version=1 means bits 7-5 = 001
	// PT=1 means bit 4 = 1 (distinguishes from GTP Prime which uses PT=0)
	version := (response[0] >> 5) & 0x07
	pt := (response[0] >> 4) & 0x01

	if version != 1 {
		return false, nil
	}

	if pt != 1 {
		return false, nil // PT=0 is GTP Prime, not GTP-C
	}

	// Byte 1: Message Type should be 0x02 (Echo Response)
	if response[1] != 0x02 {
		return false, nil
	}

	return true, nil
}

func init() {
	plugins.RegisterPlugin(&GTPCPlugin{})
}

func (p *GTPCPlugin) PortPriority(port uint16) bool {
	return port == 2123
}

func (p *GTPCPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Try GTPv2-C first (more common in modern networks)
	if isGTPv2, err := tryGTPv2(conn, timeout); isGTPv2 && err == nil {
		payload := plugins.ServiceGTPC{
			Version: "GTPv2",
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
	}

	// Fall back to GTPv1-C
	if isGTPv1, err := tryGTPv1(conn, timeout); isGTPv1 && err == nil {
		payload := plugins.ServiceGTPC{
			Version: "GTPv1",
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
	}

	// If neither version detected, return nil (not GTP-C)
	return nil, nil
}

func (p *GTPCPlugin) Name() string {
	return GTPC
}

func (p *GTPCPlugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *GTPCPlugin) Priority() int {
	// Priority 79 (before GTP Prime's 80)
	return 79
}

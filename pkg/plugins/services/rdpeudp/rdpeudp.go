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

package rdpeudp

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

// MS-RDPEUDP: Remote Desktop Protocol UDP Transport Extension
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp

const (
	rdpeudpPort     = 3389
	rdpeudpPriority = 90 // Near TCP RDP plugins (priority 89)
)

// RDPUDP flag constants from MS-RDPEUDP specification.
const (
	flagSYN   = 0x0001
	flagACK   = 0x0004
	flagSYNEX = 0x1000
)

// Plugin implements MS-RDPEUDP service fingerprinting on 3389/UDP.
type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return rdpeudpPriority
}

func (p *Plugin) PortPriority(port uint16) bool {
	return port == rdpeudpPort
}

func (p *Plugin) Name() string {
	return "rdpeudp"
}

// Run sends an RDPUDP SYN datagram and validates the SYN+ACK response.
func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	probe := buildSYNProbe()

	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	metadata, ok := parseSYNACK(response)
	if !ok {
		return nil, nil
	}

	return plugins.CreateServiceFrom(target, metadata, false, "", plugins.UDP), nil
}

// buildSYNProbe constructs a 16-byte RDPUDP SYN datagram.
//
// Layout (MS-RDPEUDP spec):
//
//	Bytes 0-3:   snSourceAck           (0xFFFFFFFF for SYN)
//	Bytes 4-5:   uReceiveWindowSize    (16)
//	Bytes 6-7:   uFlags                (RDPUDP_FLAG_SYN = 0x0001)
//	Bytes 8-11:  snInitialSequenceNumber (random)
//	Bytes 12-13: uUpStreamMtu          (1232)
//	Bytes 14-15: uDownStreamMtu        (1232)
func buildSYNProbe() []byte {
	probe := make([]byte, 16)

	// RDPUDP_FEC_HEADER (8 bytes)
	binary.LittleEndian.PutUint32(probe[0:4], 0xFFFFFFFF) // snSourceAck = -1 (required for SYN)
	binary.LittleEndian.PutUint16(probe[4:6], 16)         // uReceiveWindowSize
	binary.LittleEndian.PutUint16(probe[6:8], flagSYN)    // uFlags

	// RDPUDP_SYNDATA_PAYLOAD (8 bytes)
	seqNum := make([]byte, 4)
	_, _ = rand.Read(seqNum) // crypto/rand.Read does not fail on supported platforms
	copy(probe[8:12], seqNum) // snInitialSequenceNumber
	binary.LittleEndian.PutUint16(probe[12:14], 1232)      // uUpStreamMtu
	binary.LittleEndian.PutUint16(probe[14:16], 1232)      // uDownStreamMtu

	return probe
}

// parseSYNACK validates an RDPUDP SYN+ACK response and extracts metadata.
//
// A valid response must have:
//  1. At least 16 bytes (FEC_HEADER + SYNDATA_PAYLOAD)
//  2. uFlags contains both RDPUDP_FLAG_SYN (0x0001) and RDPUDP_FLAG_ACK (0x0004)
//
// Optionally extracts protocol version from SYNDATAEX_PAYLOAD if RDPUDP_FLAG_SYNEX is set.
func parseSYNACK(data []byte) (plugins.ServiceRDPEUDP, bool) {
	// Minimum: FEC_HEADER (8) + SYNDATA_PAYLOAD (8) = 16 bytes
	if len(data) < 16 {
		return plugins.ServiceRDPEUDP{}, false
	}

	flags := binary.LittleEndian.Uint16(data[6:8])

	// Must have both SYN and ACK flags set
	if flags&flagSYN == 0 || flags&flagACK == 0 {
		return plugins.ServiceRDPEUDP{}, false
	}

	metadata := plugins.ServiceRDPEUDP{
		UpStreamMtu:  binary.LittleEndian.Uint16(data[12:14]),
		DownStreamMtu: binary.LittleEndian.Uint16(data[14:16]),
	}

	// If SYNEX flag is set, parse the extended SYN payload for protocol version.
	// RDPUDP_SYNDATAEX_PAYLOAD starts at offset 16:
	//   Bytes 0-1: uSynExFlags
	//   Bytes 2-3: uUdpVer (protocol version)
	if flags&flagSYNEX != 0 && len(data) >= 20 {
		metadata.ProtocolVersion = binary.LittleEndian.Uint16(data[18:20])
	}

	return metadata, true
}

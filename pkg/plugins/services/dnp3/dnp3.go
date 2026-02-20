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

package dnp3

import (
	"crypto/rand"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	DNP3StartByte1 = 0x05
	DNP3StartByte2 = 0x64
	DNP3MinLength  = 10 // Start(2) + Len(1) + Ctrl(1) + Dest(2) + Src(2) + CRC(2)
)

// DNP3 Control byte flags
const (
	CtrlDIR = 0x80 // Direction (1=from master)
	CtrlPRM = 0x40 // Primary message
	CtrlFCB = 0x20 // Frame count bit
	CtrlFCV = 0x10 // Frame count valid
)

// DNP3 Function codes (lower 4 bits of control byte)
const (
	FuncRequestLinkStatus = 0x09
)

type DNP3Plugin struct{}

func init() {
	plugins.RegisterPlugin(&DNP3Plugin{})
}

const DNP3 = "dnp3"

func (p *DNP3Plugin) PortPriority(port uint16) bool {
	return port == 20000
}

// Run
/*
   DNP3 (Distributed Network Protocol 3) is a protocol used in SCADA systems
   for communications between control centers, RTUs, and IEDs.

   DNP3 runs over TCP/IP on port 20000 by default. All DNP3 frames begin with
   the start bytes 0x05 0x64 (magic signature).

   This implementation uses Function Code 0x09 (Request Link Status) which is
   a safe, read-only diagnostic query that:
   - Only requests link status
   - Does NOT modify any data
   - Does NOT trigger control operations
   - Safe for ICS/SCADA environments

   Frame structure (FT3 Format):
   - Start bytes: 0x05 0x64
   - Length: 1 byte
   - Control byte: 1 byte (DIR, PRM, FCB, FCV, Function code)
   - Destination address: 2 bytes (little-endian)
   - Source address: 2 bytes (little-endian)
   - Header CRC: 2 bytes (CRC-16)

   Testing: Can be tested with dnp3 simulators or OpenDNP3 outstation
*/
func (p *DNP3Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Build Request Link Status probe
	probe, err := buildRequestLinkStatusProbe()
	if err != nil {
		return nil, err
	}

	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Validate DNP3 response
	if len(response) < DNP3MinLength {
		return nil, nil
	}

	// Check for DNP3 start bytes (0x05 0x64)
	if response[0] != DNP3StartByte1 || response[1] != DNP3StartByte2 {
		return nil, nil
	}

	// Valid DNP3 frame detected - parse device role
	deviceRole := parseDeviceRole(response)

	// Extract addresses for metadata
	var srcAddr, destAddr uint16
	if len(response) >= 8 {
		// DNP3 addresses are little-endian
		destAddr = uint16(response[4]) | (uint16(response[5]) << 8)
		srcAddr = uint16(response[6]) | (uint16(response[7]) << 8)
	}

	// Create service metadata
	service := plugins.ServiceDNP3{
		SourceAddress:      srcAddr,
		DestinationAddress: destAddr,
		DeviceRole:         deviceRole,
		FunctionCode:       FuncRequestLinkStatus,
		CPEs:               []string{}, // DNP3 is a protocol, not a specific product
	}

	return plugins.CreateServiceFrom(target, service, false, "", plugins.TCP), nil
}

func (p *DNP3Plugin) Name() string {
	return DNP3
}

func (p *DNP3Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *DNP3Plugin) Priority() int {
	return 400 // Same priority as Modbus (ICS protocol)
}
// buildRequestLinkStatusProbe creates a DNP3 Request Link Status frame
func buildRequestLinkStatusProbe() ([]byte, error) {
	// Generate random source address (1-65534, avoiding 0 and 65535)
	srcAddrBytes := make([]byte, 2)
	_, err := rand.Read(srcAddrBytes)
	if err != nil {
		return nil, &utils.RandomizeError{Message: "Source Address"}
	}

	// Ensure source address is not 0 or 0xFFFF
	srcAddr := uint16(srcAddrBytes[0]) | (uint16(srcAddrBytes[1]) << 8)
	if srcAddr == 0 || srcAddr == 0xFFFF {
		srcAddr = 1
	}

	// Build frame without CRC
	frame := []byte{
		DNP3StartByte1,               // Start byte 1: 0x05
		DNP3StartByte2,               // Start byte 2: 0x64
		0x05,                         // Length: 5 bytes follow
		CtrlPRM | FuncRequestLinkStatus, // Control: PRM=1, Func=0x09 (Request Link Status)
		0x00, 0x00,                   // Destination: 0 (broadcast)
		byte(srcAddr & 0xFF), byte(srcAddr >> 8), // Source: random address (little-endian)
	}

	// Calculate and append CRC-16
	crc := calculateDNP3CRC(frame[1:]) // CRC calculated from byte 1 onwards (excluding first start byte)
	frame = append(frame, byte(crc&0xFF), byte(crc>>8))

	return frame, nil
}

// DNP3 CRC-16 lookup table (polynomial 0x3D65, reversed 0xA6BC)
var dnp3CRCTable = [256]uint16{
	0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
	0xFF89, 0xC9D7, 0x9335, 0xA56B, 0x26F1, 0x10AF, 0x4A4D, 0x7C13,
	0xB26B, 0x8435, 0xDED7, 0xE889, 0x6B13, 0x5D4D, 0x07AF, 0x31F1,
	0x4DE2, 0x7BBC, 0x215E, 0x1700, 0x949A, 0xA2C4, 0xF826, 0xCE78,
	0x29AF, 0x1FF1, 0x4513, 0x734D, 0xF0D7, 0xC689, 0x9C6B, 0xAA35,
	0xD626, 0xE078, 0xBA9A, 0x8CC4, 0x0F5E, 0x3900, 0x63E2, 0x55BC,
	0x9BC4, 0xAD9A, 0xF778, 0xC126, 0x42BC, 0x74E2, 0x2E00, 0x185E,
	0x644D, 0x5213, 0x08F1, 0x3EAF, 0xBD35, 0x8B6B, 0xD189, 0xE7D7,
	0x535E, 0x6500, 0x3FE2, 0x09BC, 0x8A26, 0xBC78, 0xE69A, 0xD0C4,
	0xACD7, 0x9A89, 0xC06B, 0xF635, 0x75AF, 0x43F1, 0x1913, 0x2F4D,
	0xE135, 0xD76B, 0x8D89, 0xBBD7, 0x384D, 0x0E13, 0x54F1, 0x62AF,
	0x1EBC, 0x28E2, 0x7200, 0x445E, 0xC7C4, 0xF19A, 0xAB78, 0x9D26,
	0x7AF1, 0x4CAF, 0x164D, 0x2013, 0xA389, 0x95D7, 0xCF35, 0xF96B,
	0x8578, 0xB326, 0xE9C4, 0xDF9A, 0x5C00, 0x6A5E, 0x30BC, 0x06E2,
	0xC89A, 0xFEC4, 0xA426, 0x9278, 0x11E2, 0x27BC, 0x7D5E, 0x4B00,
	0x3713, 0x014D, 0x5BAF, 0x6DF1, 0xEE6B, 0xD835, 0x82D7, 0xB489,
	0xA6BC, 0x90E2, 0xCA00, 0xFC5E, 0x7FC4, 0x499A, 0x1378, 0x2526,
	0x5935, 0x6F6B, 0x3589, 0x03D7, 0x804D, 0xB613, 0xECF1, 0xDAAF,
	0x14D7, 0x2289, 0x786B, 0x4E35, 0xCDAF, 0xFBF1, 0xA113, 0x974D,
	0xEB5E, 0xDD00, 0x87E2, 0xB1BC, 0x3226, 0x0478, 0x5E9A, 0x68C4,
	0x8F13, 0xB94D, 0xE3AF, 0xD5F1, 0x566B, 0x6035, 0x3AD7, 0x0C89,
	0x709A, 0x46C4, 0x1C26, 0x2A78, 0xA9E2, 0x9FBC, 0xC55E, 0xF300,
	0x3D78, 0x0B26, 0x51C4, 0x679A, 0xE400, 0xD25E, 0x88BC, 0xBEE2,
	0xC2F1, 0xF4AF, 0xAE4D, 0x9813, 0x1B89, 0x2DD7, 0x7735, 0x416B,
	0xF5E2, 0xC3BC, 0x995E, 0xAF00, 0x2C9A, 0x1AC4, 0x4026, 0x7678,
	0x0A6B, 0x3C35, 0x66D7, 0x5089, 0xD313, 0xE54D, 0xBFAF, 0x89F1,
	0x4789, 0x71D7, 0x2B35, 0x1D6B, 0x9EF1, 0xA8AF, 0xF24D, 0xC413,
	0xB800, 0x8E5E, 0xD4BC, 0xE2E2, 0x6178, 0x5726, 0x0DC4, 0x3B9A,
	0xDC4D, 0xEA13, 0xB0F1, 0x86AF, 0x0535, 0x336B, 0x6989, 0x5FD7,
	0x23C4, 0x159A, 0x4F78, 0x7926, 0xFABC, 0xCCE2, 0x9600, 0xA05E,
	0x6E26, 0x5878, 0x029A, 0x34C4, 0xB75E, 0x8100, 0xDBE2, 0xEDBC,
	0x91AF, 0xA7F1, 0xFD13, 0xCB4D, 0x48D7, 0x7E89, 0x246B, 0x1235,
}

// calculateDNP3CRC computes DNP3 CRC-16 (polynomial 0x3D65)
func calculateDNP3CRC(data []byte) uint16 {
	crc := uint16(0)
	for _, b := range data {
		crc = (crc >> 8) ^ dnp3CRCTable[(crc^uint16(b))&0xFF]
	}
	return ^crc // Complement the result
}

// parseDeviceRole determines if device is master or outstation based on control byte
func parseDeviceRole(response []byte) string {
	if len(response) < 4 {
		return "unknown"
	}

	controlByte := response[3]

	// DIR bit (0x80): 0=from outstation, 1=from master
	if controlByte&CtrlDIR != 0 {
		return "master"
	}
	return "outstation"
}

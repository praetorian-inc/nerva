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

// Package pfcp implements PFCP (Packet Forwarding Control Protocol) detection.
// PFCP is defined by 3GPP TS 29.244 for the N4 interface between SMF and UPF
// in 5G/4G-CUPS architecture. Detection uses Heartbeat Request/Response
// (standard keepalive, safe, no authentication required).
// Default port: 8805/UDP.
package pfcp

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const PFCP = "pfcp"

type Plugin struct{}

// PFCP Heartbeat Request (16 bytes)
// Header (8 bytes when S=0):
//   Byte 0: Version(3b)=1, Spare(3b)=0, FO(1b)=0, S(1b)=0 → 0x20
//   Byte 1: Message Type = 1 (Heartbeat Request)
//   Bytes 2-3: Message Length = 12 (bytes after first 4 header bytes)
//   Bytes 4-6: Sequence Number = 0x000001
//   Byte 7: Spare = 0x00
// IE: Recovery Time Stamp (8 bytes):
//   Bytes 8-9: IE Type = 96 (0x0060)
//   Bytes 10-11: IE Length = 4
//   Bytes 12-15: NTP Timestamp (seconds since 1900-01-01)
var pfcpHeartbeatRequest = [16]byte{
	0x20,       // Flags: Version=1, Spare=0, FO=0, S=0
	0x01,       // Message Type: Heartbeat Request
	0x00, 0x0c, // Message Length: 12
	0x00, 0x00, 0x01, // Sequence Number: 1
	0x00,             // Spare
	0x00, 0x60, // IE Type: Recovery Time Stamp (96)
	0x00, 0x04, // IE Length: 4
	0x00, 0x00, 0x00, 0x01, // Recovery Time Stamp (placeholder)
}

// PFCP IE types
const (
	ieTypeNodeID            = 60 // 0x003C
	ieTypeRecoveryTimeStamp = 96 // 0x0060
)

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// detectPFCP sends a Heartbeat Request and validates the response.
func detectPFCP(conn net.Conn, timeout time.Duration) ([]byte, error) {
	response, err := utils.SendRecv(conn, pfcpHeartbeatRequest[:], timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < 8 {
		return nil, nil
	}

	// Validate PFCP header:
	// Byte 0: Version (bits 7-5) must be 1
	version := (response[0] >> 5) & 0x07
	if version != 1 {
		return nil, nil
	}

	// Byte 1: Message Type must be 0x02 (Heartbeat Response)
	if response[1] != 0x02 {
		return nil, nil
	}

	return response, nil
}

// enrichPFCP extracts Recovery Time Stamp and Node ID from PFCP IEs.
func enrichPFCP(response []byte) (uint32, string) {
	var recoveryTS uint32
	var nodeID string

	// IEs start at offset 8 (after 8-byte header when S=0)
	offset := 8
	for offset+4 <= len(response) {
		ieType := binary.BigEndian.Uint16(response[offset : offset+2])
		ieLen := binary.BigEndian.Uint16(response[offset+2 : offset+4])
		offset += 4

		if offset+int(ieLen) > len(response) {
			break
		}

		switch ieType {
		case ieTypeRecoveryTimeStamp:
			if ieLen >= 4 {
				recoveryTS = binary.BigEndian.Uint32(response[offset : offset+4])
			}
		case ieTypeNodeID:
			if ieLen >= 1 {
				nodeIDType := response[offset]
				switch nodeIDType {
				case 0: // IPv4
					if ieLen >= 5 {
						nodeID = net.IP(response[offset+1 : offset+5]).String()
					}
				case 1: // IPv6
					if ieLen >= 17 {
						nodeID = net.IP(response[offset+1 : offset+17]).String()
					}
				case 2: // FQDN
					if ieLen >= 2 {
						nodeID = string(response[offset+1 : offset+int(ieLen)])
					}
				}
			}
		}

		offset += int(ieLen)
	}

	return recoveryTS, nodeID
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := detectPFCP(conn, timeout)
	if err != nil || response == nil {
		return nil, nil
	}

	recoveryTS, nodeID := enrichPFCP(response)

	payload := plugins.ServicePFCP{
		RecoveryTimestamp: recoveryTS,
		NodeID:            nodeID,
	}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
}

func (p *Plugin) PortPriority(port uint16) bool {
	return port == 8805
}

func (p *Plugin) Name() string {
	return PFCP
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 80
}

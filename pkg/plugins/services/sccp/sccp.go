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

package sccp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const SCCP = "sccp"

// SCCP Header constants
const (
	sccpHeaderSize = 12
)

// SCCP Message IDs
const (
	msgStationRegister        = 0x0001 // StationRegisterMessage
	msgStationRegisterAck     = 0x0081 // StationRegisterAckMessage
	msgStationRegisterReject  = 0x009D // StationRegisterRejectMessage
)

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	registerPacket := buildStationRegisterMessage()
	response, err := utils.SendRecv(conn, registerPacket, timeout)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, nil
	}

	if !isValidSCCPHeader(response) {
		return nil, nil
	}

	messageID := binary.LittleEndian.Uint32(response[8:12])
	if messageID != msgStationRegisterAck {
		return nil, nil
	}

	deviceInfo := extractDeviceInfo(response)
	return plugins.CreateServiceFrom(target, deviceInfo, false, deviceInfo.ProtocolVersion, plugins.TCP), nil
}

func (p *Plugin) PortPriority(port uint16) bool {
	return port == 2000 || port == 2443
}

func (p *Plugin) Name() string {
	return SCCP
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 150
}

// isValidSCCPHeader validates the SCCP header format
func isValidSCCPHeader(response []byte) bool {
	if len(response) < sccpHeaderSize {
		return false
	}

	// Check reserved field (bytes 4-7) must be zero
	reserved := binary.LittleEndian.Uint32(response[4:8])
	if reserved != 0 {
		return false
	}

	// Check length field (bytes 0-3) is non-zero and matches actual payload
	length := binary.LittleEndian.Uint32(response[0:4])
	if length == 0 {
		return false
	}

	// Verify actual response size matches header length field
	// Total expected size = header (12 bytes) + payload (length)
	expectedSize := int(length) + sccpHeaderSize
	if len(response) < expectedSize {
		return false
	}

	return true
}

// buildStationRegisterMessage creates a SCCP StationRegisterMessage (0x0001)
func buildStationRegisterMessage() []byte {
	// SCCP Header (12 bytes) + Minimal payload
	// DeviceName: 16 bytes (null-terminated)
	// StationUserId: 4 bytes
	// StationInstance: 4 bytes
	// DeviceType: 4 bytes
	payloadSize := 28 // Minimal payload for registration

	packet := make([]byte, sccpHeaderSize+payloadSize)

	// SCCP Header
	binary.LittleEndian.PutUint32(packet[0:4], uint32(payloadSize))  // Length
	binary.LittleEndian.PutUint32(packet[4:8], 0)                    // Reserved
	binary.LittleEndian.PutUint32(packet[8:12], msgStationRegister)  // Message ID

	// Payload (minimal device registration)
	// DeviceName: "SEP000000000000" (16 bytes, null-terminated)
	deviceName := []byte("SEP000000000000")
	copy(packet[12:28], deviceName)

	// StationUserId: 0 (4 bytes)
	binary.LittleEndian.PutUint32(packet[28:32], 0)

	// StationInstance: 1 (4 bytes)
	binary.LittleEndian.PutUint32(packet[32:36], 1)

	// DeviceType: 0 (4 bytes) - Generic
	binary.LittleEndian.PutUint32(packet[36:40], 0)

	return packet
}

// extractDeviceInfo extracts device information from StationRegisterAckMessage
func extractDeviceInfo(response []byte) plugins.ServiceSCCP {
	if len(response) < sccpHeaderSize+16 {
		return plugins.ServiceSCCP{
			DeviceType:      "Station",
			ProtocolVersion: "unknown",
		}
	}

	// RegisterAckMessage structure:
	// - Header (12 bytes)
	// - KeepAlive (4 bytes)
	// - DateTemplate (4 bytes)
	// - SecondaryKeepAlive (4 bytes)
	// - ProtocolVersion (4 bytes)

	protocolVersion := "unknown"
	if len(response) >= sccpHeaderSize+16 {
		protoVer := binary.LittleEndian.Uint32(response[sccpHeaderSize+12:sccpHeaderSize+16])
		protocolVersion = fmt.Sprintf("%d", protoVer)
	}

	return plugins.ServiceSCCP{
		DeviceType:      "Station",
		ProtocolVersion: protocolVersion,
		MaxStreams:      0,
		DeviceName:      "",
	}
}

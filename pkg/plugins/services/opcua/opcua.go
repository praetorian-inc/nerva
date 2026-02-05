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

package opcua

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type OPCUAPlugin struct{}

func init() {
	plugins.RegisterPlugin(&OPCUAPlugin{})
}

const OPCUA = "opcua"

func (p *OPCUAPlugin) PortPriority(port uint16) bool {
	return port == 4840
}

// Run implements OPC UA (Unified Architecture) protocol detection.
//
// OPC UA is an industrial communication standard for machine-to-machine communication.
// This implementation sends a Hello message and validates the server's ACK response.
//
// Protocol Structure:
//   - Hello message contains: MessageType="HEL", ProtocolVersion, buffer sizes, endpoint URL
//   - Valid OPC UA server responds with: MessageType="ACK"
//   - Both messages have 8-byte header: MessageType (3 bytes) + 'F' + MessageSize (4 bytes)
//
// The default TCP port is 4840 (official IANA assignment for OPC UA).
func (p *OPCUAPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	endpointURL := fmt.Sprintf("opc.tcp://%s:%d", target.Address.Addr().String(), target.Address.Port())

	hello := buildOPCUAHello(endpointURL)

	response, err := utils.SendRecv(conn, hello, timeout)
	if err != nil {
		return nil, err
	}

	// Empty response means no OPC UA server
	if len(response) == 0 {
		return nil, nil
	}

	// Valid ACK response must be at least 8 bytes (header size)
	// and start with "ACK" message type
	if len(response) >= 8 && string(response[0:3]) == "ACK" {
		return plugins.CreateServiceFrom(target, plugins.ServiceOPCUA{
			CPEs: []string{"cpe:2.3:a:opcfoundation:opcua_server:*:*:*:*:*:*:*:*"},
		}, false, "", plugins.TCP), nil
	}

	return nil, nil
}

// buildOPCUAHello constructs an OPC UA Hello message.
//
// Message structure:
//   Header (8 bytes):
//     - Bytes 0-2: "HEL" (MessageType)
//     - Byte 3: 'F' (final chunk indicator)
//     - Bytes 4-7: MessageSize as UInt32 little-endian (includes header)
//   Body:
//     - ProtocolVersion: UInt32 (0 for OPC UA 1.0)
//     - ReceiveBufferSize: UInt32 (65536 bytes)
//     - SendBufferSize: UInt32 (65536 bytes)
//     - MaxMessageSize: UInt32 (0 = no limit)
//     - MaxChunkCount: UInt32 (0 = no limit)
//     - EndpointUrl: String (4-byte length prefix + UTF-8 bytes)
func buildOPCUAHello(endpointURL string) []byte {
	// Header
	messageType := []byte("HEL")
	chunkType := byte('F') // Final chunk

	// Body parameters
	protocolVersion := uint32(0)       // OPC UA 1.0
	receiveBufferSize := uint32(65536) // 64 KB
	sendBufferSize := uint32(65536)    // 64 KB
	maxMessageSize := uint32(0)        // No limit
	maxChunkCount := uint32(0)         // No limit

	// Endpoint URL with length prefix
	endpointBytes := []byte(endpointURL)
	endpointLength := uint32(len(endpointBytes))

	// Calculate total message size
	messageSize := uint32(8 +  // Header
		4 + // ProtocolVersion
		4 + // ReceiveBufferSize
		4 + // SendBufferSize
		4 + // MaxMessageSize
		4 + // MaxChunkCount
		4 + // EndpointUrl length
		len(endpointBytes)) // EndpointUrl bytes

	// Build message
	message := make([]byte, 0, messageSize)

	// Header
	message = append(message, messageType...)
	message = append(message, chunkType)
	messageSizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(messageSizeBytes, messageSize)
	message = append(message, messageSizeBytes...)

	// Body
	buf := make([]byte, 4)

	binary.LittleEndian.PutUint32(buf, protocolVersion)
	message = append(message, buf...)

	binary.LittleEndian.PutUint32(buf, receiveBufferSize)
	message = append(message, buf...)

	binary.LittleEndian.PutUint32(buf, sendBufferSize)
	message = append(message, buf...)

	binary.LittleEndian.PutUint32(buf, maxMessageSize)
	message = append(message, buf...)

	binary.LittleEndian.PutUint32(buf, maxChunkCount)
	message = append(message, buf...)

	binary.LittleEndian.PutUint32(buf, endpointLength)
	message = append(message, buf...)

	message = append(message, endpointBytes...)

	return message
}

func (p *OPCUAPlugin) Name() string {
	return OPCUA
}

func (p *OPCUAPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *OPCUAPlugin) Priority() int {
	return 400
}

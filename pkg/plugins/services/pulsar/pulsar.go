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

/*
Apache Pulsar Service Fingerprinting

This plugin implements Apache Pulsar service fingerprinting with dual detection:
1. Binary protocol detection on ports 6650 (TCP) and 6651 (TCPTLS)
2. HTTP admin API detection on ports 8080 (TCP) and 8443 (TCPTLS)

Detection Strategy:

PHASE 1 - BINARY PROTOCOL DETECTION (ports 6650/6651):
  - Build minimal Pulsar Connect frame (hand-crafted protobuf)
  - Send Connect command via binary protocol
  - Parse Connected response
  - Extract server version from response
  - Generate CPE for vulnerability tracking

PHASE 2 - HTTP ADMIN API DETECTION (ports 8080/8443):
  - Send GET /admin/v2/clusters HTTP request
  - Parse JSON response (array of cluster names)
  - Detect Pulsar admin API presence
  - No version extraction (not reliably available from admin API)

Pulsar Binary Protocol Wire Format:
  Frame Structure:
    [totalSize:4 bytes BE][cmdSize:4 bytes BE][protobuf command bytes]

  Connect Command (hand-crafted protobuf):
    BaseCommand field 1 (type) = 2 (CONNECT): 08 02
    BaseCommand field 2 (connect) = nested CommandConnect: 12 XX (XX = length)
    CommandConnect field 1 (client_version) = "Pulsar-Client-Go-v0.1.0": 0a + varint length + UTF-8
    CommandConnect field 4 (protocol_version) = 6: 20 06

  Connected Response (expected):
    BaseCommand field 1 (type) = 3 (CONNECTED)
    BaseCommand field 3 (connected) = nested CommandConnected
    CommandConnected field 1 (server_version) = "Pulsar-Broker-vX.X.X"
    CommandConnected field 2 (protocol_version) = varint

Protobuf Parsing Strategy (without library):
  - Walk protobuf bytes manually
  - Each field: (field_number << 3 | wire_type) as varint tag
  - Wire type 0 = varint, wire type 2 = length-delimited (strings, nested messages)
  - For Connected response:
    - Tag 08 = field 1 (type), value should be 03 (CONNECTED)
    - Tag 1a = field 3 (connected), followed by length + nested message
    - Inside connected: tag 0a = field 1 (server_version), length + string
    - Inside connected: tag 10 = field 2 (protocol_version), varint

HTTP Admin API Response:
  GET /admin/v2/clusters returns:
    HTTP/1.1 200 OK
    Content-Type: application/json

    ["standalone"] or ["cluster1", "cluster2", ...]

Version Compatibility:
  - Pulsar 1.x - 3.x: Binary protocol supported
  - Protocol version 6+ standard across most deployments
  - Admin API available in all modern versions

Port Configuration:
  - Port 6650: Binary protocol (TCP)
  - Port 6651: Binary protocol (TCPTLS)
  - Port 8080: HTTP admin API (TCP)
  - Port 8443: HTTPS admin API (TCPTLS)

References:
  - https://pulsar.apache.org/docs/develop-binary-protocol/
  - https://github.com/apache/pulsar/blob/master/pulsar-common/src/main/proto/PulsarApi.proto
  - https://pulsar.apache.org/admin-rest-api/
*/

package pulsar

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	PULSAR         = "pulsar"
	PULSARTLS      = "pulsar"
	PULSARADMIN    = "pulsar-admin"
	PULSARADMINTLS = "pulsar-admin"
)

type Plugin struct{}
type TLSPlugin struct{}
type AdminPlugin struct{}
type AdminTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
	plugins.RegisterPlugin(&AdminPlugin{})
	plugins.RegisterPlugin(&AdminTLSPlugin{})
}

// Plugin - Binary protocol on port 6650 (TCP)
func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectPulsarBinary(conn, false, timeout, target)
}

func (p *Plugin) PortPriority(port uint16) bool {
	return port == 6650
}

func (p *Plugin) Name() string {
	return PULSAR
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 100
}

// TLSPlugin - Binary protocol on port 6651 (TCPTLS)
func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectPulsarBinary(conn, true, timeout, target)
}

func (p *TLSPlugin) PortPriority(port uint16) bool {
	return port == 6651
}

func (p *TLSPlugin) Name() string {
	return PULSARTLS
}

func (p *TLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *TLSPlugin) Priority() int {
	return 101
}

// AdminPlugin - HTTP admin API on port 8080 (TCP)
func (p *AdminPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectPulsarAdmin(conn, false, timeout, target)
}

func (p *AdminPlugin) PortPriority(port uint16) bool {
	return port == 8080
}

func (p *AdminPlugin) Name() string {
	return PULSARADMIN
}

func (p *AdminPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *AdminPlugin) Priority() int {
	return -1 // Can coexist with HTTP on port 8080
}

// AdminTLSPlugin - HTTPS admin API on port 8443 (TCPTLS)
func (p *AdminTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectPulsarAdmin(conn, true, timeout, target)
}

func (p *AdminTLSPlugin) PortPriority(port uint16) bool {
	return port == 8443
}

func (p *AdminTLSPlugin) Name() string {
	return PULSARADMINTLS
}

func (p *AdminTLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *AdminTLSPlugin) Priority() int {
	return -1 // Can coexist with HTTPS on port 8443
}

// detectPulsarBinary implements binary protocol detection
func detectPulsarBinary(conn net.Conn, isTLS bool, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Build Connect frame
	connectFrame := buildConnectFrame()

	// Send and receive
	response, err := utils.SendRecv(conn, connectFrame, timeout)
	if err != nil {
		return nil, err
	}

	// Parse response
	if len(response) < 8 {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: PULSAR,
			Info:    "response too short",
		}
	}

	// Extract totalSize (first 4 bytes, big-endian)
	// totalSize counts everything AFTER the totalSize field itself (cmdSize + protobuf)
	totalSize := binary.BigEndian.Uint32(response[0:4])
	if totalSize > 4096 || len(response) < 4+int(totalSize) {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: PULSAR,
			Info:    "incomplete response",
		}
	}

	// Extract cmdSize (next 4 bytes, big-endian)
	cmdSize := binary.BigEndian.Uint32(response[4:8])
	if cmdSize > 4092 || len(response) < 8+int(cmdSize) {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: PULSAR,
			Info:    "incomplete command",
		}
	}

	// Parse protobuf command
	pbData := response[8 : 8+cmdSize]

	// Check if response is CONNECTED (type = 2)
	if len(pbData) < 2 || pbData[0] != 0x08 {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: PULSAR,
			Info:    "invalid protobuf tag",
		}
	}

	cmdType := pbData[1]
	if cmdType != 0x03 { // CONNECTED = 3
		return nil, &utils.InvalidResponseErrorInfo{
			Service: PULSAR,
			Info:    fmt.Sprintf("unexpected command type: %d", cmdType),
		}
	}

	// Extract server version from protobuf
	version := extractServerVersion(pbData)

	// Build CPE if version found
	var cpes []string
	if version != "" {
		cpes = []string{buildCPE(version)}
	}

	return plugins.CreateServiceFrom(target, plugins.ServicePulsar{
		ProtocolVersion: 6, // We requested protocol version 6
		CPEs:            cpes,
	}, isTLS, version, plugins.TCP), nil
}

// detectPulsarAdmin implements HTTP admin API detection
func detectPulsarAdmin(conn net.Conn, isTLS bool, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Build HTTP GET request
	httpRequest := fmt.Sprintf(
		"GET /admin/v2/clusters HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Accept: application/json\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		conn.RemoteAddr().String(),
	)

	// Send and receive
	response, err := utils.SendRecv(conn, []byte(httpRequest), timeout)
	if err != nil {
		return nil, err
	}

	// Find header/body separator
	bodyStart := strings.Index(string(response), "\r\n\r\n")
	if bodyStart == -1 {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: PULSARADMIN,
			Info:    "no HTTP headers found",
		}
	}

	// Parse HTTP response
	responseStr := string(response)
	if !strings.HasPrefix(responseStr, "HTTP/1.1 200") && !strings.HasPrefix(responseStr, "HTTP/1.0 200") {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: PULSARADMIN,
			Info:    "non-200 HTTP response",
		}
	}

	// Extract body
	body := response[bodyStart+4:]

	// Try to parse as JSON array of cluster names
	var clusters []string
	if err := json.Unmarshal(body, &clusters); err != nil {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: PULSARADMIN,
			Info:    "invalid JSON response",
		}
	}

	// Success - Pulsar admin API detected
	return plugins.CreateServiceFrom(target, plugins.ServicePulsarAdmin{
		Clusters: clusters,
	}, isTLS, "", plugins.TCP), nil
}

// buildConnectFrame constructs a minimal Pulsar Connect frame
func buildConnectFrame() []byte {
	// Hand-craft protobuf for CommandConnect
	clientVersion := "Pulsar-Client-Go-v0.14.0"
	protocolVersion := 6

	// Protobuf encoding:
	// BaseCommand {
	//   type = 1 (CONNECT): 08 01
	//   connect = CommandConnect { ... }: 12 XX (XX = length of nested message)
	// }
	//
	// CommandConnect {
	//   client_version = "...": 0a + varint length + UTF-8 bytes
	//   protocol_version = 6: 20 06
	// }

	// Build CommandConnect nested message
	var connectMsg []byte

	// Field 1: client_version (tag 0a = field 1, wire type 2)
	connectMsg = append(connectMsg, 0x0a)
	connectMsg = append(connectMsg, byte(len(clientVersion)))
	connectMsg = append(connectMsg, []byte(clientVersion)...)

	// Field 4: protocol_version (tag 20 = field 4, wire type 0)
	connectMsg = append(connectMsg, 0x20)
	connectMsg = append(connectMsg, byte(protocolVersion))

	// Build BaseCommand
	var baseCmd []byte

	// Field 1: type = 2 (CONNECT)
	baseCmd = append(baseCmd, 0x08, 0x02)

	// Field 2: connect (nested message)
	baseCmd = append(baseCmd, 0x12)
	baseCmd = append(baseCmd, byte(len(connectMsg)))
	baseCmd = append(baseCmd, connectMsg...)

	// Build frame: [totalSize:4][cmdSize:4][protobuf bytes]
	cmdSize := uint32(len(baseCmd))
	totalSize := 4 + cmdSize // cmdSize field + protobuf bytes

	frame := make([]byte, 8+cmdSize)
	binary.BigEndian.PutUint32(frame[0:4], totalSize)
	binary.BigEndian.PutUint32(frame[4:8], cmdSize)
	copy(frame[8:], baseCmd)

	return frame
}

// decodeVarint reads a protobuf varint from pbData starting at pos.
// Returns the decoded value and the new position, or -1 for pos on error.
func decodeVarint(pbData []byte, pos int) (uint64, int) {
	var value uint64
	var shift uint
	for {
		if pos >= len(pbData) {
			return 0, -1
		}
		b := pbData[pos]
		pos++
		value |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return value, pos
		}
		shift += 7
		if shift > 63 {
			return 0, -1 // overflow protection
		}
	}
}

// extractServerVersion parses server_version from Connected response protobuf
func extractServerVersion(pbData []byte) string {
	// Walk through protobuf to find field 3 (connected)
	pos := 0
	for pos < len(pbData) {
		// Read tag
		tag, newPos := decodeVarint(pbData, pos)
		if newPos == -1 {
			break
		}
		pos = newPos

		fieldNum := tag >> 3
		wireType := tag & 0x07

		// Field 3 = connected (nested message, wire type 2 = length-delimited)
		if fieldNum == 3 && wireType == 2 {
			length, newPos := decodeVarint(pbData, pos)
			if newPos == -1 {
				break
			}
			pos = newPos

			end := pos + int(length)
			if end > len(pbData) || length > 4096 {
				break
			}

			// Parse nested CommandConnected message
			connectedMsg := pbData[pos:end]
			return parseServerVersionFromConnected(connectedMsg)
		} else if wireType == 0 {
			// Varint - skip it
			_, newPos := decodeVarint(pbData, pos)
			if newPos == -1 {
				break
			}
			pos = newPos
		} else if wireType == 2 {
			// Length-delimited - skip it
			length, newPos := decodeVarint(pbData, pos)
			if newPos == -1 {
				break
			}
			pos = newPos
			end := pos + int(length)
			if end > len(pbData) || length > 4096 {
				break
			}
			pos = end
		} else {
			// Unknown wire type - stop parsing
			break
		}
	}

	return ""
}

// parseServerVersionFromConnected extracts server_version from CommandConnected
func parseServerVersionFromConnected(pbData []byte) string {
	pos := 0
	for pos < len(pbData) {
		// Read tag
		tag, newPos := decodeVarint(pbData, pos)
		if newPos == -1 {
			break
		}
		pos = newPos

		fieldNum := tag >> 3
		wireType := tag & 0x07

		// Field 1 = server_version (string, wire type 2)
		if fieldNum == 1 && wireType == 2 {
			length, newPos := decodeVarint(pbData, pos)
			if newPos == -1 {
				break
			}
			pos = newPos

			end := pos + int(length)
			if end > len(pbData) || length > 256 {
				break
			}

			serverVersion := string(pbData[pos:end])

			// Extract version by trimming known prefixes
			if strings.HasPrefix(serverVersion, "Pulsar-Broker-v") {
				return strings.TrimPrefix(serverVersion, "Pulsar-Broker-v")
			}
			if strings.HasPrefix(serverVersion, "Pulsar Server") {
				return strings.TrimPrefix(serverVersion, "Pulsar Server")
			}

			return serverVersion
		} else if wireType == 0 {
			// Varint - skip
			_, newPos := decodeVarint(pbData, pos)
			if newPos == -1 {
				break
			}
			pos = newPos
		} else if wireType == 2 {
			// Length-delimited - skip
			length, newPos := decodeVarint(pbData, pos)
			if newPos == -1 {
				break
			}
			pos = newPos
			end := pos + int(length)
			if end > len(pbData) || length > 4096 {
				break
			}
			pos = end
		} else {
			break
		}
	}

	return ""
}

// buildCPE generates CPE string for vulnerability tracking
func buildCPE(version string) string {
	if version == "" {
		return ""
	}
	return fmt.Sprintf("cpe:2.3:a:apache:pulsar:%s:*:*:*:*:*:*:*", version)
}

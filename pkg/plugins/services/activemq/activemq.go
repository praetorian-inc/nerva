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
Package activemq implements service detection for Apache ActiveMQ using the OpenWire protocol.

Detection Strategy:
1. Sends minimal WIREFORMAT_INFO frame (21 bytes):
   - 4-byte size prefix (big-endian, value = 17)
   - 1-byte type (0x01 = WIREFORMAT_INFO)
   - 8-byte magic "ActiveMQ" (ASCII)
   - 4-byte protocol version (big-endian, value = 1)
   - 4-byte empty properties (big-endian, value = 0)
2. Validates server WIREFORMAT_INFO response:
   - Minimum 17 bytes required
   - Byte 4 must be 0x01 (WIREFORMAT_INFO type)
   - Bytes 5-12 must be "ActiveMQ" (magic bytes)
   - Bytes 13-16 contain protocol version (1-12 valid range)
3. Returns Service with protocol version or wildcard CPE if version unknown
*/
package activemq

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	ActiveMQOpenWire    = "activemq-openwire"
	ActiveMQOpenWireTLS = "activemq-openwire-tls"
	WireFormatInfo      = 0x01
	MagicBytes          = "ActiveMQ"
	MinResponseSize     = 17
	MaxProtocolVersion  = 12
	ActiveMQCPEMatch    = "cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*"
)

type Plugin struct{}
type TLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

// buildWireFormatInfo constructs the minimal OpenWire WIREFORMAT_INFO probe
func buildWireFormatInfo() []byte {
	// 21-byte probe: size(4) + type(1) + magic(8) + version(4) + properties(4)
	probe := make([]byte, 21)

	// Size prefix: 17 bytes (everything after this field)
	binary.BigEndian.PutUint32(probe[0:4], 17)

	// Type: WIREFORMAT_INFO (0x01)
	probe[4] = WireFormatInfo

	// Magic: "ActiveMQ" (8 bytes)
	copy(probe[5:13], MagicBytes)

	// Protocol version: 1 (4 bytes, big-endian)
	binary.BigEndian.PutUint32(probe[13:17], 1)

	// Empty properties: 0 (4 bytes, big-endian)
	binary.BigEndian.PutUint32(probe[17:21], 0)

	return probe
}

// isValidWireFormatInfo validates an OpenWire WIREFORMAT_INFO response
func isValidWireFormatInfo(response []byte) bool {
	// Minimum response: size(4) + type(1) + magic(8) + version(4) = 17 bytes
	if len(response) < MinResponseSize {
		return false
	}

	// Check type (0x01 = WIREFORMAT_INFO)
	if response[4] != WireFormatInfo {
		return false
	}

	// Check magic bytes "ActiveMQ"
	magic := string(response[5:13])
	if magic != MagicBytes {
		return false
	}

	return true
}

// parseProtocolVersion extracts the OpenWire protocol version from response
func parseProtocolVersion(response []byte) int {
	if len(response) < MinResponseSize {
		return 0
	}

	// Protocol version is at bytes 13-16 (big-endian uint32)
	version := binary.BigEndian.Uint32(response[13:17])

	// Valid OpenWire protocol versions are 1-12
	if version < 1 || version > MaxProtocolVersion {
		return 0
	}

	return int(version)
}

// DetectActiveMQ performs ActiveMQ OpenWire protocol detection
func DetectActiveMQ(conn net.Conn, timeout time.Duration) (version int, detected bool, err error) {
	// Send WIREFORMAT_INFO probe
	probe := buildWireFormatInfo()
	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return 0, false, err
	}

	if len(response) == 0 {
		return 0, false, &utils.ServerNotEnable{}
	}

	// Validate WIREFORMAT_INFO response
	if !isValidWireFormatInfo(response) {
		return 0, false, &utils.InvalidResponseError{Service: ActiveMQOpenWire}
	}

	// Extract protocol version
	version = parseProtocolVersion(response)

	return version, true, nil
}

// generateCPE creates CPE identifier for ActiveMQ services
func generateCPE(version int) []string {
	// OpenWire protocol version != ActiveMQ product version
	// Use wildcard CPE since we can't determine product version from protocol
	return []string{ActiveMQCPEMatch}
}

// Plugin implements TCP ActiveMQ OpenWire detection
func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	version, detected, err := DetectActiveMQ(conn, timeout)
	if err != nil {
		if _, ok := err.(*utils.ServerNotEnable); ok {
			return nil, nil
		}
		if _, ok := err.(*utils.InvalidResponseError); ok {
			return nil, nil
		}
		return nil, err
	}

	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceActiveMQOpenWire{
		Version: version,
		CPEs:    generateCPE(version),
	}

	// Version field in CreateServiceFrom is string representation of protocol version
	versionStr := ""
	if version > 0 {
		versionStr = fmt.Sprintf("%d", version)
	}

	return plugins.CreateServiceFrom(target, payload, false, versionStr, plugins.TCP), nil
}

func (p *Plugin) PortPriority(port uint16) bool {
	return port == 61616
}

func (p *Plugin) Name() string {
	return ActiveMQOpenWire
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 100
}

// TLSPlugin implements TLS ActiveMQ OpenWire detection
func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	version, detected, err := DetectActiveMQ(conn, timeout)
	if err != nil {
		if _, ok := err.(*utils.ServerNotEnable); ok {
			return nil, nil
		}
		if _, ok := err.(*utils.InvalidResponseError); ok {
			return nil, nil
		}
		return nil, err
	}

	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceActiveMQOpenWire{
		Version: version,
		CPEs:    generateCPE(version),
	}

	// Version field in CreateServiceFrom is string representation of protocol version
	versionStr := ""
	if version > 0 {
		versionStr = fmt.Sprintf("%d", version)
	}

	return plugins.CreateServiceFrom(target, payload, true, versionStr, plugins.TCP), nil
}

func (p *TLSPlugin) PortPriority(port uint16) bool {
	return port == 61617
}

func (p *TLSPlugin) Name() string {
	return ActiveMQOpenWireTLS
}

func (p *TLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *TLSPlugin) Priority() int {
	return 100
}

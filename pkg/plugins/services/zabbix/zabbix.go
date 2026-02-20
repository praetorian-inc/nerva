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

package zabbix

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type ZabbixAgentPlugin struct{}

const ZabbixAgent = "zabbix-agent"

var zbxdMagic = []byte{0x5A, 0x42, 0x58, 0x44} // "ZBXD"
var versionRegex = regexp.MustCompile(`^(\d+\.\d+\.\d+)`)

// buildZBXDRequest constructs a ZBXD-framed request for a given item key.
// Zabbix 5.4+ requires ZBXD header in requests; older versions accept both.
// Format: ZBXD(4) + FLAGS(1) + DATALEN(4 LE) + RESERVED(4 LE) + payload
func buildZBXDRequest(itemKey string) []byte {
	payload := []byte(itemKey)
	header := make([]byte, 13)
	copy(header[0:4], zbxdMagic)
	header[4] = 0x01 // standard flag
	binary.LittleEndian.PutUint32(header[5:9], uint32(len(payload)))
	binary.LittleEndian.PutUint32(header[9:13], 0) // reserved
	return append(header, payload...)
}

// parseZBXDResponse parses a ZBXD protocol response and returns the payload.
// Returns an error if the response is invalid or too short.
func parseZBXDResponse(data []byte) ([]byte, error) {
	if len(data) < 13 {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: ZabbixAgent,
			Info:    "response too short (need at least 13 bytes for ZBXD header)",
		}
	}

	// Check magic bytes
	if !bytes.Equal(data[0:4], zbxdMagic) {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: ZabbixAgent,
			Info:    "invalid ZBXD magic bytes",
		}
	}

	flags := data[4]

	// Check if standard flag is set (0x01)
	if flags&0x01 == 0 {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: ZabbixAgent,
			Info:    "invalid FLAGS byte (standard flag not set)",
		}
	}

	// Determine header size based on flags
	var datalen uint64
	var headerSize int

	if flags&0x04 != 0 {
		// Large packet: 8-byte datalen and reserved fields
		if len(data) < 21 {
			return nil, &utils.InvalidResponseErrorInfo{
				Service: ZabbixAgent,
				Info:    "response too short for large packet",
			}
		}
		datalen = binary.LittleEndian.Uint64(data[5:13])
		headerSize = 21
	} else {
		// Standard packet: 4-byte datalen and reserved fields
		datalen = uint64(binary.LittleEndian.Uint32(data[5:9]))
		headerSize = 13
	}

	// Validate we have enough data
	if len(data) < headerSize+int(datalen) {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: ZabbixAgent,
			Info:    fmt.Sprintf("incomplete payload (expected %d bytes, got %d)", headerSize+int(datalen), len(data)),
		}
	}

	payload := data[headerSize : headerSize+int(datalen)]
	return payload, nil
}

// extractVersion extracts the version string from the agent.version response payload.
// Returns empty string if version cannot be extracted.
func extractVersion(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}

	payloadStr := string(payload)

	// Check if this is a ZBX_NOTSUPPORTED response
	if strings.HasPrefix(payloadStr, "ZBX_NOTSUPPORTED") {
		return ""
	}

	// Extract version using regex (format: X.Y.Z)
	matches := versionRegex.FindStringSubmatch(payloadStr)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// buildZabbixAgentCPE generates a CPE (Common Platform Enumeration) string for Zabbix Agent.
// CPE format: cpe:2.3:a:zabbix:zabbix_agent:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" wildcard to enable asset inventory use cases
// even without precise version information.
func buildZabbixAgentCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:zabbix:zabbix_agent:%s:*:*:*:*:*:*:*", version)
}

// checkRemoteCommands checks if the Zabbix agent has remote commands enabled (RCE vulnerability).
// Returns true if remote commands are enabled, false otherwise.
func checkRemoteCommands(conn net.Conn, timeout time.Duration) bool {
	// Build ZBXD-framed system.run[id] probe (required for Zabbix 5.4+)
	probe := buildZBXDRequest("system.run[id]")

	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil || len(response) == 0 {
		// If error or no response, assume remote commands are disabled
		return false
	}

	// Parse the ZBXD response
	payload, err := parseZBXDResponse(response)
	if err != nil {
		// Invalid response means inconclusive, assume disabled
		return false
	}

	payloadStr := string(payload)

	// If response starts with ZBX_NOTSUPPORTED, remote commands are disabled (safe)
	if strings.HasPrefix(payloadStr, "ZBX_NOTSUPPORTED") {
		return false
	}

	// If we got a valid response (command output), remote commands are enabled (CRITICAL)
	return true
}

func init() {
	plugins.RegisterPlugin(&ZabbixAgentPlugin{})
}

func (p *ZabbixAgentPlugin) PortPriority(port uint16) bool {
	return port == 10050
}

func (p *ZabbixAgentPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Phase 1: Detection + Version
	// Build ZBXD-framed agent.version probe (required for Zabbix 5.4+)
	probe := buildZBXDRequest("agent.version")

	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Parse ZBXD response
	payload, err := parseZBXDResponse(response)
	if err != nil {
		// Not a valid Zabbix response
		return nil, nil
	}

	// Extract version (may be empty if ZBX_NOTSUPPORTED)
	version := extractVersion(payload)

	// Phase 2: RCE Check
	// Check if remote commands are enabled (uses same connection)
	remoteCommandsEnabled := checkRemoteCommands(conn, timeout)

	// Generate CPE (uses "*" for unknown version)
	cpe := buildZabbixAgentCPE(version)

	metadata := plugins.ServiceZabbixAgent{
		RemoteCommandsEnabled: remoteCommandsEnabled,
		CPEs:                  []string{cpe},
	}

	return plugins.CreateServiceFrom(target, metadata, false, version, plugins.TCP), nil
}

func (p *ZabbixAgentPlugin) Name() string {
	return ZabbixAgent
}

func (p *ZabbixAgentPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *ZabbixAgentPlugin) Priority() int {
	return 410
}

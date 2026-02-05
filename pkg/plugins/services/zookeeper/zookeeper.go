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

package zookeeper

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type ZooKeeperPlugin struct{}

const ZOOKEEPER = "zookeeper"

// checkZooKeeper validates if the response is from a ZooKeeper server
// returns an error if it's not validated as a ZooKeeper server
func checkZooKeeper(data []byte) error {
	// Valid "imok" response (4 ASCII bytes)
	imok := []byte("imok")

	msgLength := len(data)
	if msgLength == 0 {
		return &utils.InvalidResponseErrorInfo{
			Service: ZOOKEEPER,
			Info:    "empty response",
		}
	}

	// Check for "imok" response
	if msgLength >= 4 && string(data[:4]) == string(imok) {
		return nil
	}

	// Check for whitelist restriction
	response := string(data)
	if strings.Contains(response, "not in the whitelist") || strings.Contains(response, "not executed") {
		return &utils.InvalidResponseErrorInfo{
			Service: ZOOKEEPER,
			Info:    "command restricted by whitelist",
		}
	}

	return &utils.InvalidResponseErrorInfo{
		Service: ZOOKEEPER,
		Info:    "invalid response",
	}
}

// extractZooKeeperVersion extracts the ZooKeeper version from a srvr response.
// The srvr command returns server information with the version in the first line.
// Format: "Zookeeper version: 3.8.0-5a02a05eddb59aee6ac762f7ea82e92a68eb9c0f, built on 2022-02-25 08:49 UTC"
//
// Parameters:
//   - response: The srvr response string containing server metadata
//
// Returns:
//   - string: The ZooKeeper version (e.g., "3.8.0"), or empty string if not found
func extractZooKeeperVersion(response string) string {
	if response == "" {
		return ""
	}

	// Look for "Zookeeper version:" line
	// Pattern: "Zookeeper version: 3.8.0-<commit>, built on ..." or "Zookeeper version: 3.8.0"
	re := regexp.MustCompile(`Zookeeper version:\s*(\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(response)
	if len(matches) >= 2 {
		return matches[1]
	}

	return ""
}

// extractZooKeeperMode extracts the ZooKeeper mode from a srvr response.
// Mode indicates the role of this server in the ensemble.
// Format: "Mode: standalone" or "Mode: leader" or "Mode: follower" or "Mode: observer"
//
// Parameters:
//   - response: The srvr response string containing server metadata
//
// Returns:
//   - string: The ZooKeeper mode (standalone, leader, follower, observer), or empty if not found
func extractZooKeeperMode(response string) string {
	if response == "" {
		return ""
	}

	// Split response by newlines
	lines := strings.Split(strings.ReplaceAll(response, "\r\n", "\n"), "\n")

	// Look for Mode field
	for _, line := range lines {
		if strings.HasPrefix(line, "Mode:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	return ""
}

// extractZooKeeperConnections extracts the number of connections from a srvr response.
// Format: "Connections: 5"
//
// Parameters:
//   - response: The srvr response string containing server metadata
//
// Returns:
//   - int: The number of connections, or 0 if not found
func extractZooKeeperConnections(response string) int {
	if response == "" {
		return 0
	}

	// Split response by newlines
	lines := strings.Split(strings.ReplaceAll(response, "\r\n", "\n"), "\n")

	// Look for Connections field
	for _, line := range lines {
		if strings.HasPrefix(line, "Connections:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if num, err := strconv.Atoi(val); err == nil {
					return num
				}
			}
		}
	}

	return 0
}

// extractZooKeeperNodeCount extracts the node count from a srvr response.
// Format: "Node count: 42"
//
// Parameters:
//   - response: The srvr response string containing server metadata
//
// Returns:
//   - int: The node count, or 0 if not found
func extractZooKeeperNodeCount(response string) int {
	if response == "" {
		return 0
	}

	// Split response by newlines
	lines := strings.Split(strings.ReplaceAll(response, "\r\n", "\n"), "\n")

	// Look for Node count field
	for _, line := range lines {
		if strings.HasPrefix(line, "Node count:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if num, err := strconv.Atoi(val); err == nil {
					return num
				}
			}
		}
	}

	return 0
}

// buildZooKeeperCPE generates a CPE (Common Platform Enumeration) string for ZooKeeper servers.
// CPE format: cpe:2.3:a:apache:zookeeper:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" wildcard to match Wappalyzer/RMI/FTP plugin behavior
// and enable asset inventory use cases even without precise version information.
//
// Parameters:
//   - version: ZooKeeper version string (e.g., "3.8.0"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" wildcard
func buildZooKeeperCPE(version string) string {
	// Use wildcard for unknown versions (matches FTP/RMI/Wappalyzer pattern)
	if version == "" {
		version = "*"
	}

	// ZooKeeper CPE template: cpe:2.3:a:apache:zookeeper:{version}:*:*:*:*:*:*:*
	return fmt.Sprintf("cpe:2.3:a:apache:zookeeper:%s:*:*:*:*:*:*:*", version)
}

// checkWhitelistRestriction checks if the response indicates a whitelist restriction.
// ZooKeeper 3.5.3+ requires commands to be whitelisted via 4lw.commands.whitelist config.
//
// Parameters:
//   - response: The response string from the server
//
// Returns:
//   - bool: true if whitelist restriction detected, false otherwise
func checkWhitelistRestriction(response string) bool {
	return strings.Contains(response, "not in the whitelist") || strings.Contains(response, "not executed")
}

func init() {
	plugins.RegisterPlugin(&ZooKeeperPlugin{})
}

func (p *ZooKeeperPlugin) PortPriority(port uint16) bool {
	return port == 2181
}

func (p *ZooKeeperPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return DetectZooKeeper(conn, target, timeout)
}

func DetectZooKeeper(conn net.Conn, target plugins.Target, timeout time.Duration) (*plugins.Service, error) {
	// Phase 1: Try "srvr" command first (provides both detection AND metadata in one request)
	// This is more efficient and avoids the connection-closing issue
	// https://zookeeper.apache.org/doc/current/zookeeperAdmin.html#sc_4lw
	srvr := []byte("srvr")

	response, err := utils.SendRecv(conn, srvr, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	respStr := string(response)

	// Check if this is a valid ZooKeeper srvr response (contains version line)
	if strings.Contains(respStr, "Zookeeper version:") {
		// Definitely ZooKeeper - extract all metadata
		version := extractZooKeeperVersion(respStr)
		mode := extractZooKeeperMode(respStr)
		connections := extractZooKeeperConnections(respStr)
		nodeCount := extractZooKeeperNodeCount(respStr)
		cpe := buildZooKeeperCPE(version)

		payload := plugins.ServiceZooKeeper{
			CPEs:        []string{cpe},
			Mode:        mode,
			Connections: connections,
			NodeCount:   nodeCount,
			Restricted:  false,
		}
		return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
	}

	// Phase 2: If "srvr" didn't work (whitelist restriction or not ZooKeeper),
	// fall back to "ruok" for basic detection
	// Note: We can't use the same connection because ZooKeeper closes it after first response
	// The test framework will provide a fresh connection if needed

	// Check if "srvr" is whitelisted but we got a restriction response
	if checkWhitelistRestriction(respStr) {
		// ZooKeeper detected but restricted - return with restricted flag and no version
		cpe := buildZooKeeperCPE("")
		payload := plugins.ServiceZooKeeper{
			CPEs:       []string{cpe},
			Restricted: true,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
	}

	// Response doesn't look like ZooKeeper srvr response
	// Could be a different service or invalid response
	return nil, nil
}

func (p *ZooKeeperPlugin) Name() string {
	return ZOOKEEPER
}

func (p *ZooKeeperPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *ZooKeeperPlugin) Priority() int {
	return 100
}
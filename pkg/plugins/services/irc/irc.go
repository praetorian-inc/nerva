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

// Package irc implements IRC (Internet Relay Chat) service fingerprinting.
//
// Detection strategy:
//   - Sends NICK + USER commands and reads the welcome burst (numerics 001-005, 251)
//   - Validates response contains IRC numeric replies (3-digit codes)
//   - ERROR prefix on connection indicates server rejected us (K-lined, banned) - treated as not-IRC
//   - Extracts server name, network name, software, version, user count, and CPEs
//
// Default ports: 6667 (TCP), 6697 (TLS)
// Also common: 6660-6669 (TCP), 7000 (TCP)
package irc

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

const (
	ircPort     = 6667
	ircsPort    = 6697
	ircPriority = 110
)

// TCPPlugin implements IRC service fingerprinting over plain TCP.
type TCPPlugin struct{}

// TLSPlugin implements IRC service fingerprinting over TLS.
type TLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&TCPPlugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

// Type returns the protocol transport type for the TCP variant.
func (p *TCPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Type returns the protocol transport type for the TLS variant.
func (p *TLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

// Priority returns the scan priority for the TCP variant.
func (p *TCPPlugin) Priority() int {
	return ircPriority
}

// Priority returns the scan priority for the TLS variant.
func (p *TLSPlugin) Priority() int {
	return ircPriority + 1
}

// Name returns the plugin name for the TCP variant.
func (p *TCPPlugin) Name() string {
	return plugins.ProtoIRC
}

// Name returns the plugin name for the TLS variant.
func (p *TLSPlugin) Name() string {
	return plugins.ProtoIRCS
}

// PortPriority returns true if the port is a standard IRC port.
func (p *TCPPlugin) PortPriority(port uint16) bool {
	return port == ircPort || (port >= 6660 && port <= 6669) || port == 7000
}

// PortPriority returns true if the port is the standard IRCS port.
func (p *TLSPlugin) PortPriority(port uint16) bool {
	return port == ircsPort
}

// ircMessage represents a parsed IRC protocol message.
type ircMessage struct {
	prefix  string
	command string
	params  []string
	trail   string
}

// parseIRCLine parses a single IRC message line per RFC 1459:
//
//	[:prefix] COMMAND [params...] [:trailing]
func parseIRCLine(line string) ircMessage {
	line = strings.TrimRight(line, "\r\n")
	msg := ircMessage{}

	// Parse optional prefix
	if strings.HasPrefix(line, ":") {
		spaceIdx := strings.Index(line, " ")
		if spaceIdx == -1 {
			msg.prefix = line[1:]
			return msg
		}
		msg.prefix = line[1:spaceIdx]
		line = line[spaceIdx+1:]
	}

	// Split trailing parameter (after " :")
	trailIdx := strings.Index(line, " :")
	if trailIdx != -1 {
		msg.trail = line[trailIdx+2:]
		line = line[:trailIdx]
	}

	// Split remaining into command + params
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return msg
	}
	msg.command = parts[0]
	if len(parts) > 1 {
		msg.params = parts[1:]
	}

	return msg
}

// ircDetectResult holds parsed IRC server information.
type ircDetectResult struct {
	serverName     string
	networkName    string
	version        string
	serverSoftware string
	createdDate    string
	userModes      string
	channelModes   string
	userCount      int
	channelCount   int
}

var versionRe = regexp.MustCompile(`(?i)running version\s+(\S+)`)
var usersRe = regexp.MustCompile(`(?i)There are (\d+) users`)

// parseIRCResponse parses the IRC welcome burst and extracts server metadata.
// Returns nil if the response does not contain valid IRC numerics.
func parseIRCResponse(response string) *ircDetectResult {
	lines := strings.Split(response, "\n")
	result := &ircDetectResult{}
	foundNumeric := false

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}

		// ERROR prefix means connection rejected (K-line, ban, server full, etc.)
		// This is a valid IRC server response but we can't enumerate it properly.
		// Return nil to indicate "not our service to report".
		if strings.HasPrefix(line, "ERROR") {
			return nil
		}

		msg := parseIRCLine(line)
		if msg.command == "" {
			continue
		}

		switch msg.command {
		case "001": // RPL_WELCOME
			foundNumeric = true
			// params[0] is the nick; prefix is the server name
			if msg.prefix != "" {
				result.serverName = msg.prefix
			}
			// "Welcome to the NetworkName Internet Relay Chat Network nick"
			if msg.trail != "" {
				result.networkName = extractNetworkName(msg.trail)
			}

		case "002": // RPL_YOURHOST
			foundNumeric = true
			// "Your host is servername, running version DaemonName-X.Y.Z"
			if msg.trail != "" {
				software, ver := extractVersionInfo(msg.trail)
				result.serverSoftware = software
				result.version = ver
			}

		case "003": // RPL_CREATED
			foundNumeric = true
			// "This server was created DATE"
			if msg.trail != "" {
				prefix := "This server was created "
				if strings.HasPrefix(msg.trail, prefix) {
					result.createdDate = strings.TrimPrefix(msg.trail, prefix)
				} else {
					result.createdDate = msg.trail
				}
			}

		case "004": // RPL_MYINFO
			foundNumeric = true
			// params: nick servername version usermodes chanmodes
			// (some servers encode version here too)
			if len(msg.params) >= 5 {
				result.userModes = msg.params[3]
				result.channelModes = msg.params[4]
			} else if len(msg.params) == 4 {
				result.userModes = msg.params[3]
			}

		case "251": // RPL_LUSERCLIENT
			foundNumeric = true
			// "There are N users and M services on K servers"
			if msg.trail != "" {
				if m := usersRe.FindStringSubmatch(msg.trail); len(m) == 2 {
					n, err := strconv.Atoi(m[1])
					if err == nil {
						result.userCount = n
					}
				}
			}

		case "254": // RPL_LUSERCHANNELS
			foundNumeric = true
			// params: nick N; trail: "channels formed"
			if len(msg.params) >= 2 {
				if count, err := strconv.Atoi(msg.params[1]); err == nil {
					result.channelCount = count
				}
			}
		}
	}

	if !foundNumeric {
		return nil
	}

	return result
}

// extractNetworkName extracts the IRC network name from the RPL_WELCOME trailing text.
// Format: "Welcome to the NetworkName Internet Relay Chat Network nick"
func extractNetworkName(welcome string) string {
	prefix := "Welcome to the "
	if !strings.HasPrefix(welcome, prefix) {
		return ""
	}
	s := strings.TrimPrefix(welcome, prefix)

	// Remove trailing nick (last word)
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	// Remove last word (nick)
	s = strings.Join(words[:len(words)-1], " ")

	// Remove common network suffixes
	suffixes := []string{
		" Internet Relay Chat Network",
		" IRC Network",
		" Network",
	}
	for _, suffix := range suffixes {
		if strings.HasSuffix(s, suffix) {
			s = strings.TrimSuffix(s, suffix)
			break
		}
	}

	return strings.TrimSpace(s)
}

// extractVersionInfo extracts server software name and version from RPL_YOURHOST text.
// Format: "Your host is servername, running version DaemonName-X.Y.Z"
func extractVersionInfo(yourhost string) (software, version string) {
	m := versionRe.FindStringSubmatch(yourhost)
	if len(m) != 2 {
		return "", ""
	}
	versionStr := m[1]

	// Split software name from version number.
	// Daemons use formats like "UnrealIRCd-6.1.3", "InspIRCd-4.0.1", "ngIRCd-27"
	// Find the last '-' followed by a digit to split name/version.
	lastDash := strings.LastIndex(versionStr, "-")
	if lastDash != -1 && lastDash < len(versionStr)-1 {
		afterDash := versionStr[lastDash+1:]
		if len(afterDash) > 0 && (afterDash[0] >= '0' && afterDash[0] <= '9') {
			return versionStr[:lastDash], versionStr[lastDash+1:]
		}
	}

	// No version number split found; return full string as software
	return versionStr, ""
}

// knownDaemon maps a lowercase pattern to (vendor, product) for CPE generation.
type knownDaemon struct {
	pattern string
	vendor  string
	product string
}

var knownDaemons = []knownDaemon{
	{pattern: "unrealircd", vendor: "unrealircd", product: "unrealircd"},
	{pattern: "inspircd", vendor: "inspircd", product: "inspircd"},
	{pattern: "ircd-hybrid", vendor: "ircd-hybrid_project", product: "ircd-hybrid"},
	{pattern: "charybdis", vendor: "charybdis_project", product: "charybdis"},
	{pattern: "ngircd", vendor: "ngircd", product: "ngircd"},
	{pattern: "ircd-seven", vendor: "ircd-seven_project", product: "ircd-seven"},
	{pattern: "bahamut", vendor: "dal.net", product: "bahamut"},
	{pattern: "ircd-ratbox", vendor: "ircd-ratbox_project", product: "ircd-ratbox"},
}

// generateCPE creates a CPE 2.3 string for the identified IRC daemon.
// Version numbers are used as-is (dots preserved) since CPE 2.3 allows them.
// Unknown daemons use the normalized software name as both vendor and product.
func generateCPE(serverSoftware, version string) []string {
	if serverSoftware == "" {
		return nil
	}
	lower := strings.ToLower(serverSoftware)

	ver := version
	if ver == "" {
		ver = "*"
	}

	for _, d := range knownDaemons {
		if strings.Contains(lower, d.pattern) {
			cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", d.vendor, d.product, ver)
			return []string{cpe}
		}
	}

	// Unknown daemon: use normalized software name as vendor+product
	slug := normalizeCPE(serverSoftware)
	cpe := fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", slug, slug, ver)
	return []string{cpe}
}

// normalizeCPE converts a string to CPE-safe format (lowercase, alphanumeric + underscores).
// Spaces, hyphens and dots are replaced with underscores. Other characters are dropped.
// If the result contains only underscores or is empty, "*" is returned.
func normalizeCPE(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else if r == ' ' || r == '-' || r == '.' {
			b.WriteRune('_')
		}
	}
	result := strings.Trim(b.String(), "_")
	if result == "" {
		return "*"
	}
	return result
}

// detectIRC connects, sends NICK+USER, reads the welcome burst, and parses it.
func detectIRC(conn net.Conn, timeout time.Duration) (*ircDetectResult, error) {
	probe := []byte("NICK nervaprobe\r\nUSER nerva 0 * :nerva service detection\r\n")

	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}

	// Try to read more of the welcome burst with half the timeout
	more, _ := utils.Recv(conn, timeout/2)
	if len(more) > 0 {
		response = append(response, more...)
	}

	// Send QUIT for clean disconnect (best effort)
	_, _ = utils.SendRecv(conn, []byte("QUIT :nerva\r\n"), timeout/4)

	if len(response) == 0 {
		return nil, nil
	}

	return parseIRCResponse(string(response)), nil
}

// Run performs IRC service fingerprinting over plain TCP.
func (p *TCPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	result, err := detectIRC(conn, timeout)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}

	cpes := generateCPE(result.serverSoftware, result.version)

	payload := plugins.ServiceIRC{
		ServerName:     result.serverName,
		NetworkName:    result.networkName,
		Version:        result.version,
		ServerSoftware: result.serverSoftware,
		CreatedDate:    result.createdDate,
		UserModes:      result.userModes,
		ChannelModes:   result.channelModes,
		UserCount:      result.userCount,
		ChannelCount:   result.channelCount,
		CPEs:           cpes,
	}

	ver := result.version
	if ver == "" {
		ver = result.serverSoftware
	}

	return plugins.CreateServiceFrom(target, payload, false, ver, plugins.TCP), nil
}

// Run performs IRC service fingerprinting over TLS.
func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	result, err := detectIRC(conn, timeout)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}

	cpes := generateCPE(result.serverSoftware, result.version)

	payload := plugins.ServiceIRCS{
		ServerName:     result.serverName,
		NetworkName:    result.networkName,
		Version:        result.version,
		ServerSoftware: result.serverSoftware,
		CreatedDate:    result.createdDate,
		UserModes:      result.userModes,
		ChannelModes:   result.channelModes,
		UserCount:      result.userCount,
		ChannelCount:   result.channelCount,
		CPEs:           cpes,
	}

	ver := result.version
	if ver == "" {
		ver = result.serverSoftware
	}

	service := plugins.CreateServiceFrom(target, payload, true, ver, plugins.TCPTLS)
	if target.Misconfigs {
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

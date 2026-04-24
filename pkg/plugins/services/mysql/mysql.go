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

package mysql

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

/*
When we perform fingerprinting of the MySQL service, we can expect to get one
of two packets back from the server on the initial connection. The first would
be an initial handshake packet indicating we can authenticate to the server.

The second potential response would be an error message returned by the server
telling us why we can't authenticate. For example, the server may respond with
an error message stating the client IP is not allowed to authenticate to the
server.

 Example MySQL Initial Handshake Packet:
   Length: 4a 00 00 00
   Version: 0a
   Server Version: 38 2e 30  2e 32 38 00 (null terminated string "8.0.28")
   Connection Id: 0b 00 00 00
   Auth-Plugin-Data-Part-1: 15 05 6c 51 28 32 48 15
   Filler: 00
   Capability Flags: ff ff
   Character Set: ff
   Status Flags: 02 00
   Capability Flags: ff df
   Length of Auth Plugin Data: 15
   Reserved (all 00): 00 00 00 00 00 00 00 00 00 00
   Auth-Plugin-Data-Part-2 (len 13 base 10): 26 68 15 1e 2e 7f 69 38 52 6b 6c 5c 00
   Auth Plugin Name: null terminated string "caching_sha2_password"

 Example MySQL Error Packet on Initial Connection:
   Packet Length: 45 00 00 00
   Header: ff
   Error Code: 6a 04
   Human Readable Error Message: Host '50.82.91.234' is not allowed to connect to this MySQL server
*/

type MYSQLPlugin struct{}

const (
	// protocolVersion = 10
	maxPacketSize = 1 << 24 // 16MB max MySQL packet (MySQL protocol limit)
	MYSQL         = "MySQL"

	// MySQL capability flags (from MySQL protocol spec)
	clientProtocol41      = 1 << 9  // CLIENT_PROTOCOL_41
	clientSecureConnection = 1 << 15 // CLIENT_SECURE_CONNECTION
	clientPluginAuth      = 1 << 19 // CLIENT_PLUGIN_AUTH

	// MySQL response packet type bytes
	packetOK         = 0x00
	packetERR        = 0xFF
	packetAuthSwitch = 0xFE
)

// Version detection regex patterns for MySQL-family servers
// Priority order: Aurora → MariaDB → Percona → MySQL
var (
	// Aurora MySQL: {mysql_major}.mysql_aurora.{aurora_version}
	auroraRegex = regexp.MustCompile(`(\d+\.\d+)\.mysql_aurora\.(\d+\.\d+\.\d+)`)

	// MariaDB: {major}.{minor}.{patch}-MariaDB{optional-suffix}
	// Note: Older versions have "5.5.5-" prefix (RPL_VERSION_HACK) which must be stripped
	mariadbRegex = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)-MariaDB`)

	// Percona Server: {base_mysql_version}-{percona_build}
	perconaRegex = regexp.MustCompile(`^(\d+\.\d+\.\d+-\d+)`)

	// MySQL (Oracle): {major}.{minor}.{patch}{optional-suffix}
	mysqlRegex = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)
)

// CPE vendor/product mappings for MySQL-family servers
// CPE format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
var cpeTemplates = map[string]string{
	"mysql":   "cpe:2.3:a:oracle:mysql:%s:*:*:*:*:*:*:*",
	"mariadb": "cpe:2.3:a:mariadb:mariadb:%s:*:*:*:*:*:*:*",
	"percona": "cpe:2.3:a:percona:percona_server:%s:*:*:*:*:*:*:*",
	"aurora":  "cpe:2.3:a:amazon:aurora:%s:*:*:*:*:*:*:*",
}

func init() {
	plugins.RegisterPlugin(&MYSQLPlugin{})
}

// handshakeInfo holds auth-relevant fields parsed from the MySQL initial handshake packet.
type handshakeInfo struct {
	capabilityFlags uint32
	characterSet    byte
	authPluginName  string
}

// parseHandshake extracts auth-relevant fields from a MySQL initial handshake packet.
// Returns nil if the packet is malformed or too short.
func parseHandshake(response []byte) *handshakeInfo {
	// Minimum size: 4-byte header + 1 version + 1 null byte for version string + 13 fields
	if len(response) < 35 {
		return nil
	}

	// Byte 4: protocol version (must be 10)
	if response[4] != 10 {
		return nil
	}

	// Skip server version string (null-terminated), starting at byte 5
	pos := 5
	for pos < len(response) && response[pos] != 0x00 {
		pos++
	}
	if pos >= len(response) {
		return nil
	}
	pos++ // skip null terminator

	// Skip connection ID (4 bytes)
	pos += 4
	// Skip auth-plugin-data-part-1 (8 bytes)
	pos += 8

	// Filler byte must be 0x00
	if pos >= len(response) || response[pos] != 0x00 {
		return nil
	}
	pos++ // skip filler

	// Capability flags lower 2 bytes
	if pos+1 >= len(response) {
		return nil
	}
	capsLow := uint32(response[pos]) | uint32(response[pos+1])<<8
	pos += 2

	// Character set (1 byte)
	if pos >= len(response) {
		return nil
	}
	charSet := response[pos]
	pos++

	// Status flags (2 bytes) - skip
	pos += 2

	// Capability flags upper 2 bytes
	if pos+1 >= len(response) {
		return nil
	}
	capsHigh := uint32(response[pos]) | uint32(response[pos+1])<<8
	pos += 2

	caps := capsLow | (capsHigh << 16)

	// Auth plugin data length (1 byte)
	var authDataLen int
	if pos >= len(response) {
		return nil
	}
	authDataLen = int(response[pos])
	pos++

	// Reserved (10 bytes) - skip
	pos += 10

	// Auth-plugin-data-part-2: max(13, authDataLen-8) bytes if CLIENT_SECURE_CONNECTION
	if caps&uint32(clientSecureConnection) != 0 {
		part2Len := authDataLen - 8
		if part2Len < 13 {
			part2Len = 13
		}
		pos += part2Len
	}

	// Auth plugin name (null-terminated) if CLIENT_PLUGIN_AUTH
	authPluginName := ""
	if caps&uint32(clientPluginAuth) != 0 && pos < len(response) {
		end := pos
		for end < len(response) && response[end] != 0x00 {
			end++
		}
		authPluginName = string(response[pos:end])
	}

	return &handshakeInfo{
		capabilityFlags: caps,
		characterSet:    charSet,
		authPluginName:  authPluginName,
	}
}

// buildHandshakeResponse41 builds a MySQL HandshakeResponse41 packet with empty credentials.
func buildHandshakeResponse41(hs *handshakeInfo) []byte {
	// Client capability flags
	clientCaps := uint32(clientProtocol41 | clientSecureConnection)
	if hs.capabilityFlags&uint32(clientPluginAuth) != 0 {
		clientCaps |= uint32(clientPluginAuth)
	}

	payload := []byte{}

	// Capability flags (4 bytes, little-endian)
	payload = append(payload,
		byte(clientCaps&0xFF),
		byte((clientCaps>>8)&0xFF),
		byte((clientCaps>>16)&0xFF),
		byte((clientCaps>>24)&0xFF),
	)

	// Max packet size: 16MB (little-endian: 0x00, 0x00, 0x00, 0x01 = 16777216)
	payload = append(payload, 0x00, 0x00, 0x00, 0x01)

	// Character set
	payload = append(payload, hs.characterSet)

	// Reserved: 23 zero bytes
	payload = append(payload, make([]byte, 23)...)

	// Username: empty (just null terminator)
	payload = append(payload, 0x00)

	// Auth response: length-prefixed, length=0
	payload = append(payload, 0x00)

	// Auth plugin name (null-terminated) if CLIENT_PLUGIN_AUTH
	if clientCaps&uint32(clientPluginAuth) != 0 {
		payload = append(payload, []byte(hs.authPluginName)...)
		payload = append(payload, 0x00)
	}

	// Wrap in MySQL packet: 3-byte length (little-endian) + sequence number 1
	pktLen := len(payload)
	packet := []byte{
		byte(pktLen & 0xFF),
		byte((pktLen >> 8) & 0xFF),
		byte((pktLen >> 16) & 0xFF),
		0x01, // sequence number
	}
	packet = append(packet, payload...)
	return packet
}

// checkMySQLAuth attempts anonymous login against a MySQL server that has already
// sent its initial handshake. Returns true if anonymous access succeeds.
func checkMySQLAuth(conn net.Conn, timeout time.Duration, hs *handshakeInfo) bool {
	pkt := buildHandshakeResponse41(hs)
	resp, err := utils.SendRecv(conn, pkt, timeout)
	if err != nil || len(resp) < 5 {
		return false
	}

	// MySQL response payload starts at byte 4
	pktType := resp[4]
	switch pktType {
	case packetOK:
		return true
	case packetERR:
		return false
	case packetAuthSwitch:
		// Auth switch request: send empty auth response
		seqNum := resp[3] + 1
		emptyAuth := []byte{0x00, 0x00, 0x00, seqNum}
		resp2, err := utils.SendRecv(conn, emptyAuth, timeout)
		if err != nil || len(resp2) < 5 {
			return false
		}
		return resp2[4] == packetOK
	default:
		// caching_sha2_password fast auth success: 0x01 0x03
		if pktType == 0x01 && len(resp) > 5 && resp[5] == 0x03 {
			// The OK packet may be coalesced with the fast-auth packet in the same read.
			// Parse the first packet's length to find where the next packet starts.
			firstLen := int(resp[0]) | int(resp[1])<<8 | int(resp[2])<<16
			nextOffset := 4 + firstLen
			if len(resp) >= nextOffset+5 && resp[nextOffset+4] == packetOK {
				return true
			}
			// Read the following OK packet separately
			resp3, err := utils.Recv(conn, timeout)
			if err != nil || len(resp3) < 5 {
				return false
			}
			return resp3[4] == packetOK
		}
		return false
	}
}

// Run checks if the identified service is a MySQL (or MariaDB) server using
// two methods. Upon the connection of a client to a MySQL server it can return
// one of two responses. Either the server returns an initial handshake packet
// or an error message packet.
func (p *MYSQLPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	mysqlVersionStr, err := CheckInitialHandshakePacket(response)
	if err == nil {
		// Extract server type and version from version string
		serverType, version := parseVersionString(mysqlVersionStr)

		// Generate CPE for vulnerability tracking
		cpe := buildMySQLCPE(serverType, version)

		payload := plugins.ServiceMySQL{
			PacketType:   "handshake",
			ErrorMessage: "",
			ErrorCode:    0,
			CPEs:         []string{cpe},
		}
		service := plugins.CreateServiceFrom(target, payload, false, mysqlVersionStr, plugins.TCP)
		if target.Misconfigs {
			hs := parseHandshake(response)
			if hs != nil && checkMySQLAuth(conn, timeout, hs) {
				service.AnonymousAccess = true
				service.SecurityFindings = []plugins.SecurityFinding{{
					ID:          "mysql-no-auth",
					Severity:    plugins.SeverityCritical,
					Description: "MySQL accessible without authentication",
					Evidence:    "Anonymous login succeeded without credentials",
				}}
			}
		}
		return service, nil
	}

	errorStr, errorCode, err := CheckErrorMessagePacket(response)
	if err == nil {
		payload := plugins.ServiceMySQL{
			PacketType:   "error",
			ErrorMessage: errorStr,
			ErrorCode:    errorCode,
		}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
	}
	return nil, nil
}

func (p *MYSQLPlugin) PortPriority(port uint16) bool {
	return port == 3306
}

func (p *MYSQLPlugin) Name() string {
	return MYSQL
}
func (p *MYSQLPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *MYSQLPlugin) Priority() int {
	return 133
}

// CheckErrorMessagePacket checks the response packet error message
func CheckErrorMessagePacket(response []byte) (string, int, error) {
	// My brief research suggests that its not possible to get a compliant
	// error message packet that is less than eight bytes
	if len(response) < 8 {
		return "", 0, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet is too small for an error message packet",
		}
	}

	// MySQL uses 3 bytes for packet length (bytes 0-2), byte 3 is sequence number
	packetLength := int(
		uint32(response[0]) | uint32(response[1])<<8 | uint32(response[2])<<16,
	)

	// Validate packet length is within MySQL protocol limits
	if packetLength < 0 || packetLength > maxPacketSize {
		return "", 0, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length out of valid range",
		}
	}

	actualResponseLength := len(response) - 4

	if packetLength != actualResponseLength {
		return "", 0, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length does not match length of the response from the server",
		}
	}

	header := int(response[4])
	if header != 0xff {
		return "", 0, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet has an invalid header for an error message packet",
		}
	}

	errorCode := int(uint32(response[5]) | uint32(response[6])<<8)
	if errorCode < 1000 || errorCode > 2000 {
		return "", errorCode, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet has an invalid error code",
		}
	}

	errorStr, err := readEOFTerminatedASCIIString(response, 7)
	if err != nil {
		return "", errorCode, &utils.InvalidResponseErrorInfo{Service: MYSQL, Info: err.Error()}
	}

	return errorStr, errorCode, nil
}

// CheckInitialHandshakePacket checks if the response received from the server
// matches the expected response for the MySQL service
func CheckInitialHandshakePacket(response []byte) (string, error) {
	// My brief research suggests that its not possible to get a compliant
	// initial handshake packet that is less than roughly 35 bytes
	if len(response) < 35 {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length is too small for an initial handshake packet",
		}
	}

	// MySQL uses 3 bytes for packet length (bytes 0-2), byte 3 is sequence number
	packetLength := int(
		uint32(response[0]) | uint32(response[1])<<8 | uint32(response[2])<<16,
	)

	// Validate packet length is within MySQL protocol limits
	if packetLength < 0 || packetLength > maxPacketSize {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length out of valid range",
		}
	}

	version := int(response[4])

	if packetLength < 25 || packetLength > 4096 {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet length doesn't make sense for the MySQL handshake packet",
		}
	}

	if version != 10 {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "packet has an invalid version",
		}
	}

	mysqlVersionStr, position, err := readNullTerminatedASCIIString(response, 5)
	if err != nil {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "unable to read null-terminated ASCII version string, err: " + err.Error(),
		}
	}

	// If we skip the connection id and auth-plugin-data-part-1 fields the spec says
	// there is a filler byte that should always be zero at this position
	fillerPos := position + 13
	if position >= len(response) {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "buffer is too small to be a valid initial handshake packet",
		}
	}

	// According to the specification this should always be zero since it is a filler byte
	if response[fillerPos] != 0x00 {
		return "", &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info: fmt.Sprintf(
				"expected filler byte at ths position to be zero got: %d",
				response[fillerPos],
			),
		}
	}

	return mysqlVersionStr, nil
}

// parseVersionString extracts server type and version from MySQL version string.
//
// Detects MySQL-family servers in priority order:
//  1. Aurora MySQL (mysql_aurora keyword)
//  2. MariaDB (MariaDB keyword, strips legacy 5.5.5- prefix)
//  3. Percona Server (Percona keyword)
//  4. MySQL (Oracle) - default for valid version numbers
//  5. Unknown - fallback for invalid/missing version strings
//
// Parameters:
//   - versionStr: Version string from MySQL handshake packet
//
// Returns:
//   - serverType: One of "mysql", "mariadb", "percona", "aurora", "unknown"
//   - version: Extracted version string, or empty if not found
func parseVersionString(versionStr string) (string, string) {
	// Priority 1: Aurora MySQL (most specific marker)
	if strings.Contains(versionStr, "mysql_aurora") {
		if matches := auroraRegex.FindStringSubmatch(versionStr); len(matches) >= 3 {
			auroraVersion := matches[2] // Extract Aurora version (e.g., "3.11.0")
			return "aurora", auroraVersion
		}
	}

	// Priority 2: MariaDB (check for "MariaDB" keyword)
	if strings.Contains(versionStr, "MariaDB") {
		// Strip legacy 5.5.5- prefix (RPL_VERSION_HACK in older MariaDB versions)
		cleanStr := strings.Replace(versionStr, "5.5.5-", "", 1)
		if matches := mariadbRegex.FindStringSubmatch(cleanStr); len(matches) >= 4 {
			version := fmt.Sprintf("%s.%s.%s", matches[1], matches[2], matches[3])
			return "mariadb", version
		}
	}

	// Priority 3: Percona Server (check for "Percona" keyword)
	if strings.Contains(versionStr, "Percona") {
		if matches := perconaRegex.FindStringSubmatch(versionStr); len(matches) >= 2 {
			version := matches[1]
			return "percona", version
		}
	}

	// Priority 4: MySQL (Oracle) - default for valid version numbers
	if matches := mysqlRegex.FindStringSubmatch(versionStr); len(matches) >= 4 {
		version := fmt.Sprintf("%s.%s.%s", matches[1], matches[2], matches[3])
		return "mysql", version
	}

	// Priority 5: Unknown (fallback for invalid/missing version strings)
	return "unknown", ""
}

// buildMySQLCPE generates a CPE (Common Platform Enumeration) string for MySQL-family servers.
//
// Uses wildcard version ("*") when version is unknown to match Wappalyzer/RMI/FTP plugin
// behavior and enable asset inventory use cases even without precise version information.
//
// CPE format: cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*
//
// Vendor/product mappings:
//   - mysql   → cpe:2.3:a:oracle:mysql
//   - mariadb → cpe:2.3:a:mariadb:mariadb
//   - percona → cpe:2.3:a:percona:percona_server
//   - aurora  → cpe:2.3:a:amazon:aurora
//
// Parameters:
//   - serverType: Server type ("mysql", "mariadb", "percona", "aurora", "unknown", or empty)
//   - version: Version string (e.g., "8.0.28"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" wildcard
func buildMySQLCPE(serverType, version string) string {
	// Default to MySQL CPE for unknown/empty server types (MySQL-compatible assumption)
	if serverType == "" || serverType == "unknown" {
		serverType = "mysql"
	}

	// Use wildcard for unknown versions (matches FTP/RMI/Wappalyzer pattern)
	if version == "" {
		version = "*"
	}

	// Look up CPE template for this server type
	cpeTemplate, exists := cpeTemplates[serverType]
	if !exists {
		// Fallback to MySQL if server type not recognized
		cpeTemplate = cpeTemplates["mysql"]
	}

	// Format CPE with version
	return fmt.Sprintf(cpeTemplate, version)
}

// readNullTerminatedASCIIString is responsible for reading a null terminated
// ASCII string from a buffer and returns it as a string type
func readNullTerminatedASCIIString(buffer []byte, startPosition int) (string, int, error) {
	characters := []byte{}
	success := false
	endPosition := 0

	for position := startPosition; position < len(buffer); position++ {
		if buffer[position] >= 0x20 && buffer[position] <= 0x7E {
			characters = append(characters, buffer[position])
		} else if buffer[position] == 0x00 {
			success = true
			endPosition = position
			break
		} else {
			return "", 0, &utils.InvalidResponseErrorInfo{Service: MYSQL, Info: "encountered invalid ASCII character"}
		}
	}

	if !success {
		return "", 0, &utils.InvalidResponseErrorInfo{
			Service: MYSQL,
			Info:    "hit the end of the buffer without encountering a null terminator",
		}
	}

	return string(characters), endPosition, nil
}

// readEOFTerminatedASCIIString is responsible for reading an ASCII string
// that is terminated by the end of the message
func readEOFTerminatedASCIIString(buffer []byte, startPosition int) (string, error) {
	characters := []byte{}

	for position := startPosition; position < len(buffer); position++ {
		if buffer[position] >= 0x20 && buffer[position] <= 0x7E {
			characters = append(characters, buffer[position])
		} else {
			return "", &utils.InvalidResponseErrorInfo{Service: MYSQL, Info: "encountered invalid ASCII character"}
		}
	}

	return string(characters), nil
}

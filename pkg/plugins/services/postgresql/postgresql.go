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

package postgres

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type POSTGRESPlugin struct{}

const POSTGRES = "postgres"

// https://www.postgresql.org/docs/current/protocol-flow.html
// the following three values are the only three valid responses
// from a server for the first byte
const ErrorResponse byte = 0x45

// all of the following messages start with R (0x52)
// AuthenticationOk
// AuthenticationKerberosV5
// AuthenticationCleartextPassword
// AuthenticationMD5Password
// AuthenticationSCMCredential
// AuthenticationGSS
// AuthenticationSSPI
// AuthenticationGSSContinue
// AuthenticationSASL
// AuthenticationSASLContinue
// AuthenticationSASLFinal
// NegotiateProtocolVersion
const AuthReq byte = 0x52

const NegotiateProtocolVersion = 0x76

// parseParameterStatus parses a PostgreSQL ParameterStatus message ('S' type).
//
// ParameterStatus message format:
//
//	Byte 0:       'S' (0x53) - Message type identifier
//	Bytes 1-4:    Message length (Int32, big-endian, includes itself)
//	Bytes 5+:     Parameter name (null-terminated C string)
//	Following:    Parameter value (null-terminated C string)
//
// Parameters:
//   - msg: The raw message bytes from the PostgreSQL server
//
// Returns:
//   - name: Parameter name (e.g., "server_version")
//   - value: Parameter value (e.g., "14.5")
//   - error: Non-nil if message is invalid or malformed
func parseParameterStatus(msg []byte) (string, string, error) {
	// Validate minimum length: type(1) + length(4) + name(1+) + value(1+)
	if len(msg) < 7 {
		return "", "", &utils.InvalidResponseErrorInfo{
			Service: POSTGRES,
			Info:    "ParameterStatus message too short",
		}
	}

	// Verify message type is 'S' (ParameterStatus)
	if msg[0] != 0x53 {
		return "", "", &utils.InvalidResponseErrorInfo{
			Service: POSTGRES,
			Info:    fmt.Sprintf("expected ParameterStatus type 'S' (0x53), got 0x%02x", msg[0]),
		}
	}

	// Extract parameter name (null-terminated string starting at byte 5)
	nameStart := 5
	nameEnd := bytes.IndexByte(msg[nameStart:], 0)
	if nameEnd == -1 {
		return "", "", &utils.InvalidResponseErrorInfo{
			Service: POSTGRES,
			Info:    "parameter name missing null terminator",
		}
	}
	name := string(msg[nameStart : nameStart+nameEnd])

	// Extract parameter value (null-terminated string after name)
	valueStart := nameStart + nameEnd + 1
	if valueStart >= len(msg) {
		return "", "", &utils.InvalidResponseErrorInfo{
			Service: POSTGRES,
			Info:    "message truncated before parameter value",
		}
	}

	valueEnd := bytes.IndexByte(msg[valueStart:], 0)
	if valueEnd == -1 {
		return "", "", &utils.InvalidResponseErrorInfo{
			Service: POSTGRES,
			Info:    "parameter value missing null terminator",
		}
	}
	value := string(msg[valueStart : valueStart+valueEnd])

	return name, value, nil
}

func verifyPSQL(data []byte) bool {
	msgLength := len(data)
	if msgLength < 6 {
		// from reading (https://www.postgresql.org/docs/14/protocol-message-formats.html)
		// no valid server response from the startup packet can be less than 6 bytes
		return false
	}

	// (heuristic) Check if length of error or authentication method is reasonable
	// (assume length is less than 16 bits)
	if data[1] != 0 || data[2] != 0 {
		return false
	}

	// ErrorResponse or NegotiateProtocolVersion status codes are probably a PSQL server
	if data[0] == ErrorResponse || data[0] == NegotiateProtocolVersion {
		return true
	}

	// A message starting with AuthReq is likely a PSQL server
	if data[0] == AuthReq {
		return true
	}

	// Anything else is not a valid server response
	return false
}

// parse the message from the PSQL server to see if it requires AUTH
// a valid AUTH_OK message is:
// [AuthReq UINT32(8) UINT32(0)]
func successfulAuth(data []byte) bool {
	msgLength := len(data)
	// the AUTH_OK message is 9 bytes
	if msgLength < 9 {
		return false
	}
	if data[0] != AuthReq {
		return false
	}
	length := binary.BigEndian.Uint32(data[1:5])
	if length != 8 {
		return false
	}
	msg := binary.BigEndian.Uint32(data[5:9])
	return msg == 0
}

// buildPostgreSQLCPE generates a CPE (Common Platform Enumeration) string for PostgreSQL.
//
// Uses wildcard version ("*") when version is unknown to match FTP/MySQL plugin
// behavior and enable asset inventory use cases even without precise version information.
//
// CPE format: cpe:2.3:a:postgresql:postgresql:{version}:*:*:*:*:*:*:*
//
// Parameters:
//   - version: Version string (e.g., "14.5", "16.1"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" wildcard
func buildPostgreSQLCPE(version string) string {
	// Use wildcard for unknown versions (matches FTP/MySQL pattern)
	if version == "" {
		version = "*"
	}

	// Format CPE with version
	return fmt.Sprintf("cpe:2.3:a:postgresql:postgresql:%s:*:*:*:*:*:*:*", version)
}

func init() {
	plugins.RegisterPlugin(&POSTGRESPlugin{})
}

func (p *POSTGRESPlugin) PortPriority(port uint16) bool {
	return port == 5432
}

func (p *POSTGRESPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	startupPacket := []byte{
		0x00, 0x00, 0x00, 0x54, 0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72, 0x00, 0x70, 0x6f, 0x73,
		0x74, 0x67, 0x72, 0x65, 0x73, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x00, 0x70,
		0x6f, 0x73, 0x74, 0x67, 0x72, 0x65, 0x73, 0x00, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74,
		0x69, 0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x70, 0x73, 0x71, 0x6c, 0x00, 0x63, 0x6c,
		0x69, 0x65, 0x6e, 0x74, 0x5f, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00, 0x55, 0x54,
		0x46, 0x38, 0x00, 0x00,
	}

	response, err := utils.SendRecv(conn, startupPacket, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	isPSQL := verifyPSQL(response)
	if !isPSQL {
		return nil, nil
	}

	version := extractServerVersion(response)
	cpe := buildPostgreSQLCPE(version)

	payload := plugins.ServicePostgreSQL{
		AuthRequired: !successfulAuth(response),
		CPEs:         []string{cpe},
	}
	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	if target.Misconfigs && !payload.AuthRequired {
		service.AnonymousAccess = true
		service.SecurityFindings = []plugins.SecurityFinding{{
			ID:          "postgresql-no-auth",
			Severity:    plugins.SeverityCritical,
			Description: "PostgreSQL accessible without authentication",
			Evidence:    "Connection succeeded without credentials",
		}}
	}
	if target.Misconfigs {
		if finding := checkPostgresEOL(version); finding != nil {
			service.SecurityFindings = append(service.SecurityFindings, *finding)
		}
	}
	return service, nil
}

type eolEntry struct {
	name     string
	severity plugins.Severity
}

var postgresEOLMap = map[string]eolEntry{
	"9.1": {"PostgreSQL 9.1", plugins.SeverityLow},
}

// extractServerVersion walks type+int32-length frames and returns the
// server_version ParameterStatus value, or "" if none is present.
func extractServerVersion(response []byte) string {
	i := 0
	for i+5 <= len(response) {
		typ := response[i]
		length := int(binary.BigEndian.Uint32(response[i+1 : i+5]))
		if length < 4 || i+1+length > len(response) {
			break
		}
		frame := response[i : i+1+length]
		if typ == 0x53 {
			name, value, err := parseParameterStatus(frame)
			if err == nil && name == "server_version" {
				return value
			}
		}
		i += 1 + length
	}
	return ""
}

// checkPostgresEOL maps a server_version string to a SecurityFinding if the
// PostgreSQL version is end-of-life (major.minor 9.1). Returns nil otherwise.
func checkPostgresEOL(version string) *plugins.SecurityFinding {
	version = strings.TrimSpace(version)
	major, rest, ok := postgresLeadingInt(version)
	if !ok {
		return nil
	}
	minor := 0
	if strings.HasPrefix(rest, ".") {
		minor, _, ok = postgresLeadingInt(rest[1:])
		if !ok {
			return nil
		}
	}
	entry, found := postgresEOLMap[fmt.Sprintf("%d.%d", major, minor)]
	if !found {
		return nil
	}
	return &plugins.SecurityFinding{
		ID:          "postgres-eol",
		Severity:    entry.severity,
		Description: fmt.Sprintf("PostgreSQL running end-of-life version: %s", entry.name),
		Evidence:    version,
	}
}

func postgresLeadingInt(s string) (int, string, bool) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, s, false
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0, s, false
	}
	return n, s[i:], true
}

func (p *POSTGRESPlugin) Name() string {
	return POSTGRES
}
func (p *POSTGRESPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *POSTGRESPlugin) Priority() int {
	return 1000
}

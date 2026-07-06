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

package amqp

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	AMQP              = "amqp"
	AMQPS             = "amqps"
	FrameTypeMethod   = 0x01
	ConnectionClass   = 10
	ConnectionStart   = 10
	ConnectionStartOk = 11
	ConnectionTune    = 30
	FrameEnd          = 0xCE
	MinFrameSize      = 8
	RabbitMQCPEMatch  = "cpe:2.3:a:pivotal_software:rabbitmq"
)

type AMQPPlugin struct{}
type TLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&AMQPPlugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

// buildProtocolHeader constructs the AMQP 0-9-1 protocol header
func buildProtocolHeader() []byte {
	return []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}
}

// isValidConnectionStart validates an AMQP Connection.Start method frame
func isValidConnectionStart(response []byte) bool {
	// Minimum frame: type(1) + channel(2) + size(4) + class(2) + method(2) + end(1) = 12 bytes
	if len(response) < 12 {
		return false
	}

	// Check frame type (0x01 = Method)
	if response[0] != FrameTypeMethod {
		return false
	}

	// Check channel (should be 0x0000)
	channel := binary.BigEndian.Uint16(response[1:3])
	if channel != 0 {
		return false
	}

	// Parse payload size
	payloadSize := binary.BigEndian.Uint32(response[3:7])
	expectedLen := 7 + int(payloadSize) + 1 // header(7) + payload + frame-end(1)
	if len(response) < expectedLen {
		return false
	}

	// Check class ID (10 = Connection)
	classID := binary.BigEndian.Uint16(response[7:9])
	if classID != ConnectionClass {
		return false
	}

	// Check method ID (10 = Start)
	methodID := binary.BigEndian.Uint16(response[9:11])
	if methodID != ConnectionStart {
		return false
	}

	// Check frame end marker
	frameEndPos := 7 + int(payloadSize)
	if frameEndPos < len(response) && response[frameEndPos] != FrameEnd {
		return false
	}

	return true
}

// parseServerProperties extracts product, version, and platform from AMQP field table
func parseServerProperties(data []byte) (product, version, platform string) {
	if len(data) < 4 {
		return "", "", ""
	}

	tableLen := binary.BigEndian.Uint32(data[0:4])
	if len(data) < int(4+tableLen) {
		return "", "", ""
	}

	pos := 4
	end := 4 + int(tableLen)

	for pos < end {
		// Read field name length
		if pos >= end {
			break
		}
		nameLen := int(data[pos])
		pos++

		if pos+nameLen > end {
			break
		}

		// Read field name
		fieldName := string(data[pos : pos+nameLen])
		pos += nameLen

		// Read field type
		if pos >= end {
			break
		}
		fieldType := data[pos]
		pos++

		// Parse value based on type
		var value string
		switch fieldType {
		case 'S': // Long string
			if pos+4 > end {
				return product, version, platform
			}
			valueLen := binary.BigEndian.Uint32(data[pos : pos+4])
			pos += 4

			if pos+int(valueLen) > end {
				return product, version, platform
			}
			value = string(data[pos : pos+int(valueLen)])
			pos += int(valueLen)

		case 's': // Short string
			if pos+1 > end {
				return product, version, platform
			}
			valueLen := int(data[pos])
			pos++

			if pos+valueLen > end {
				return product, version, platform
			}
			value = string(data[pos : pos+valueLen])
			pos += valueLen

		case 'F': // Field table (nested)
			if pos+4 > end {
				return product, version, platform
			}
			// Skip nested table: 4-byte length + content
			nestedLen := binary.BigEndian.Uint32(data[pos : pos+4])
			pos += 4 + int(nestedLen)
			if pos > end {
				return product, version, platform
			}
			continue // Skip to next field (no value to extract)

		case 't': // Boolean
			if pos+1 > end {
				return product, version, platform
			}
			pos++    // Skip 1 byte
			continue // Skip to next field (no value to extract)

		case 'I': // Signed 32-bit integer
			if pos+4 > end {
				return product, version, platform
			}
			pos += 4 // Skip 4 bytes
			continue // Skip to next field (no value to extract)

		case 'l': // Signed 64-bit integer
			if pos+8 > end {
				return product, version, platform
			}
			pos += 8 // Skip 8 bytes
			continue // Skip to next field (no value to extract)

		default:
			// Skip unknown types by returning early
			// This preserves backward compatibility if new types are added
			return product, version, platform
		}

		// Store recognized fields
		switch fieldName {
		case "product":
			product = value
		case "version":
			version = value
		case "platform":
			platform = value
		}
	}

	return product, version, platform
}

// trySASLAuth sends an AMQP Connection.StartOk frame with the given SASL PLAIN
// response bytes on the already-open conn (after DetectAMQP consumed the
// Connection.Start frame). It returns true if the server responds with
// Connection.Tune (class 10, method 30), indicating the credentials were accepted.
//
// Limitation: SASL PLAIN is a single-step mechanism (RFC 4616), so Connection.Secure
// (class 10, method 20) is not expected and not handled. A broker that uses multi-step
// SASL for PLAIN authentication would be reported as "not vulnerable" (false negative).
// No known AMQP 0-9-1 broker exhibits this behavior.
func trySASLAuth(conn net.Conn, timeout time.Duration, saslResponse []byte) bool {
	// Build Connection.StartOk payload:
	//   class-id (2)       = 0x000A (10)
	//   method-id (2)      = 0x000B (11)
	//   client-properties (4) = 0x00000000 (empty table)
	//   mechanism: short string "PLAIN" (1-byte length + 5 bytes)
	//   response: long string (4-byte length + len(saslResponse) bytes)
	//   locale: short string "en_US" (1-byte length + 5 bytes)
	payload := []byte{
		0x00, 0x0A, // class-id: 10 (Connection)
		0x00, 0x0B, // method-id: 11 (StartOk)
		0x00, 0x00, 0x00, 0x00, // client-properties: empty table
		0x05, 'P', 'L', 'A', 'I', 'N', // mechanism: "PLAIN" (short string)
	}
	responseLen := make([]byte, 4)
	binary.BigEndian.PutUint32(responseLen, uint32(len(saslResponse))) // #nosec G115 -- saslResponse is locally constructed (a few bytes); cannot overflow uint32
	payload = append(payload, responseLen...)
	payload = append(payload, saslResponse...)
	payload = append(payload, 0x05, 'e', 'n', '_', 'U', 'S') // locale: "en_US"

	// Build the full Method frame:
	//   frame-type (1) = 0x01
	//   channel (2)    = 0x0000
	//   payload-size (4)
	//   payload
	//   frame-end (1)  = 0xCE
	frame := make([]byte, 7+len(payload)+1)
	frame[0] = FrameTypeMethod
	frame[1] = 0x00
	frame[2] = 0x00
	binary.BigEndian.PutUint32(frame[3:7], uint32(len(payload))) // #nosec G115 -- payload is locally constructed (~36 bytes); cannot overflow uint32
	copy(frame[7:], payload)
	frame[7+len(payload)] = FrameEnd

	response, err := utils.SendRecv(conn, frame, timeout)
	if err != nil || len(response) < 12 {
		return false
	}

	// Validate Connection.Tune response:
	//   frame-type must be 0x01 (Method)
	//   channel must be 0x0000
	//   payload-size must be plausible and consistent with response length
	//   frame-end marker must be 0xCE
	//   class-id at bytes 7-8 must be 0x000A (10 = Connection)
	//   method-id at bytes 9-10 must be 0x001E (30 = Tune)
	if response[0] != FrameTypeMethod || binary.BigEndian.Uint16(response[1:3]) != 0 {
		return false
	}
	payloadSize := binary.BigEndian.Uint32(response[3:7])
	frameLen := uint64(7) + uint64(payloadSize) + 1
	if payloadSize < 4 || frameLen > uint64(len(response)) || response[7+int(payloadSize)] != FrameEnd {
		return false
	}
	classID := binary.BigEndian.Uint16(response[7:9])
	methodID := binary.BigEndian.Uint16(response[9:11])
	return classID == ConnectionClass && methodID == ConnectionTune
}

// checkDefaultCredentials sends SASL PLAIN guest/guest credentials on the
// already-open conn. It returns true if the server accepts them.
func checkDefaultCredentials(conn net.Conn, timeout time.Duration) bool {
	return trySASLAuth(conn, timeout, []byte("\x00guest\x00guest"))
}

// amqpDefaultCredsFinding returns a SecurityFinding for AMQP default guest/guest credentials.
func amqpDefaultCredsFinding(product string) plugins.SecurityFinding {
	evidence := "SASL PLAIN authentication succeeded with default credentials"
	if product != "" {
		evidence = fmt.Sprintf("SASL PLAIN authentication succeeded with default credentials on %s", product)
	}
	return plugins.SecurityFinding{
		ID:          "amqp-default-creds",
		Severity:    plugins.SeverityHigh,
		Description: "AMQP service accepts default guest/guest credentials",
		Evidence:    evidence,
	}
}

// amqpAnonymousAccessFinding returns a SecurityFinding for AMQP anonymous access
// (SASL PLAIN authentication accepted with no credentials).
func amqpAnonymousAccessFinding(product string) plugins.SecurityFinding {
	evidence := "SASL PLAIN authentication succeeded without credentials"
	if product != "" {
		evidence = fmt.Sprintf("SASL PLAIN authentication succeeded without credentials on %s", product)
	}
	return plugins.SecurityFinding{
		ID:          "amqp-anonymous-access",
		Severity:    plugins.SeverityHigh,
		Description: "AMQP service allows anonymous access without credentials",
		Evidence:    evidence,
	}
}

// probeDefaultCredentials opens a new connection to target, performs the AMQP
// handshake, and checks for guest/guest default credentials. It is used as a
// fallback when the anonymous access check on the original connection fails.
func probeDefaultCredentials(target plugins.Target, timeout time.Duration, useTLS bool) bool {
	var conn net.Conn
	var err error

	if useTLS {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target.Address.String(), &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- scanner probing untrusted targets; cert validation would prevent detection
	} else {
		conn, err = net.DialTimeout("tcp", target.Address.String(), timeout)
	}
	if err != nil {
		return false
	}
	defer conn.Close()

	_, _, _, detected, err := DetectAMQP(conn, timeout)
	if err != nil || !detected {
		return false
	}

	return checkDefaultCredentials(conn, timeout)
}

// DetectAMQP performs AMQP protocol detection
func DetectAMQP(conn net.Conn, timeout time.Duration) (product, version, platform string, detected bool, err error) {
	// Send AMQP 0-9-1 protocol header
	header := buildProtocolHeader()
	response, err := utils.SendRecv(conn, header, timeout)
	if err != nil {
		return "", "", "", false, err
	}

	if len(response) == 0 {
		return "", "", "", false, &utils.ServerNotEnable{}
	}

	// Validate Connection.Start response
	if !isValidConnectionStart(response) {
		return "", "", "", false, &utils.InvalidResponseError{Service: AMQP}
	}

	// Parse server properties from Connection.Start frame
	// Server properties start at byte 11 (after version major/minor at bytes 11-12)
	if len(response) > 13 {
		// Skip: frame-type(1) + channel(2) + size(4) + class(2) + method(2) + version(2) = 13
		product, version, platform = parseServerProperties(response[13:])
	}

	return product, version, platform, true, nil
}

// generateCPE creates CPE identifiers for AMQP services
func generateCPE(product, version string) []string {
	if product == "" {
		return nil
	}

	// Only generate CPE for RabbitMQ
	if product != "RabbitMQ" {
		return nil
	}

	if version == "" {
		return []string{fmt.Sprintf("%s:*:*:*:*:*:*:*:*", RabbitMQCPEMatch)}
	}

	return []string{fmt.Sprintf("%s:%s:*:*:*:*:*:*:*", RabbitMQCPEMatch, version)}
}

// AMQPPlugin implements TCP AMQP detection
func (p *AMQPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	product, version, platform, detected, err := DetectAMQP(conn, timeout)
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

	payload := plugins.ServiceAMQP{
		Product:  product,
		Version:  version,
		Platform: platform,
		CPEs:     generateCPE(product, version),
	}

	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	if target.Misconfigs {
		if trySASLAuth(conn, timeout, []byte("\x00\x00")) {
			service.AnonymousAccess = true
			service.SecurityFindings = []plugins.SecurityFinding{amqpAnonymousAccessFinding(product)}
		} else if probeDefaultCredentials(target, timeout, false) {
			service.SecurityFindings = []plugins.SecurityFinding{amqpDefaultCredsFinding(product)}
		}
	}
	return service, nil
}

func (p *AMQPPlugin) PortPriority(port uint16) bool {
	return port == 5672
}

func (p *AMQPPlugin) Name() string {
	return AMQP
}

func (p *AMQPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *AMQPPlugin) Priority() int {
	return 100
}

// TLSPlugin implements TLS AMQP detection
func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	product, version, platform, detected, err := DetectAMQP(conn, timeout)
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

	payload := plugins.ServiceAMQP{
		Product:  product,
		Version:  version,
		Platform: platform,
		CPEs:     generateCPE(product, version),
	}

	service := plugins.CreateServiceFrom(target, payload, true, version, plugins.TCP)
	if target.Misconfigs {
		if trySASLAuth(conn, timeout, []byte("\x00\x00")) {
			service.AnonymousAccess = true
			service.SecurityFindings = []plugins.SecurityFinding{amqpAnonymousAccessFinding(product)}
		} else if probeDefaultCredentials(target, timeout, true) {
			service.SecurityFindings = []plugins.SecurityFinding{amqpDefaultCredsFinding(product)}
		}
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *TLSPlugin) PortPriority(port uint16) bool {
	return port == 5671
}

func (p *TLSPlugin) Name() string {
	return AMQPS
}

func (p *TLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *TLSPlugin) Priority() int {
	return 100
}

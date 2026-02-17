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
Package kerberos implements a Kerberos v5 service detection plugin for Nerva.

Detection Strategy:

The plugin uses a two-phase approach to detect Kerberos services:

Phase 1 - Service Detection (detectKerberos):
  - Sends a minimal AS-REQ (Authentication Service Request) for realm "NM" and principal "NM"
  - This is the same probe used by Nmap's kerberos-sec scanner
  - For TCP, the AS-REQ is prefixed with a 4-byte big-endian length (113 = 0x71)
  - Validates the response by checking:
    1. Response length (minimum 10 bytes: 4-byte TCP length + 6 bytes Kerberos data)
    2. Kerberos message type (0x7E for KRB-ERROR or 0x6B for AS-REP)
    3. Protocol version (pvno=5 pattern: \xa0\x03\x02\x01\x05)

Phase 2 - Metadata Extraction (parseKerberosError):
  - Parses the KRB-ERROR response for additional information
  - Extracts error-code field (context tag [6])
  - Extracts realm field (context tag [9])
  - Extracts optional e-text field (context tag [11])
  - All extractions are best-effort with defensive bounds checking

The AS-REQ probe structure (113 bytes DER-encoded):
  - Application tag 0x6A (AS-REQ)
  - Contains realm "NM" (0x4E 0x4D)
  - Contains principal "krbtgt/NM"
  - Timestamp: 1970-01-01 00:00:00Z (epoch)
  - Random nonce: 0x1f1eb9d9
  - Supported encryption types: 18, 17, 16, 23, 1, 3, 2

This probe is proven by Nmap and triggers consistent responses from Kerberos KDCs.
*/
package kerberos

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type KerberosPlugin struct{}

const KERBEROS = "kerberos"

const (
	tagKRBError = 0x7E // APPLICATION 30, constructed
	tagASREP    = 0x6B // APPLICATION 11, constructed
)

// The raw AS-REQ bytes (113 bytes) - proven by Nmap
var asReqProbe = []byte{
	0x6a, 0x81, 0x6e, 0x30, 0x81, 0x6b, 0xa1, 0x03,
	0x02, 0x01, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x0a,
	0xa4, 0x81, 0x5e, 0x30, 0x5c, 0xa0, 0x07, 0x03,
	0x05, 0x00, 0x50, 0x80, 0x00, 0x10, 0xa2, 0x04,
	0x1b, 0x02, 0x4e, 0x4d, 0xa3, 0x17, 0x30, 0x15,
	0xa0, 0x03, 0x02, 0x01, 0x00, 0xa1, 0x0e, 0x30,
	0x0c, 0x1b, 0x06, 0x6b, 0x72, 0x62, 0x74, 0x67,
	0x74, 0x1b, 0x02, 0x4e, 0x4d, 0xa5, 0x11, 0x18,
	0x0f, 0x31, 0x39, 0x37, 0x30, 0x30, 0x31, 0x30,
	0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
	0xa7, 0x06, 0x02, 0x04, 0x1f, 0x1e, 0xb9, 0xd9,
	0xa8, 0x17, 0x30, 0x15, 0x02, 0x01, 0x12, 0x02,
	0x01, 0x11, 0x02, 0x01, 0x10, 0x02, 0x01, 0x17,
	0x02, 0x01, 0x01, 0x02, 0x01, 0x03, 0x02, 0x01,
	0x02,
}

// pvno=5 pattern to search for: context tag [1] + length 3 + INTEGER tag + length 1 + value 5
var pvnoPattern = []byte{0xa0, 0x03, 0x02, 0x01, 0x05}

func init() {
	plugins.RegisterPlugin(&KerberosPlugin{})
}

// detectKerberos sends an AS-REQ probe and validates the response
// Returns: (detected bool, response bytes, error)
func detectKerberos(conn net.Conn, timeout time.Duration) (bool, []byte, error) {
	// For TCP, prepend 4-byte big-endian length
	tcpProbe := make([]byte, 4+len(asReqProbe))
	binary.BigEndian.PutUint32(tcpProbe[0:4], uint32(len(asReqProbe)))
	copy(tcpProbe[4:], asReqProbe)

	response, err := utils.SendRecv(conn, tcpProbe, timeout)
	if err != nil {
		return false, nil, err
	}

	// Response must be at least 10 bytes (4-byte TCP length + 6 bytes Kerberos minimum)
	if len(response) < 10 {
		return false, response, nil
	}

	// Skip the 4-byte TCP length prefix
	kerberosData := response[4:]

	// Check the Kerberos message byte (should be KRB-ERROR or AS-REP)
	if len(kerberosData) < 1 {
		return false, response, nil
	}
	messageType := kerberosData[0]
	if messageType != tagKRBError && messageType != tagASREP {
		return false, response, nil
	}

	// Search for pvno=5 pattern in the response
	if !bytes.Contains(kerberosData, pvnoPattern) {
		return false, response, nil
	}

	return true, response, nil
}

// parseDERLength parses a DER length field and returns (length, bytesConsumed).
// Short form: single byte (0-127)
// Long form: first byte = 0x80 | N, followed by N bytes of length
func parseDERLength(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 0
	}
	if data[0] < 0x80 {
		return int(data[0]), 1
	}
	numBytes := int(data[0] & 0x7f)
	if numBytes == 0 || numBytes > 3 || len(data) < 1+numBytes {
		return 0, 0
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}
	return length, 1 + numBytes
}

// parseKerberosError extracts metadata from a KRB-ERROR response.
// Returns: (realm string, errorCode int, errorText string)
func parseKerberosError(response []byte) (string, int, string) {
	if len(response) < 4 {
		return "", 0, ""
	}

	// Skip TCP length prefix
	data := response[4:]
	if len(data) < 2 {
		return "", 0, ""
	}

	// Skip APPLICATION 30 wrapper (0x7E + length)
	if data[0] != tagKRBError {
		return "", 0, ""
	}
	_, consumed := parseDERLength(data[1:])
	if consumed == 0 {
		return "", 0, ""
	}
	data = data[1+consumed:]

	// Skip SEQUENCE wrapper (0x30 + length)
	if len(data) < 2 || data[0] != 0x30 {
		return "", 0, ""
	}
	_, consumed = parseDERLength(data[1:])
	if consumed == 0 {
		return "", 0, ""
	}
	data = data[1+consumed:]

	// Now walk the context-tagged fields inside the SEQUENCE
	var realm string
	var errorCode int
	var errorText string

	for len(data) > 2 {
		tag := data[0]
		fieldLen, consumed := parseDERLength(data[1:])
		if consumed == 0 || 1+consumed+fieldLen > len(data) {
			break
		}
		fieldData := data[1+consumed : 1+consumed+fieldLen]

		switch tag {
		case 0xa6: // context tag [6] - error-code
			// error-code wraps an INTEGER
			if len(fieldData) >= 3 && fieldData[0] == 0x02 {
				intLen := int(fieldData[1])
				if 2+intLen <= len(fieldData) {
					for j := 0; j < intLen; j++ {
						errorCode = (errorCode << 8) | int(fieldData[2+j])
					}
				}
			}
		case 0xa9: // context tag [9] - realm
			// realm wraps a GeneralString
			if len(fieldData) >= 3 && fieldData[0] == 0x1b {
				strLen := int(fieldData[1])
				if 2+strLen <= len(fieldData) {
					realm = string(fieldData[2 : 2+strLen])
				}
			}
		case 0xab: // context tag [11] - e-text
			// e-text wraps a GeneralString
			if len(fieldData) >= 3 && fieldData[0] == 0x1b {
				strLen := int(fieldData[1])
				if 2+strLen <= len(fieldData) {
					errorText = string(fieldData[2 : 2+strLen])
				}
			}
		}

		// Move to next field
		data = data[1+consumed+fieldLen:]
	}

	return realm, errorCode, errorText
}

func (p *KerberosPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	detected, response, err := detectKerberos(conn, timeout)
	if err != nil {
		return nil, err
	}

	if !detected {
		return nil, nil
	}

	// Extract metadata from the response
	realm, errorCode, errorText := parseKerberosError(response)

	payload := plugins.ServiceKerberos{
		Realm:     realm,
		ErrorCode: errorCode,
		ErrorText: errorText,
	}

	// Kerberos version is always "5" for Kerberos v5
	return plugins.CreateServiceFrom(target, payload, false, "5", plugins.TCP), nil
}

func (p *KerberosPlugin) PortPriority(port uint16) bool {
	return port == 88
}

func (p *KerberosPlugin) Name() string {
	return KERBEROS
}

func (p *KerberosPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *KerberosPlugin) Priority() int {
	return 175
}

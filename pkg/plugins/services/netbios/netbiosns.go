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

package netbios

import (
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const NETBIOS = "netbios-ns"

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	transactionID := make([]byte, 2)
	_, err := rand.Read(transactionID)
	if err != nil {
		return nil, &utils.RandomizeError{Message: "Transaction ID"}
	}
	// NBSTAT Node Status Request with wildcard name "*" (RFC 1002)
	probe := append(transactionID, []byte{ //nolint:gocritic
		0x00, 0x00, // Flags: standard query
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Question: NetBIOS L1-encoded wildcard name "*" + null padding
		0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
		0x00, 0x21, // QTYPE: NBSTAT
		0x00, 0x01, // QCLASS: IN
	}...)

	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < 2 {
		return nil, nil
	}

	// Validate transaction ID matches what we sent
	if response[0] != transactionID[0] || response[1] != transactionID[1] {
		return nil, nil
	}

	payload, ok := parseNBSTATResponse(response)
	if !ok {
		return nil, nil
	}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
}

// parseNBSTATResponse parses an NBSTAT (Node Status) response per RFC 1002.
//
// Response layout after the 12-byte header + question section:
//
//	Answer section:
//	  - Name (variable, encoded)
//	  - Type (2 bytes) = 0x0021 (NBSTAT)
//	  - Class (2 bytes) = 0x0001 (IN)
//	  - TTL (4 bytes)
//	  - RDLENGTH (2 bytes)
//	  - RDATA:
//	    - NUM_NAMES (1 byte)
//	    - Name entries: NUM_NAMES x 18 bytes each (15-char name + 1-byte suffix + 2-byte flags)
//	    - MAC address (6 bytes)
func parseNBSTATResponse(data []byte) (plugins.ServiceNetbios, bool) {
	// Minimum: 12-byte header
	if len(data) < 12 {
		return plugins.ServiceNetbios{}, false
	}

	// Validate response flag (bit 15 of flags at offset 2-3)
	flags := (uint16(data[2]) << 8) | uint16(data[3])
	if flags&0x8000 == 0 {
		return plugins.ServiceNetbios{}, false
	}
	// RCODE must be NOERROR (lower 4 bits of flags)
	if flags&0x000F != 0 {
		return plugins.ServiceNetbios{}, false
	}
	// ANCOUNT must be > 0 (bytes 6-7)
	answerCount := (uint16(data[6]) << 8) | uint16(data[7])
	if answerCount == 0 {
		return plugins.ServiceNetbios{}, false
	}

	// Skip header (12 bytes) and question section to find the answer.
	// The question section has a variable-length name, then 4 bytes (QTYPE + QCLASS).
	offset := 12
	offset = skipDNSName(data, offset)
	if offset < 0 || offset+4 > len(data) {
		return plugins.ServiceNetbios{}, false
	}
	offset += 4 // skip QTYPE (2) + QCLASS (2)

	// Now at the answer section. Skip the answer name (may be compressed pointer or literal).
	offset = skipDNSName(data, offset)
	if offset < 0 {
		return plugins.ServiceNetbios{}, false
	}

	// Validate TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10 bytes
	if offset+10 > len(data) {
		return plugins.ServiceNetbios{}, false
	}
	rrType := (uint16(data[offset]) << 8) | uint16(data[offset+1])
	rrClass := (uint16(data[offset+2]) << 8) | uint16(data[offset+3])
	if rrType != 0x0021 || rrClass != 0x0001 {
		return plugins.ServiceNetbios{}, false
	}
	rdLength := int((uint16(data[offset+8]) << 8) | uint16(data[offset+9]))
	offset += 10

	// Validate RDLENGTH doesn't exceed remaining data
	if offset+rdLength > len(data) {
		return plugins.ServiceNetbios{}, false
	}
	rdataEnd := offset + rdLength

	// RDATA: NUM_NAMES (1 byte)
	if offset >= rdataEnd {
		return plugins.ServiceNetbios{}, false
	}
	numNames := int(data[offset])
	offset++

	// Each name entry is 18 bytes: 15-char name + 1-byte suffix + 2-byte flags
	const nameEntryLen = 18
	if offset+numNames*nameEntryLen > rdataEnd {
		return plugins.ServiceNetbios{}, false
	}

	result := plugins.ServiceNetbios{}
	result.Names = make([]plugins.NetbiosEntry, 0, numNames)

	for i := 0; i < numNames; i++ {
		entryOffset := offset + i*nameEntryLen
		name := strings.TrimRight(string(data[entryOffset:entryOffset+15]), " \x00")
		suffix := data[entryOffset+15]
		nameFlags := (uint16(data[entryOffset+16]) << 8) | uint16(data[entryOffset+17])

		flagStr := "unique"
		if nameFlags&0x8000 != 0 {
			flagStr = "group"
		}

		entry := plugins.NetbiosEntry{
			Name:   name,
			Suffix: suffix,
			Flags:  flagStr,
		}
		result.Names = append(result.Names, entry)

		// First unique name with suffix 0x00 is the workstation/hostname
		if suffix == 0x00 && flagStr == "unique" && result.NetBIOSName == "" {
			result.NetBIOSName = name
		}

		// First group name with suffix 0x00 is the workgroup/domain
		if suffix == 0x00 && flagStr == "group" && result.GroupName == "" {
			result.GroupName = name
		}
	}

	// MAC address follows the name table (6 bytes)
	macOffset := offset + numNames*nameEntryLen
	if macOffset+6 <= rdataEnd {
		mac := data[macOffset : macOffset+6]
		result.MACAddress = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	}

	// Fallback: if no name was identified, treat as invalid
	if result.NetBIOSName == "" && len(result.Names) == 0 {
		return plugins.ServiceNetbios{}, false
	}

	return result, true
}

// skipDNSName advances past a DNS-encoded name at data[offset], handling both
// literal labels and compression pointers (RFC 1035 Section 4.1.4).
// Returns the new offset after the name, or -1 if the data is malformed.
func skipDNSName(data []byte, offset int) int {
	if offset >= len(data) {
		return -1
	}
	// Compression pointer: two bytes starting with 0xC0
	if data[offset]&0xC0 == 0xC0 {
		if offset+2 > len(data) {
			return -1
		}
		return offset + 2
	}
	// Literal labels: sequence of length-prefixed labels ending with 0x00
	for offset < len(data) {
		labelLen := int(data[offset])
		if labelLen == 0 {
			return offset + 1 // skip the 0x00 terminator
		}
		// Check for compression pointer mid-name
		if labelLen&0xC0 == 0xC0 {
			if offset+2 > len(data) {
				return -1
			}
			return offset + 2
		}
		offset += labelLen + 1
	}
	return -1
}

func (p *Plugin) PortPriority(i uint16) bool {
	return i == 137
}

func (p *Plugin) Name() string {
	return NETBIOS
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 700
}

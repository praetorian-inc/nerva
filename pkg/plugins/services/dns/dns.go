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

package dns

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const DNS = "dns"

type UDPPlugin struct{}
type TCPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&UDPPlugin{})
	plugins.RegisterPlugin(&TCPPlugin{})
}

func CheckDNS(conn net.Conn, timeout time.Duration) (bool, error) {
	for attempts := 0; attempts < 3; attempts++ {
		transactionID := make([]byte, 2)
		_, err := rand.Read(transactionID)
		if err != nil {
			return false, &utils.RandomizeError{Message: "Transaction ID"}
		}

		InitialConnectionPackage := append(transactionID, []byte{ //nolint:gocritic
			// Transaction ID
			0x01, 0x00, // Flags: 0x0100 Standard query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answer RRs: 0
			0x00, 0x00, // Authority RRs: 0
			0x00, 0x00, // Additional RRs: 0
			0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e, 0x64, 0x00, // Name: version.bind
			0x00, 0x10, // Type: TXT (Text strings) (16)
			0x00, 0x03, // Class: CH (0x0003)
		}...)

		if conn.RemoteAddr().Network() == "tcp" {
			InitialConnectionPackage = append([]byte{0x00, 0x1e}, InitialConnectionPackage...)
		}

		response, err := utils.SendRecv(conn, InitialConnectionPackage, timeout)
		if err != nil {
			return false, err
		}

		if len(response) == 0 {
			return false, nil
		}

		if conn.RemoteAddr().Network() == "udp" {
			if !bytes.Equal(transactionID[0:2], response[0:2]) {
				return false, nil
			}
		}

		if conn.RemoteAddr().Network() == "tcp" {
			if !bytes.Equal(transactionID[0:2], response[2:4]) {
				return false, nil
			}
		}
	}

	return true, nil
}

func (p *UDPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	isDNS, err := CheckDNS(conn, timeout)
	if err != nil {
		return nil, err
	}

	if isDNS {
		payload := plugins.ServiceDNS{}
		return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
	}

	return nil, nil
}

func (p *UDPPlugin) PortPriority(i uint16) bool {
	return i == 53
}

func (p UDPPlugin) Name() string {
	return DNS
}
func (p *UDPPlugin) Type() plugins.Protocol {
	return plugins.UDP
}

// checkZoneTransfer sends an AXFR query for the root zone and returns the
// number of answer records if the transfer succeeds (RCODE 0, ANCOUNT > 0).
// Returns 0 if the server refuses or returns an error response.
func checkZoneTransfer(conn net.Conn, timeout time.Duration) (int, error) {
	// Build an AXFR query for the root zone ".".
	// DNS header: TxID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2) = 12 bytes
	// Question: QNAME=0x00 (root), QTYPE=252 (AXFR), QCLASS=1 (IN)
	transactionID := make([]byte, 2)
	if _, err := rand.Read(transactionID); err != nil {
		return 0, fmt.Errorf("failed to generate transaction ID: %w", err)
	}

	query := []byte{
		transactionID[0], transactionID[1], // Transaction ID
		0x00, 0x00, // Flags: standard query
		0x00, 0x01, // QDCOUNT: 1 question
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
		0x00,       // QNAME: root zone (single empty label)
		0x00, 0xfc, // QTYPE: 252 (AXFR)
		0x00, 0x01, // QCLASS: 1 (IN)
	}

	// DNS over TCP requires a 2-byte big-endian length prefix.
	msgLen := uint16(len(query))
	packet := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(packet[0:2], msgLen)
	copy(packet[2:], query)

	response, err := utils.SendRecv(conn, packet, timeout)
	if err != nil {
		return 0, err
	}

	// Minimum response: 2-byte length prefix + 12-byte DNS header = 14 bytes.
	if len(response) < 14 {
		return 0, nil
	}

	// DNS message starts after the 2-byte TCP length prefix.
	msg := response[2:]
	if len(msg) < 12 {
		return 0, nil
	}

	// RCODE is the lower 4 bits of the second flags byte (msg[3]).
	rcode := msg[3] & 0x0f
	if rcode != 0 {
		return 0, nil
	}

	// ANCOUNT is at bytes 6-7 of the DNS message.
	ancount := int(binary.BigEndian.Uint16(msg[6:8]))
	return ancount, nil
}

func (p TCPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	isDNS, err := CheckDNS(conn, timeout)
	if err != nil {
		return nil, err
	}

	if isDNS {
		payload := plugins.ServiceDNS{}
		service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)

		if target.Misconfigs {
			ancount, err := checkZoneTransfer(conn, timeout)
			if err == nil && ancount > 0 {
				service.SecurityFindings = []plugins.SecurityFinding{{
					ID:          "dns-zone-transfer",
					Severity:    plugins.SeverityHigh,
					Description: "DNS zone transfer (AXFR) enabled; exposes all DNS records including internal hostnames and network topology",
					Evidence:    fmt.Sprintf("AXFR returned %d records", ancount),
				}}
			}
		}

		return service, nil
	}

	return nil, nil
}

func (p TCPPlugin) PortPriority(i uint16) bool {
	return i == 53
}

func (p TCPPlugin) Name() string {
	return DNS
}
func (p *TCPPlugin) Priority() int {
	return 50
}

func (p *UDPPlugin) Priority() int {
	return 50
}

func (p TCPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

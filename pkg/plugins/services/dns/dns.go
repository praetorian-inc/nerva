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
	"strconv"
	"strings"
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

func CheckDNS(conn net.Conn, timeout time.Duration) (bool, string, error) {
	var version string
	for attempts := 0; attempts < 3; attempts++ {
		transactionID := make([]byte, 2)
		_, err := rand.Read(transactionID)
		if err != nil {
			return false, "", &utils.RandomizeError{Message: "Transaction ID"}
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
			return false, "", err
		}

		if len(response) == 0 {
			return false, "", nil
		}

		var dnsMsg []byte
		if conn.RemoteAddr().Network() == "udp" {
			if !bytes.Equal(transactionID[0:2], response[0:2]) {
				return false, "", nil
			}
			dnsMsg = response
		}

		if conn.RemoteAddr().Network() == "tcp" {
			if len(response) < 4 || !bytes.Equal(transactionID[0:2], response[2:4]) {
				return false, "", nil
			}
			// TXID match is enough to detect DNS. Only parse version.bind when
			// the TCP length prefix describes a complete DNS message; a split
			// read (prefix without the full body) must not fail detection.
			declaredLen := int(binary.BigEndian.Uint16(response[0:2]))
			if declaredLen >= 12 && len(response) >= 2+declaredLen {
				dnsMsg = response[2 : 2+declaredLen]
			}
		}

		if v, ok := parseVersionBindTXT(dnsMsg); ok {
			version = v
		}
		// Return on the first TXID-matching response so a later SendRecv
		// error cannot discard the version captured on this attempt.
		return true, version, nil
	}

	return true, version, nil
}

func (p *UDPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	isDNS, version, err := CheckDNS(conn, timeout)
	if err != nil {
		return nil, err
	}

	if isDNS {
		payload := plugins.ServiceDNS{}
		service := plugins.CreateServiceFrom(target, payload, false, version, plugins.UDP)
		if target.Misconfigs {
			if finding := checkBINDEOL(version); finding != nil {
				service.SecurityFindings = append(service.SecurityFindings, *finding)
			}
		}
		return service, nil
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
	msgLen := uint16(len(query)) // #nosec G115 -- query is a fixed 17-byte literal; cannot overflow uint16
	packet := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(packet[0:2], msgLen)
	copy(packet[2:], query)

	response, err := utils.SendRecv(conn, packet, timeout)
	if err != nil {
		return 0, err
	}

	// Minimum response: 2-byte TCP length prefix + 12-byte DNS header.
	if len(response) < 14 {
		return 0, nil
	}

	// Use the declared TCP length to bound the DNS message.
	declaredLen := int(binary.BigEndian.Uint16(response[0:2]))
	if declaredLen < 12 || len(response) < 2+declaredLen {
		return 0, nil
	}
	msg := response[2 : 2+declaredLen]

	// Transaction ID must match the query we sent.
	if !bytes.Equal(msg[0:2], transactionID) {
		return 0, nil
	}

	// Must be a response (QR bit set in first flags byte).
	if msg[2]&0x80 == 0 {
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
	isDNS, version, err := CheckDNS(conn, timeout)
	if err != nil {
		return nil, err
	}

	if isDNS {
		payload := plugins.ServiceDNS{}
		service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)

		if target.Misconfigs {
			if finding := checkBINDEOL(version); finding != nil {
				service.SecurityFindings = append(service.SecurityFindings, *finding)
			}
			ancount, err := checkZoneTransfer(conn, timeout)
			if err == nil && ancount > 0 {
				service.SecurityFindings = append(service.SecurityFindings, plugins.SecurityFinding{
					ID:          "dns-zone-transfer",
					Severity:    plugins.SeverityHigh,
					Description: "DNS zone transfer (AXFR) enabled; exposes all DNS records including internal hostnames and network topology",
					Evidence:    fmt.Sprintf("AXFR returned %d records", ancount),
				})
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

// parseVersionBindTXT extracts the TXT RDATA from a CHAOS version.bind answer.
// Returns ("", false) on truncated messages, wrong class, or empty RDATA.
func parseVersionBindTXT(msg []byte) (string, bool) {
	if len(msg) < 12 {
		return "", false
	}
	qdcount := int(binary.BigEndian.Uint16(msg[4:6]))
	ancount := int(binary.BigEndian.Uint16(msg[6:8]))
	if ancount < 1 {
		return "", false
	}
	off := 12
	var ok bool
	for i := 0; i < qdcount; i++ {
		off, ok = skipDNSName(msg, off)
		if !ok || off+4 > len(msg) {
			return "", false
		}
		off += 4 // QTYPE + QCLASS
	}
	off, ok = skipDNSName(msg, off)
	if !ok || off+10 > len(msg) {
		return "", false
	}
	typ := binary.BigEndian.Uint16(msg[off : off+2])
	class := binary.BigEndian.Uint16(msg[off+2 : off+4])
	rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
	off += 10
	if typ != 16 || class != 3 {
		return "", false
	}
	if rdlen == 0 || off+rdlen > len(msg) {
		return "", false
	}
	rdata := msg[off : off+rdlen]
	var b strings.Builder
	i := 0
	for i < len(rdata) {
		n := int(rdata[i])
		i++
		if i+n > len(rdata) {
			return "", false
		}
		b.Write(rdata[i : i+n])
		i += n
	}
	s := b.String()
	if s == "" {
		return "", false
	}
	return s, true
}

func skipDNSName(msg []byte, off int) (int, bool) {
	if off >= len(msg) {
		return 0, false
	}
	end := off
	consumedEnd := false
	jumps := 0
	for {
		if off >= len(msg) {
			return 0, false
		}
		l := int(msg[off])
		if l&0xc0 == 0xc0 {
			if off+1 >= len(msg) {
				return 0, false
			}
			if !consumedEnd {
				end = off + 2
				consumedEnd = true
			}
			off = int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3fff)
			jumps++
			if jumps > 10 {
				return 0, false
			}
			continue
		}
		if l&0xc0 != 0 {
			return 0, false
		}
		if l == 0 {
			off++
			if !consumedEnd {
				end = off
			}
			return end, true
		}
		off += 1 + l
	}
}

func parseMajorMinor(version string) (int, int, bool) {
	version = strings.TrimSpace(version)
	major, rest, ok := leadingInt(version)
	if !ok {
		return 0, 0, false
	}
	minor := 0
	if strings.HasPrefix(rest, ".") {
		minor, _, ok = leadingInt(rest[1:])
		if !ok {
			return 0, 0, false
		}
	}
	return major, minor, true
}

func leadingInt(s string) (int, string, bool) {
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

// checkBINDEOL maps a parsed version.bind string to a SecurityFinding if the
// BIND version is 9.x with minor <= 16. Non-9 majors (dnsmasq 2.x, Unbound 1.x)
// and 9.20+ are not BIND EOL.
func checkBINDEOL(version string) *plugins.SecurityFinding {
	major, minor, ok := parseMajorMinor(version)
	if !ok {
		return nil
	}
	if major != 9 || minor > 16 {
		return nil
	}
	return &plugins.SecurityFinding{
		ID:          "bind-eol",
		Severity:    plugins.SeverityLow,
		Description: fmt.Sprintf("BIND service running end-of-life version: %d.%d", major, minor),
		Evidence:    version,
	}
}

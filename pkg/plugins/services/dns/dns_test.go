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
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

func TestDNS(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "dns",
			Port:        53,
			Protocol:    plugins.UDP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "ruudud/devdns",
				Mounts:     []string{"/var/run/docker.sock:/var/run/docker.sock:ro"},
				Privileged: true,
			},
		},
	}

	var p *UDPPlugin

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

// tcpAddr implements net.Addr and returns "tcp" from Network() so that
// CheckDNS selects the TCP code path (length-prefixed packets).
type tcpAddr struct{}

func (tcpAddr) Network() string { return "tcp" }
func (tcpAddr) String() string  { return "127.0.0.1:53" }

// dnsMockConn is a net.Conn that handles DNS TCP queries dynamically.
//
// CheckDNS sends a version.bind query whose 2-byte transaction ID sits at
// bytes 2-3 of the length-prefixed packet (bytes 0-1 are the TCP length
// prefix). The mock echoes the transaction ID back in the response so that
// CheckDNS considers it valid.
//
// After CheckDNS passes, checkZoneTransfer sends an AXFR query. The mock
// responds according to the axfrResponse field: if allowAXFR is true, it
// returns a success response with answerCount records; otherwise it returns
// RCODE REFUSED (5).
type dnsMockConn struct {
	// axfrResponse controls what the mock returns for AXFR queries.
	allowAXFR   bool
	answerCount int
	// versionBind is the TXT RDATA returned for version.bind. Empty defaults to
	// "9.20" so existing AXFR tests do not emit bind-eol.
	versionBind string
	// readBuf holds the next response to return from Read.
	readBuf []byte
	// writeBuf accumulates the bytes from the current Write call.
	writeBuf []byte
}

// buildVersionBindResponse constructs a minimal valid DNS response for a
// version.bind query. The transaction ID is echoed from the received packet.
// The response is length-prefixed for TCP (2 bytes big-endian before the
// DNS message).
func buildVersionBindResponse(txID [2]byte) []byte {
	return buildVersionBindResponseTXT(txID, "9.20")
}

func buildVersionBindResponseTXT(txID [2]byte, txt string) []byte {
	if txt == "" {
		txt = "9.20"
	}
	rdata := append([]byte{byte(len(txt))}, []byte(txt)...)
	msg := []byte{
		txID[0], txID[1], // Transaction ID (echoed)
		0x81, 0x80, // Flags: response, no error
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x01, // ANCOUNT: 1
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
		// Question section: version.bind TXT CH
		0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
		0x04, 0x62, 0x69, 0x6e, 0x64, 0x00,
		0x00, 0x10, // QTYPE: TXT
		0x00, 0x03, // QCLASS: CH
		// Answer section: TXT record
		0xc0, 0x0c, // Name: pointer to question
		0x00, 0x10, // TYPE: TXT
		0x00, 0x03, // CLASS: CH
		0x00, 0x00, 0x00, 0x00, // TTL: 0
	}
	rdlen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdlen, uint16(len(rdata)))
	msg = append(msg, rdlen...)
	msg = append(msg, rdata...)
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(msg)))
	copy(out[2:], msg)
	return out
}

// buildAXFRSuccess constructs a DNS AXFR success response with the given
// number of answer records. The response is length-prefixed for TCP.
func buildAXFRSuccess(txID [2]byte, answerCount int) []byte {
	// Minimal SOA record used as both first and last record in an AXFR.
	soa := []byte{
		0x00,       // QNAME: root
		0x00, 0x06, // TYPE: SOA
		0x00, 0x01, // CLASS: IN
		0x00, 0x00, 0x00, 0x00, // TTL: 0
		0x00, 0x01, // RDLENGTH: 1 (minimal)
		0x00, // RDATA: single zero byte
	}

	msg := []byte{
		txID[0], txID[1], // Transaction ID (echoed)
		0x84, 0x00, // Flags: response, AA, RCODE=0
		0x00, 0x00, // QDCOUNT: 0
		byte(answerCount >> 8), byte(answerCount), // ANCOUNT
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
	}
	// Append one SOA record as the answer (minimal valid AXFR content).
	msg = append(msg, soa...)

	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(msg)))
	copy(out[2:], msg)
	return out
}

// buildAXFRRefused constructs a DNS response with RCODE REFUSED (5).
func buildAXFRRefused(txID [2]byte) []byte {
	msg := []byte{
		txID[0], txID[1], // Transaction ID (echoed)
		0x80, 0x05, // Flags: response, RCODE=5 (REFUSED)
		0x00, 0x00, // QDCOUNT: 0
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
	}
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(msg)))
	copy(out[2:], msg)
	return out
}

func (m *dnsMockConn) Write(b []byte) (int, error) {
	m.writeBuf = append(m.writeBuf, b...)

	// A complete DNS TCP packet has at least 2 (length) + 12 (header) = 14 bytes.
	// Wait until we have enough data to determine the query type.
	if len(m.writeBuf) < 14 {
		return len(b), nil
	}

	// TCP DNS: bytes 0-1 are the length prefix, bytes 2-3 are transaction ID,
	// bytes 4-5 are flags. The question section starts at byte 14 for a standard
	// query. For the AXFR query built by checkZoneTransfer, QTYPE is at a known
	// offset (after the root-zone QNAME of just one zero byte):
	//   offset 2: txID[0], txID[1]
	//   offset 4: flags
	//   ...
	//   offset 14: QNAME (0x00 for root zone OR start of version.bind label)
	//
	// We distinguish version.bind from AXFR by looking at whether the question
	// section starts with 0x07 (version.bind label length) or 0x00 (root zone).
	var txID [2]byte
	copy(txID[:], m.writeBuf[2:4])

	isVersionBind := len(m.writeBuf) > 14 && m.writeBuf[14] == 0x07

	if isVersionBind {
		m.readBuf = buildVersionBindResponseTXT(txID, m.versionBind)
	} else {
		// AXFR query
		if m.allowAXFR {
			m.readBuf = buildAXFRSuccess(txID, m.answerCount)
		} else {
			m.readBuf = buildAXFRRefused(txID)
		}
	}

	// Reset writeBuf for the next query.
	m.writeBuf = nil
	return len(b), nil
}

func (m *dnsMockConn) Read(b []byte) (int, error) {
	n := copy(b, m.readBuf)
	m.readBuf = m.readBuf[n:]
	return n, nil
}

func (m *dnsMockConn) Close() error                     { return nil }
func (m *dnsMockConn) LocalAddr() net.Addr              { return tcpAddr{} }
func (m *dnsMockConn) RemoteAddr() net.Addr             { return tcpAddr{} }
func (m *dnsMockConn) SetDeadline(time.Time) error      { return nil }
func (m *dnsMockConn) SetReadDeadline(time.Time) error  { return nil }
func (m *dnsMockConn) SetWriteDeadline(time.Time) error { return nil }

var defaultTCPTarget = plugins.Target{
	Address: netip.MustParseAddrPort("127.0.0.1:53"),
}

// TestDNSZoneTransferFinding verifies the AXFR misconfig detection in TCPPlugin.
func TestDNSZoneTransferFinding(t *testing.T) {
	plugin := TCPPlugin{}

	t.Run("finding present when AXFR accepted", func(t *testing.T) {
		conn := &dnsMockConn{allowAXFR: true, answerCount: 15}
		target := plugins.Target{
			Address:    defaultTCPTarget.Address,
			Misconfigs: true,
		}

		svc, err := plugin.Run(conn, 5*time.Second, target)
		if err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
		if svc == nil {
			t.Fatal("Run() returned nil service, want non-nil")
		}

		if len(svc.SecurityFindings) == 0 {
			t.Fatal("SecurityFindings is empty, want dns-zone-transfer finding")
		}
		f := svc.SecurityFindings[0]
		if f.ID != "dns-zone-transfer" {
			t.Errorf("finding ID = %q, want %q", f.ID, "dns-zone-transfer")
		}
		if f.Severity != plugins.SeverityHigh {
			t.Errorf("finding Severity = %q, want %q", f.Severity, plugins.SeverityHigh)
		}
		wantEvidence := fmt.Sprintf("AXFR returned %d records", 15)
		if f.Evidence != wantEvidence {
			t.Errorf("finding Evidence = %q, want %q", f.Evidence, wantEvidence)
		}
	})

	t.Run("finding absent when misconfigs disabled", func(t *testing.T) {
		conn := &dnsMockConn{allowAXFR: true, answerCount: 15}
		target := plugins.Target{
			Address:    defaultTCPTarget.Address,
			Misconfigs: false,
		}

		svc, err := plugin.Run(conn, 5*time.Second, target)
		if err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
		if svc == nil {
			t.Fatal("Run() returned nil service, want non-nil")
		}
		if len(svc.SecurityFindings) != 0 {
			t.Errorf("SecurityFindings = %v, want empty (misconfigs disabled)", svc.SecurityFindings)
		}
	})

	t.Run("finding absent when AXFR refused", func(t *testing.T) {
		conn := &dnsMockConn{allowAXFR: false}
		target := plugins.Target{
			Address:    defaultTCPTarget.Address,
			Misconfigs: true,
		}

		svc, err := plugin.Run(conn, 5*time.Second, target)
		if err != nil {
			t.Fatalf("Run() error = %v, want nil", err)
		}
		if svc == nil {
			t.Fatal("Run() returned nil service, want non-nil")
		}
		if len(svc.SecurityFindings) != 0 {
			t.Errorf("SecurityFindings = %v, want empty (AXFR refused)", svc.SecurityFindings)
		}
	})

	t.Run("UDP plugin never produces zone transfer finding", func(t *testing.T) {
		// UDPPlugin.Run calls CheckDNS, which for UDP checks response[0:2] against
		// the transaction ID. We need a UDP mock that returns an empty response
		// (no DNS detected) so we don't need to worry about the transaction ID.
		// Actually we want to confirm the UDP plugin runs and returns no SecurityFindings.
		// Use the udpMockConn which returns a valid UDP DNS response.
		udpPlugin := UDPPlugin{}
		udpConn := &udpMockConn{}
		udpTarget := plugins.Target{
			Address:    netip.MustParseAddrPort("127.0.0.1:53"),
			Misconfigs: true,
		}

		svc, err := udpPlugin.Run(udpConn, 5*time.Second, udpTarget)
		if err != nil {
			t.Fatalf("UDPPlugin.Run() error = %v, want nil", err)
		}
		// UDPPlugin may or may not detect DNS (depends on mock), but must have no SecurityFindings.
		if svc != nil && len(svc.SecurityFindings) != 0 {
			t.Errorf("UDPPlugin SecurityFindings = %v, want empty", svc.SecurityFindings)
		}
	})
}

// udpAddr implements net.Addr and returns "udp" from Network().
type udpAddr struct{}

func (udpAddr) Network() string { return "udp" }
func (udpAddr) String() string  { return "127.0.0.1:53" }

// udpMockConn is a minimal UDP mock that returns an empty response,
// causing CheckDNS to return false (not DNS). This is sufficient to verify
// that UDPPlugin never populates SecurityFindings.
type udpMockConn struct{}

func (m *udpMockConn) Read(b []byte) (int, error)       { return 0, nil }
func (m *udpMockConn) Write(b []byte) (int, error)      { return len(b), nil }
func (m *udpMockConn) Close() error                     { return nil }
func (m *udpMockConn) LocalAddr() net.Addr              { return udpAddr{} }
func (m *udpMockConn) RemoteAddr() net.Addr             { return udpAddr{} }
func (m *udpMockConn) SetDeadline(time.Time) error      { return nil }
func (m *udpMockConn) SetReadDeadline(time.Time) error  { return nil }
func (m *udpMockConn) SetWriteDeadline(time.Time) error { return nil }

// staticResponseConn is a minimal net.Conn that returns a fixed byte slice on
// every Read call. It is used to test checkZoneTransfer in isolation, without
// going through the CheckDNS handshake that dnsMockConn requires.
//
// If responseBuilder is set, it is called with the bytes written by the caller
// (the AXFR query packet), allowing the response to echo the transaction ID.
// Otherwise the fixed response field is used.
type staticResponseConn struct {
	response        []byte
	responseBuilder func(query []byte) []byte
	pos             int
	writtenBytes    []byte
}

func (s *staticResponseConn) Read(b []byte) (int, error) {
	if s.responseBuilder != nil && s.pos == 0 {
		s.response = s.responseBuilder(s.writtenBytes)
	}
	n := copy(b, s.response[s.pos:])
	s.pos += n
	return n, nil
}
func (s *staticResponseConn) Write(b []byte) (int, error) {
	s.writtenBytes = append(s.writtenBytes, b...)
	return len(b), nil
}
func (s *staticResponseConn) Close() error                     { return nil }
func (s *staticResponseConn) LocalAddr() net.Addr              { return tcpAddr{} }
func (s *staticResponseConn) RemoteAddr() net.Addr             { return tcpAddr{} }
func (s *staticResponseConn) SetDeadline(time.Time) error      { return nil }
func (s *staticResponseConn) SetReadDeadline(time.Time) error  { return nil }
func (s *staticResponseConn) SetWriteDeadline(time.Time) error { return nil }

// buildAXFRResponse constructs a TCP-length-prefixed DNS response with the
// given transaction ID, RCODE and ANCOUNT.
func buildAXFRResponse(txID []byte, rcode byte, ancount uint16) []byte {
	msg := []byte{
		txID[0], txID[1], // Transaction ID
		0x84, rcode, // Flags: QR=1, AA=1; RCODE in low nibble of byte 3
		0x00, 0x00, // QDCOUNT: 0
		byte(ancount >> 8), byte(ancount), // ANCOUNT
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
	}
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(msg)))
	copy(out[2:], msg)
	return out
}

// axfrResponseForQuery builds an AXFR response that echoes the transaction ID
// from the written TCP-prefixed query packet (bytes 2-3 of the query).
func axfrResponseForQuery(query []byte, rcode byte, ancount uint16) []byte {
	var txID []byte
	if len(query) >= 4 {
		txID = query[2:4] // skip 2-byte TCP length prefix, then 2-byte txID
	} else {
		txID = []byte{0x00, 0x00}
	}
	return buildAXFRResponse(txID, rcode, ancount)
}

// TestCheckZoneTransferEdgeCases tests boundary and error conditions in the
// checkZoneTransfer response parser to ensure it handles malformed or unusual
// server responses without panicking.
func TestCheckZoneTransferEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		response        []byte
		responseBuilder func(query []byte) []byte
		wantCount       int
	}{
		{
			name:      "empty response returns 0",
			response:  []byte{},
			wantCount: 0,
		},
		{
			name:      "response too short (10 bytes) returns 0",
			response:  make([]byte, 10),
			wantCount: 0,
		},
		{
			name: "exactly 14 bytes with RCODE 0 and ANCOUNT 0 returns 0",
			// 2-byte length prefix + 12-byte DNS header = 14 bytes; ANCOUNT 0 → 0
			responseBuilder: func(q []byte) []byte { return axfrResponseForQuery(q, 0x00, 0) },
			wantCount:       0,
		},
		{
			name:            "RCODE NXDOMAIN (3) returns 0",
			responseBuilder: func(q []byte) []byte { return axfrResponseForQuery(q, 0x03, 10) },
			wantCount:       0,
		},
		{
			name:            "RCODE SERVFAIL (2) returns 0",
			responseBuilder: func(q []byte) []byte { return axfrResponseForQuery(q, 0x02, 5) },
			wantCount:       0,
		},
		{
			name:            "RCODE REFUSED (5) returns 0",
			responseBuilder: func(q []byte) []byte { return axfrResponseForQuery(q, 0x05, 100) },
			wantCount:       0,
		},
		{
			name:            "RCODE 0 with ANCOUNT 65535 returns 65535",
			responseBuilder: func(q []byte) []byte { return axfrResponseForQuery(q, 0x00, 65535) },
			wantCount:       65535,
		},
		{
			name: "TCP length prefix claims more data than available returns 0",
			// Build a valid response, then overwrite the length prefix to claim
			// 100 bytes. The declared-length check rejects it because actual
			// payload is only 12 bytes.
			responseBuilder: func(q []byte) []byte {
				resp := axfrResponseForQuery(q, 0x00, 7)
				binary.BigEndian.PutUint16(resp[0:2], 100)
				return resp
			},
			wantCount: 0,
		},
		{
			name: "mismatched transaction ID returns 0",
			responseBuilder: func(q []byte) []byte {
				// Return a valid AXFR response but with an inverted transaction ID.
				var txID []byte
				if len(q) >= 4 {
					txID = []byte{^q[2], ^q[3]}
				} else {
					txID = []byte{0xFF, 0xFF}
				}
				return buildAXFRResponse(txID, 0x00, 10)
			},
			wantCount: 0,
		},
		{
			name: "QR bit not set returns 0",
			responseBuilder: func(q []byte) []byte {
				resp := axfrResponseForQuery(q, 0x00, 10)
				// Clear the QR bit (byte 4 after TCP length prefix = msg[2]).
				resp[4] &^= 0x80
				return resp
			},
			wantCount: 0,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			conn := &staticResponseConn{
				response:        tc.response,
				responseBuilder: tc.responseBuilder,
			}
			got, err := checkZoneTransfer(conn, 5*time.Second)
			if err != nil {
				t.Fatalf("checkZoneTransfer() error = %v, want nil", err)
			}
			if got != tc.wantCount {
				t.Errorf("checkZoneTransfer() = %d, want %d", got, tc.wantCount)
			}
		})
	}
}

func buildVersionBindTXTMsg(txt string, class uint16, compressed bool) []byte {
	msg := []byte{
		0x00, 0x01, // Transaction ID
		0x81, 0x80, // Flags: response
		0x00, 0x01, // QDCOUNT
		0x00, 0x01, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
		// Question: version.bind TXT CH
		0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
		0x04, 0x62, 0x69, 0x6e, 0x64, 0x00,
		0x00, 0x10, // QTYPE TXT
		0x00, 0x03, // QCLASS CH
	}
	if compressed {
		msg = append(msg, 0xc0, 0x0c)
	} else {
		msg = append(msg,
			0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
			0x04, 0x62, 0x69, 0x6e, 0x64, 0x00,
		)
	}
	msg = append(msg, 0x00, 0x10) // TYPE TXT
	msg = append(msg, byte(class>>8), byte(class))
	msg = append(msg, 0x00, 0x00, 0x00, 0x00) // TTL
	rdata := []byte{byte(len(txt))}
	rdata = append(rdata, []byte(txt)...)
	msg = append(msg, byte(len(rdata)>>8), byte(len(rdata)))
	msg = append(msg, rdata...)
	return msg
}

func TestParseVersionBindTXT(t *testing.T) {
	tests := []struct {
		name   string
		msg    []byte
		want   string
		wantOK bool
	}{
		{"9.8 compressed", buildVersionBindTXTMsg("9.8", 3, true), "9.8", true},
		{"9.6 uncompressed", buildVersionBindTXTMsg("9.6", 3, false), "9.6", true},
		{"9.20 compressed", buildVersionBindTXTMsg("9.20", 3, true), "9.20", true},
		{"wrong class IN", buildVersionBindTXTMsg("9.8", 1, true), "", false},
		{"empty rdata", func() []byte {
			msg := buildVersionBindTXTMsg("x", 3, true)
			// zero RDLENGTH at the last 3 bytes before rdata: rewrite last rdlength+rdata
			// Find RDLENGTH: last 1+len("x")+2 is messy; build truncated instead.
			return msg[:len(msg)-2] // drop rdata, leave rdlength pointing at missing bytes
		}(), "", false},
		{"truncated", []byte{0x00, 0x01, 0x81, 0x80}, "", false},
		{"nil", nil, "", false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseVersionBindTXT(tt.msg)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("parseVersionBindTXT() = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestCheckBINDEOL(t *testing.T) {
	tests := []struct {
		version string
		wantID  string
	}{
		{"9.6", "bind-eol"},
		{"9.8", "bind-eol"},
		{"9.8.3-P1", "bind-eol"},
		{"9.16", "bind-eol"},
		{"9.20", ""},
		{"1.0", ""},
		{"2.80", ""},
		{"dnsmasq-2.80", ""},
		{"", ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.version, func(t *testing.T) {
			finding := checkBINDEOL(tt.version)
			if tt.wantID == "" {
				if finding != nil {
					t.Errorf("checkBINDEOL(%q) = %+v, want nil", tt.version, finding)
				}
				return
			}
			if finding == nil {
				t.Fatalf("checkBINDEOL(%q) = nil, want ID %q", tt.version, tt.wantID)
			}
			if finding.ID != tt.wantID {
				t.Errorf("finding.ID = %q, want %q", finding.ID, tt.wantID)
			}
		})
	}
}

func TestBINDEOLFinding(t *testing.T) {
	plugin := TCPPlugin{}
	tests := []struct {
		name       string
		txt        string
		misconfigs bool
		wantEOL    bool
	}{
		{"9.6 misconfigs", "9.6", true, true},
		{"9.8 misconfigs", "9.8", true, true},
		{"9.20 misconfigs", "9.20", true, false},
		{"9.6 misconfigs disabled", "9.6", false, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			conn := &dnsMockConn{versionBind: tt.txt}
			target := plugins.Target{
				Address:    defaultTCPTarget.Address,
				Misconfigs: tt.misconfigs,
			}
			svc, err := plugin.Run(conn, 5*time.Second, target)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if svc == nil {
				t.Fatal("Run() returned nil service")
			}
			found := false
			for _, f := range svc.SecurityFindings {
				if f.ID == "bind-eol" {
					found = true
				}
				if f.ID == "dns-zone-transfer" {
					t.Errorf("AXFR success must not be treated as BIND version; got %q", f.ID)
				}
			}
			if found != tt.wantEOL {
				t.Errorf("bind-eol present=%v, want %v (findings=%v version=%q)", found, tt.wantEOL, svc.SecurityFindings, svc.Version)
			}
			if tt.wantEOL && svc.Version != tt.txt {
				t.Errorf("service.Version = %q, want %q", svc.Version, tt.txt)
			}
		})
	}
}

type udpVersionBindConn struct {
	txt      string
	readBuf  []byte
	writeBuf []byte
}

func (m *udpVersionBindConn) Write(b []byte) (int, error) {
	var txID [2]byte
	if len(b) >= 2 {
		copy(txID[:], b[0:2])
	}
	prefixed := buildVersionBindResponseTXT(txID, m.txt)
	m.readBuf = prefixed[2:] // UDP has no TCP length prefix
	return len(b), nil
}
func (m *udpVersionBindConn) Read(b []byte) (int, error) {
	n := copy(b, m.readBuf)
	m.readBuf = m.readBuf[n:]
	return n, nil
}
func (m *udpVersionBindConn) Close() error                     { return nil }
func (m *udpVersionBindConn) LocalAddr() net.Addr              { return udpAddr{} }
func (m *udpVersionBindConn) RemoteAddr() net.Addr             { return udpAddr{} }
func (m *udpVersionBindConn) SetDeadline(time.Time) error      { return nil }
func (m *udpVersionBindConn) SetReadDeadline(time.Time) error  { return nil }
func (m *udpVersionBindConn) SetWriteDeadline(time.Time) error { return nil }

func TestBINDEOLFindingUDP(t *testing.T) {
	plugin := UDPPlugin{}
	tests := []struct {
		txt     string
		wantEOL bool
	}{
		{"9.6", true},
		{"9.8", true},
		{"9.20", false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.txt, func(t *testing.T) {
			conn := &udpVersionBindConn{txt: tt.txt}
			target := plugins.Target{
				Address:    netip.MustParseAddrPort("127.0.0.1:53"),
				Misconfigs: true,
			}
			svc, err := plugin.Run(conn, 5*time.Second, target)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if svc == nil {
				t.Fatal("Run() returned nil service")
			}
			found := false
			for _, f := range svc.SecurityFindings {
				if f.ID == "bind-eol" {
					found = true
				}
			}
			if found != tt.wantEOL {
				t.Errorf("bind-eol present=%v, want %v (findings=%v)", found, tt.wantEOL, svc.SecurityFindings)
			}
		})
	}
}

// oneShotThenEOFConn answers the first version.bind query, then returns EOF on
// subsequent Reads so a later SendRecv error would discard attempt-0's version
// if CheckDNS kept looping.
type oneShotThenEOFConn struct {
	network  string
	reads    int
	writeBuf []byte
	readBuf  []byte
}

func (m *oneShotThenEOFConn) Write(b []byte) (int, error) {
	m.writeBuf = append(m.writeBuf, b...)
	if m.network == "tcp" {
		if len(m.writeBuf) < 4 {
			return len(b), nil
		}
		var txID [2]byte
		copy(txID[:], m.writeBuf[2:4])
		m.readBuf = buildVersionBindResponseTXT(txID, "9.6")
	} else {
		if len(m.writeBuf) < 2 {
			return len(b), nil
		}
		var txID [2]byte
		copy(txID[:], m.writeBuf[0:2])
		prefixed := buildVersionBindResponseTXT(txID, "9.6")
		m.readBuf = prefixed[2:]
	}
	m.writeBuf = nil
	return len(b), nil
}

func (m *oneShotThenEOFConn) Read(b []byte) (int, error) {
	m.reads++
	if m.reads > 1 {
		return 0, io.EOF
	}
	n := copy(b, m.readBuf)
	m.readBuf = m.readBuf[n:]
	return n, nil
}
func (m *oneShotThenEOFConn) Close() error                     { return nil }
func (m *oneShotThenEOFConn) LocalAddr() net.Addr              { return m.addr() }
func (m *oneShotThenEOFConn) RemoteAddr() net.Addr             { return m.addr() }
func (m *oneShotThenEOFConn) SetDeadline(time.Time) error      { return nil }
func (m *oneShotThenEOFConn) SetReadDeadline(time.Time) error  { return nil }
func (m *oneShotThenEOFConn) SetWriteDeadline(time.Time) error { return nil }
func (m *oneShotThenEOFConn) addr() net.Addr {
	if m.network == "udp" {
		return udpAddr{}
	}
	return tcpAddr{}
}

func TestCheckDNS_ReturnsAfterFirstTXIDMatch(t *testing.T) {
	conn := &oneShotThenEOFConn{network: "tcp"}
	isDNS, version, err := CheckDNS(conn, 5*time.Second)
	if err != nil {
		t.Fatalf("CheckDNS() error = %v, want nil (attempt-0 version must not be discarded)", err)
	}
	if !isDNS {
		t.Fatal("CheckDNS() isDNS = false, want true")
	}
	if version != "9.6" {
		t.Errorf("CheckDNS() version = %q, want %q", version, "9.6")
	}
	if conn.reads != 1 {
		t.Errorf("CheckDNS issued %d Recv calls, want 1 (must return after first TXID match)", conn.reads)
	}
}

// shortTCPFrameConn returns a TCP DNS response whose declared length exceeds
// the bytes actually present, with a matching TXID in the prefix.
type shortTCPFrameConn struct {
	writeBuf []byte
	readBuf  []byte
}

func (m *shortTCPFrameConn) Write(b []byte) (int, error) {
	m.writeBuf = append(m.writeBuf, b...)
	if len(m.writeBuf) < 4 {
		return len(b), nil
	}
	txID0, txID1 := m.writeBuf[2], m.writeBuf[3]
	body := make([]byte, 20)
	body[0] = txID0
	body[1] = txID1
	out := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(out[0:2], 50)
	copy(out[2:], body)
	m.readBuf = out
	m.writeBuf = nil
	return len(b), nil
}
func (m *shortTCPFrameConn) Read(b []byte) (int, error) {
	n := copy(b, m.readBuf)
	m.readBuf = m.readBuf[n:]
	return n, nil
}
func (m *shortTCPFrameConn) Close() error                     { return nil }
func (m *shortTCPFrameConn) LocalAddr() net.Addr              { return tcpAddr{} }
func (m *shortTCPFrameConn) RemoteAddr() net.Addr             { return tcpAddr{} }
func (m *shortTCPFrameConn) SetDeadline(time.Time) error      { return nil }
func (m *shortTCPFrameConn) SetReadDeadline(time.Time) error  { return nil }
func (m *shortTCPFrameConn) SetWriteDeadline(time.Time) error { return nil }

func TestCheckDNS_TCPShortDeclaredLengthStillDetects(t *testing.T) {
	conn := &shortTCPFrameConn{}
	isDNS, version, err := CheckDNS(conn, 5*time.Second)
	if err != nil {
		t.Fatalf("CheckDNS() error = %v, want nil", err)
	}
	if !isDNS {
		t.Fatal("CheckDNS() isDNS = false, want true (TXID match detects DNS even if TCP length prefix exceeds received bytes)")
	}
	if version != "" {
		t.Errorf("CheckDNS() version = %q, want empty (incomplete TCP frame skips version parsing)", version)
	}
}

// TestDNSZoneTransferDocker spins up the ruudud/devdns container (already used by
// the UDP test) over TCP and verifies that TCPPlugin.Run completes without error
// when Misconfigs is true. devdns typically refuses AXFR, so the test accepts
// both outcomes (finding present or absent) — it validates stability, not a
// specific AXFR posture.
func TestDNSZoneTransferDocker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skip("Docker not available: " + err.Error())
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "ruudud/devdns",
		Mounts:     []string{"/var/run/docker.sock:/var/run/docker.sock:ro"},
		Privileged: true,
	})
	if err != nil {
		t.Skip("could not start DNS container: " + err.Error())
	}
	defer pool.Purge(resource) //nolint:errcheck

	rawAddr := resource.GetHostPort("53/tcp")
	if rawAddr == "" {
		t.Skip("DNS container did not expose port 53/tcp")
	}

	host, port, err := net.SplitHostPort(rawAddr)
	if err != nil {
		t.Fatalf("could not parse host:port %q: %v", rawAddr, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	targetAddr := net.JoinHostPort(host, port)

	err = pool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", targetAddr, 5*time.Second)
		if dialErr != nil {
			return dialErr
		}
		conn.Close()
		return nil
	})
	if err != nil {
		t.Skipf("DNS container TCP port not reachable: %v", err)
	}

	conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to open TCP connection to DNS container: %v", err)
	}
	defer conn.Close()

	addrPort, err := netip.ParseAddrPort(targetAddr)
	if err != nil {
		// Fallback: resolve hostname to a numeric IP so ParseAddrPort succeeds.
		ips, resolveErr := net.LookupIP(host)
		if resolveErr != nil || len(ips) == 0 {
			t.Fatalf("could not resolve host %q to IP: %v", host, resolveErr)
		}
		resolved := net.JoinHostPort(ips[0].String(), port)
		addrPort, err = netip.ParseAddrPort(resolved)
		if err != nil {
			t.Fatalf("could not parse resolved address %q: %v", resolved, err)
		}
	}
	target := plugins.Target{
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := TCPPlugin{}
	svc, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("TCPPlugin.Run() returned unexpected error: %v", err)
	}
	if svc == nil {
		// The container responded but TCP DNS detection failed — that is a valid
		// outcome for devdns (some builds only respond over UDP).
		t.Log("TCPPlugin.Run() returned nil service; devdns may be UDP-only on this build")
		return
	}

	// Verify the service record is well-formed regardless of whether AXFR is open.
	if svc.Protocol != plugins.ProtoDNS {
		t.Errorf("service Protocol = %q, want %q", svc.Protocol, plugins.ProtoDNS)
	}

	// Each SecurityFinding, if present, must carry the expected shape.
	for _, f := range svc.SecurityFindings {
		if f.ID == "" {
			t.Error("SecurityFinding.ID is empty")
		}
		if f.Severity == "" {
			t.Error("SecurityFinding.Severity is empty")
		}
		if f.Description == "" {
			t.Error("SecurityFinding.Description is empty")
		}
	}

	t.Logf("TCPPlugin.Run() service detected; SecurityFindings=%d", len(svc.SecurityFindings))
}

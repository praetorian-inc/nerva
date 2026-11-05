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
	"encoding/hex"
	"testing"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

func TestNetBIOS(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "netbios-ns",
			Port:        137,
			Protocol:    plugins.UDP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "dperson/samba",
				Cmd:        []string{"-n"},
				Privileged: true,
			},
		},
	}

	var p *Plugin

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

// buildNBSTATResponse constructs a minimal but valid NBSTAT response byte slice.
//
// Layout:
//
//	Header (12 bytes): txid(2) + flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
//	Question section (only present if qdCount > 0): literal wildcard name (34 bytes) + QTYPE(2) + QCLASS(2)
//	Answer section: answerName + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA
//	RDATA: NUM_NAMES(1) + entries(numNames*18) + MAC(6)
//
// answerName may be either a literal label (e.g. the same 34-byte encoded name)
// or a DNS compression pointer (2 bytes: 0xC0 0x0C).
//
// qdCount controls whether a question section is written at all. Real NBSTAT
// responses from Samba and Windows use QDCOUNT=0 (the question is not echoed
// back); qdCount=1 exists to cover responders that do echo it.
func buildNBSTATResponse(txid [2]byte, flags uint16, qdCount uint16, answerCount uint16, answerNameBytes []byte, names []plugins.NetbiosEntry, mac [6]byte) []byte {
	// Question section: 34-byte encoded wildcard + QTYPE + QCLASS
	questionName := []byte{
		0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
	}

	numNames := len(names)
	rdLength := 1 + numNames*18 + 6 // NUM_NAMES + entries + MAC

	var buf []byte

	// Header
	buf = append(buf, txid[0], txid[1])
	buf = append(buf, byte(flags>>8), byte(flags))
	buf = append(buf, byte(qdCount>>8), byte(qdCount))
	buf = append(buf, byte(answerCount>>8), byte(answerCount))
	buf = append(buf, 0x00, 0x00) // NSCOUNT
	buf = append(buf, 0x00, 0x00) // ARCOUNT

	// Question section - real responders (Samba, Windows) omit this (QDCOUNT=0).
	// Emit exactly qdCount entries so callers exercising qdCount > 1 get an
	// internally consistent fixture (header count matches body content).
	for i := uint16(0); i < qdCount; i++ {
		buf = append(buf, questionName...)
		buf = append(buf, 0x00, 0x21) // QTYPE: NBSTAT
		buf = append(buf, 0x00, 0x01) // QCLASS: IN
	}

	// Answer name
	buf = append(buf, answerNameBytes...)

	// TYPE + CLASS + TTL + RDLENGTH
	buf = append(buf, 0x00, 0x21)                        // TYPE: NBSTAT
	buf = append(buf, 0x00, 0x01)                        // CLASS: IN
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)            // TTL
	buf = append(buf, byte(rdLength>>8), byte(rdLength)) // RDLENGTH

	// RDATA
	buf = append(buf, byte(numNames))
	for _, e := range names {
		entry := make([]byte, 18)
		// 15-char name padded with spaces
		copy(entry[0:15], []byte(e.Name))
		for i := len(e.Name); i < 15; i++ {
			entry[i] = ' '
		}
		entry[15] = e.Suffix
		if e.Flags == "group" {
			entry[16] = 0x80
			entry[17] = 0x00
		}
		buf = append(buf, entry...)
	}
	buf = append(buf, mac[:]...)

	return buf
}

func TestParseNBSTATResponse_Valid(t *testing.T) {
	names := []plugins.NetbiosEntry{
		{Name: "MYHOST", Suffix: 0x00, Flags: "unique"},
		{Name: "WORKGROUP", Suffix: 0x00, Flags: "group"},
	}
	mac := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	// Use compression pointer for answer name
	answerName := []byte{0xC0, 0x0C}
	data := buildNBSTATResponse([2]byte{0x01, 0x02}, 0x8400, 1, 1, answerName, names, mac)

	result, ok := parseNBSTATResponse(data)
	if !ok {
		t.Fatal("expected parseNBSTATResponse to return true for valid response")
	}
	if result.NetBIOSName != "MYHOST" {
		t.Errorf("expected NetBIOSName %q, got %q", "MYHOST", result.NetBIOSName)
	}
	if result.GroupName != "WORKGROUP" {
		t.Errorf("expected GroupName %q, got %q", "WORKGROUP", result.GroupName)
	}
	if result.MACAddress != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected MACAddress %q, got %q", "aa:bb:cc:dd:ee:ff", result.MACAddress)
	}
	if len(result.Names) != 2 {
		t.Errorf("expected 2 names, got %d", len(result.Names))
	}
}

func TestParseNBSTATResponse_TooShort(t *testing.T) {
	data := make([]byte, 8) // shorter than 12-byte minimum header
	_, ok := parseNBSTATResponse(data)
	if ok {
		t.Error("expected parseNBSTATResponse to return false for response shorter than 12 bytes")
	}
}

func TestParseNBSTATResponse_NotResponse(t *testing.T) {
	names := []plugins.NetbiosEntry{
		{Name: "HOST", Suffix: 0x00, Flags: "unique"},
	}
	mac := [6]byte{}
	answerName := []byte{0xC0, 0x0C}
	// flags with bit 15 clear = query, not response
	data := buildNBSTATResponse([2]byte{0x00, 0x01}, 0x0400, 1, 1, answerName, names, mac)

	_, ok := parseNBSTATResponse(data)
	if ok {
		t.Error("expected parseNBSTATResponse to return false when response bit is not set")
	}
}

func TestParseNBSTATResponse_NonZeroRCODE(t *testing.T) {
	names := []plugins.NetbiosEntry{
		{Name: "HOST", Suffix: 0x00, Flags: "unique"},
	}
	mac := [6]byte{}
	answerName := []byte{0xC0, 0x0C}
	// flags: response (bit 15) set, but RCODE = 3 (name error)
	data := buildNBSTATResponse([2]byte{0x00, 0x01}, 0x8403, 1, 1, answerName, names, mac)

	_, ok := parseNBSTATResponse(data)
	if ok {
		t.Error("expected parseNBSTATResponse to return false when RCODE != 0")
	}
}

func TestParseNBSTATResponse_ZeroANCOUNT(t *testing.T) {
	names := []plugins.NetbiosEntry{
		{Name: "HOST", Suffix: 0x00, Flags: "unique"},
	}
	mac := [6]byte{}
	answerName := []byte{0xC0, 0x0C}
	// ANCOUNT = 0
	data := buildNBSTATResponse([2]byte{0x00, 0x01}, 0x8400, 1, 0, answerName, names, mac)

	_, ok := parseNBSTATResponse(data)
	if ok {
		t.Error("expected parseNBSTATResponse to return false when ANCOUNT == 0")
	}
}

func TestParseNBSTATResponse_CompressedPointer(t *testing.T) {
	names := []plugins.NetbiosEntry{
		{Name: "SERVER01", Suffix: 0x00, Flags: "unique"},
	}
	mac := [6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	// Answer name uses DNS compression pointer 0xC0 0x0C
	answerName := []byte{0xC0, 0x0C}
	data := buildNBSTATResponse([2]byte{0x00, 0x01}, 0x8400, 1, 1, answerName, names, mac)

	result, ok := parseNBSTATResponse(data)
	if !ok {
		t.Fatal("expected parseNBSTATResponse to return true with compressed answer name")
	}
	if result.NetBIOSName != "SERVER01" {
		t.Errorf("expected NetBIOSName %q, got %q", "SERVER01", result.NetBIOSName)
	}
}

func TestParseNBSTATResponse_GroupOnly(t *testing.T) {
	names := []plugins.NetbiosEntry{
		{Name: "WORKGROUP", Suffix: 0x00, Flags: "group"},
		{Name: "MSBROWSE", Suffix: 0x01, Flags: "group"},
	}
	mac := [6]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	answerName := []byte{0xC0, 0x0C}
	data := buildNBSTATResponse([2]byte{0x01, 0x02}, 0x8400, 1, 1, answerName, names, mac)

	result, ok := parseNBSTATResponse(data)
	if !ok {
		t.Fatal("expected parseNBSTATResponse to return true when len(Names) > 0")
	}
	if result.NetBIOSName != "" {
		t.Errorf("expected NetBIOSName to be empty (no unique entries), got %q", result.NetBIOSName)
	}
	if result.GroupName != "WORKGROUP" {
		t.Errorf("expected GroupName %q, got %q", "WORKGROUP", result.GroupName)
	}
	if len(result.Names) != 2 {
		t.Errorf("expected 2 names, got %d", len(result.Names))
	}
	if result.MACAddress != "00:11:22:33:44:55" {
		t.Errorf("expected MACAddress %q, got %q", "00:11:22:33:44:55", result.MACAddress)
	}
}

// TestParseNBSTATResponse_QDCountTwo exercises the loop in parseNBSTATResponse
// that skips QDCOUNT question entries when there is more than one - nothing
// else in this file does, since every other fixture uses qdCount 0 or 1.
func TestParseNBSTATResponse_QDCountTwo(t *testing.T) {
	names := []plugins.NetbiosEntry{
		{Name: "MULTIQ", Suffix: 0x00, Flags: "unique"},
	}
	mac := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	// Compression pointer back to the first question's name (offset 12) is
	// valid regardless of how many questions precede the answer.
	answerName := []byte{0xC0, 0x0C}
	data := buildNBSTATResponse([2]byte{0x00, 0x01}, 0x8400, 2, 1, answerName, names, mac)

	result, ok := parseNBSTATResponse(data)
	if !ok {
		t.Fatal("expected parseNBSTATResponse to return true for a QDCOUNT=2 response")
	}
	if result.NetBIOSName != "MULTIQ" {
		t.Errorf("expected NetBIOSName %q, got %q", "MULTIQ", result.NetBIOSName)
	}
}

// TestParseNBSTATResponse_QDCountZero is a regression test: real NBSTAT
// responders (Samba's nmbd, Windows) reply with QDCOUNT=0 - they do not echo
// the question section back. The parser previously assumed a question
// section was always present and unconditionally skipped one, which for a
// QDCOUNT=0 response mis-parses the answer's own name as the question and
// desyncs every offset after it, causing every real-world response to be
// rejected. All the other tests in this file use qdCount=1 and could not
// have caught this.
func TestParseNBSTATResponse_QDCountZero(t *testing.T) {
	names := []plugins.NetbiosEntry{
		{Name: "MYHOST", Suffix: 0x00, Flags: "unique"},
		{Name: "WORKGROUP", Suffix: 0x00, Flags: "group"},
	}
	mac := [6]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	// With QDCOUNT=0 there is no question section, so the answer name starts
	// immediately after the 12-byte header; it cannot be a compression
	// pointer back into a (nonexistent) question, so use a literal label.
	answerName := []byte{
		0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
	}
	data := buildNBSTATResponse([2]byte{0x01, 0x02}, 0x8400, 0, 1, answerName, names, mac)

	result, ok := parseNBSTATResponse(data)
	if !ok {
		t.Fatal("expected parseNBSTATResponse to return true for a QDCOUNT=0 response")
	}
	if result.NetBIOSName != "MYHOST" {
		t.Errorf("expected NetBIOSName %q, got %q", "MYHOST", result.NetBIOSName)
	}
	if result.GroupName != "WORKGROUP" {
		t.Errorf("expected GroupName %q, got %q", "WORKGROUP", result.GroupName)
	}
}

// TestParseNBSTATResponse_RealNmbdCapture feeds parseNBSTATResponse the exact
// bytes captured from a real Samba nmbd 4.17.12 instance (Debian bookworm)
// responding to the wildcard NBSTAT probe this plugin sends, netbios name
// "TESTBOX", workgroup "WORKGROUP". This is an implementation-agnostic,
// byte-exact regression check independent of the TestNetBIOS Docker
// integration test above (which uses the dperson/samba image and was not
// run/verified in the environment this bug was found and fixed in).
func TestParseNBSTATResponse_RealNmbdCapture(t *testing.T) {
	data, err := hex.DecodeString(
		"4a6e8400000000010000000020434b4141414141414141414141414141414141" +
			"4141414141414141414141414100002100010000000000ad0754455354424f58" +
			"202020202020202000040054455354424f582020202020202020030400544553" +
			"54424f58202020202020202020040001025f5f4d5342524f5753455f5f020184" +
			"00574f524b47524f5550202020202020008400574f524b47524f555020202020" +
			"20201d0400574f524b47524f55502020202020201e8400000000000000000000" +
			"0000000000000000000000000000000000000000000000000000000000000000" +
			"0000000000",
	)
	if err != nil {
		t.Fatalf("bad test fixture hex: %v", err)
	}

	result, ok := parseNBSTATResponse(data)
	if !ok {
		t.Fatal("expected parseNBSTATResponse to accept a real nmbd capture")
	}
	if result.NetBIOSName != "TESTBOX" {
		t.Errorf("expected NetBIOSName %q, got %q", "TESTBOX", result.NetBIOSName)
	}
	if result.GroupName != "WORKGROUP" {
		t.Errorf("expected GroupName %q, got %q", "WORKGROUP", result.GroupName)
	}
	if len(result.Names) == 0 {
		t.Error("expected a non-empty name table from the real capture")
	}
}

func TestSkipDNSName_Literal(t *testing.T) {
	// Literal label: length byte + label bytes + 0x00 terminator
	// "\x04test\x00" = 1 + 4 + 1 = 6 bytes, starting at offset 0
	data := []byte{0x04, 't', 'e', 's', 't', 0x00, 0xFF}
	newOffset := skipDNSName(data, 0)
	if newOffset != 6 {
		t.Errorf("expected offset 6 after literal label, got %d", newOffset)
	}
}

func TestSkipDNSName_Pointer(t *testing.T) {
	// Compression pointer at offset 0: 0xC0 0x0C
	data := []byte{0xC0, 0x0C, 0xFF, 0xFF}
	newOffset := skipDNSName(data, 0)
	if newOffset != 2 {
		t.Errorf("expected offset 2 after compression pointer, got %d", newOffset)
	}
}

func TestSkipDNSName_Empty(t *testing.T) {
	// offset at end of data should return -1
	data := []byte{0x01, 0x02}
	newOffset := skipDNSName(data, 2)
	if newOffset != -1 {
		t.Errorf("expected -1 when offset is at end of data, got %d", newOffset)
	}
}

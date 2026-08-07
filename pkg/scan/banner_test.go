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

package scan

import (
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// fakePlugin is a minimal plugins.Plugin implementation used to test
// FilterPluginsByFamily in isolation from the real (150+) registered plugin
// list, so name-matching behavior can be verified deterministically.
type fakePlugin struct {
	name string
}

func (f fakePlugin) Run(net.Conn, time.Duration, plugins.Target) (*plugins.Service, error) {
	return nil, nil
}
func (f fakePlugin) PortPriority(uint16) bool { return false }
func (f fakePlugin) Name() string             { return f.name }
func (f fakePlugin) Type() plugins.Protocol   { return plugins.TCP }
func (f fakePlugin) Priority() int            { return 0 }

// mysqlGreeting builds a byte slice shaped like a real MySQL initial handshake
// packet: 3-byte little-endian length, 1-byte sequence id, 1-byte protocol
// version (0x0a), then a null-terminated server version string.
func mysqlGreeting(version string) []byte {
	payload := append([]byte{0x0a}, []byte(version)...)
	payload = append(payload, 0x00) // null terminator
	// pad with a handful of realistic trailing handshake bytes
	payload = append(payload, []byte{0x0b, 0x00, 0x00, 0x00}...) // connection id
	length := len(payload)
	header := []byte{byte(length), byte(length >> 8), byte(length >> 16), 0x00}
	return append(header, payload...)
}

func TestClassifyBanner_SSH(t *testing.T) {
	cases := [][]byte{
		[]byte("SSH-2.0-OpenSSH_8.9\r\n"),
		[]byte("SSH-1.99-OpenSSH_3.6.1sp1\r\n"),
	}
	for _, banner := range cases {
		if got := ClassifyBanner(banner); got != ProtocolFamilySSH {
			t.Errorf("ClassifyBanner(%q) = %v, want ProtocolFamilySSH", banner, got)
		}
	}
}

func TestClassifyBanner_MySQL(t *testing.T) {
	banner := mysqlGreeting("8.0.28")
	if got := ClassifyBanner(banner); got != ProtocolFamilyMySQL {
		t.Errorf("ClassifyBanner(%x) = %v, want ProtocolFamilyMySQL", banner, got)
	}
}

func TestClassifyBanner_TLS(t *testing.T) {
	cases := [][]byte{
		{0x16, 0x03, 0x01, 0x00, 0x2f}, // TLS 1.0 record header
		{0x16, 0x03, 0x03, 0x00, 0x7a}, // TLS 1.2 record header
	}
	for _, banner := range cases {
		if got := ClassifyBanner(banner); got != ProtocolFamilyTLS {
			t.Errorf("ClassifyBanner(% x) = %v, want ProtocolFamilyTLS", banner, got)
		}
	}
}

func TestClassifyBanner_SMTP(t *testing.T) {
	cases := [][]byte{
		[]byte("220 mail.example.com ESMTP Postfix\r\n"),
		[]byte("220 smtp.example.net Simple Mail Transfer Service ready\r\n"),
		[]byte("220 ftp.example.com ESMTP Postfix\r\n"),
	}
	for _, banner := range cases {
		if got := ClassifyBanner(banner); got != ProtocolFamilySMTP {
			t.Errorf("ClassifyBanner(%q) = %v, want ProtocolFamilySMTP", banner, got)
		}
	}
}

func TestClassifyBanner_FTP(t *testing.T) {
	cases := [][]byte{
		[]byte("220 (vsFTPd 3.0.3)\r\n"),
		[]byte("220 ProFTPD Server ready.\r\n"),
		[]byte("220 FileZilla Server 1.5.1\r\n"),
	}
	for _, banner := range cases {
		if got := ClassifyBanner(banner); got != ProtocolFamilyFTP {
			t.Errorf("ClassifyBanner(%q) = %v, want ProtocolFamilyFTP", banner, got)
		}
	}
}

func TestClassifyBanner_Telnet(t *testing.T) {
	cases := [][]byte{
		{0xff, 0xfd, 0x01}, // IAC DO ECHO
		{0xff, 0xfb, 0x03}, // IAC WILL SUPPRESS-GO-AHEAD
	}
	for _, banner := range cases {
		if got := ClassifyBanner(banner); got != ProtocolFamilyTelnet {
			t.Errorf("ClassifyBanner(% x) = %v, want ProtocolFamilyTelnet", banner, got)
		}
	}
}

func TestClassifyBanner_HTTP(t *testing.T) {
	banner := []byte("HTTP/1.1 200 OK\r\n")
	if got := ClassifyBanner(banner); got != ProtocolFamilyHTTP {
		t.Errorf("ClassifyBanner(%q) = %v, want ProtocolFamilyHTTP", banner, got)
	}
}

func TestClassifyBanner_UnknownEdgeCases(t *testing.T) {
	cases := []struct {
		name   string
		banner []byte
	}{
		{"empty", []byte{}},
		{"nil", nil},
		{"truncated SSH prefix", []byte("SSH")},
		{"truncated 220 response", []byte("22")},
		{"ambiguous 220 no keywords", []byte("220 ready\r\n")},
		{"single IAC byte only", []byte{0xff}},
		{"IAC with invalid command", []byte{0xff, 0x01, 0x02}},
		{"TLS-like prefix too short", []byte{0x16}},
		{"mysql-like byte4 but no null terminator", []byte{0x0b, 0x00, 0x00, 0x00, 0x0a, 'a', 'b', 'c'}},
		{"mysql-like byte4 but empty version string", []byte{0x0b, 0x00, 0x00, 0x00, 0x0a, 0x00}},
		{"mysql-like but non-zero sequence id", []byte{0x0b, 0x00, 0x00, 0x01, 0x0a, '8', '.', '0', '.', '0', 0x00}},
		{"mysql-like but undersized payload length", []byte{0x02, 0x00, 0x00, 0x00, 0x0a, '8', '.', '0', '.', '0', 0x00}},
		{"random binary garbage", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{"random binary garbage 2", []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyBanner(tc.banner); got != ProtocolFamilyUnknown {
				t.Errorf("ClassifyBanner(%v) = %v, want ProtocolFamilyUnknown", tc.banner, got)
			}
		})
	}
}

func TestProtocolFamily_String(t *testing.T) {
	cases := map[ProtocolFamily]string{
		ProtocolFamilyUnknown: "Unknown",
		ProtocolFamilySSH:     "SSH",
		ProtocolFamilyHTTP:    "HTTP",
		ProtocolFamilyMySQL:   "MySQL",
		ProtocolFamilyTLS:     "TLS",
		ProtocolFamilySMTP:    "SMTP",
		ProtocolFamilyFTP:     "FTP",
		ProtocolFamilyTelnet:  "Telnet",
	}
	for family, want := range cases {
		if got := family.String(); got != want {
			t.Errorf("ProtocolFamily(%d).String() = %q, want %q", family, got, want)
		}
	}
}

// stubConn is a minimal net.Conn that returns canned data/errors from Read,
// used to test ReadBanner without a real network connection.
type stubConn struct {
	net.Conn
	data      []byte
	err       error
	blockRead bool
	readDone  chan struct{}
}

func (s *stubConn) Read(b []byte) (int, error) {
	if s.blockRead {
		<-s.readDone
	}
	if s.err != nil && len(s.data) == 0 {
		return 0, s.err
	}
	n := copy(b, s.data)
	return n, s.err
}

// SetReadDeadline closes readDone when a non-zero deadline is set, which
// unblocks a Read call that is waiting on <-s.readDone. This simulates a
// real net.Conn where setting a read deadline causes an in-flight blocked
// Read to return once the deadline passes.
func (s *stubConn) SetReadDeadline(t time.Time) error {
	if s.blockRead && !t.IsZero() {
		close(s.readDone)
	}
	return nil
}

func TestReadBanner_ImmediateData(t *testing.T) {
	conn := &stubConn{data: []byte("SSH-2.0-OpenSSH_8.9\r\n")}
	banner, err := ReadBanner(conn, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("ReadBanner returned error: %v", err)
	}
	if string(banner) != "SSH-2.0-OpenSSH_8.9\r\n" {
		t.Errorf("ReadBanner returned %q, want SSH banner", banner)
	}
}

func TestReadBanner_UsesDefaultTimeoutWhenZero(t *testing.T) {
	conn := &stubConn{data: []byte("220 ready\r\n")}
	banner, err := ReadBanner(conn, 0)
	if err != nil {
		t.Fatalf("ReadBanner returned error: %v", err)
	}
	if len(banner) == 0 {
		t.Errorf("ReadBanner with zero timeout returned no data, want banner bytes")
	}
}

func TestReadBanner_TimeoutPathReturnsWithoutHanging(t *testing.T) {
	conn := &stubConn{blockRead: true, readDone: make(chan struct{})}

	done := make(chan struct{})
	var banner []byte
	var err error
	go func() {
		banner, err = ReadBanner(conn, 50*time.Millisecond)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ReadBanner did not return within 2s, want it to unblock on read deadline")
	}

	if err != nil {
		t.Errorf("ReadBanner returned error: %v, want nil", err)
	}
	if len(banner) != 0 {
		t.Errorf("ReadBanner returned %q, want empty banner", banner)
	}
}

func TestFilterPluginsByFamily_NarrowsToMatchingName(t *testing.T) {
	candidates := []plugins.Plugin{
		fakePlugin{name: "ssh"},
		fakePlugin{name: "ftp"},
		fakePlugin{name: "telnet"},
	}
	filtered := FilterPluginsByFamily(candidates, ProtocolFamilySSH)
	if len(filtered) != 1 || filtered[0].Name() != "ssh" {
		t.Errorf("FilterPluginsByFamily(SSH) = %v, want only the ssh plugin", filtered)
	}
}

func TestFilterPluginsByFamily_CaseInsensitiveNameMatch(t *testing.T) {
	candidates := []plugins.Plugin{
		fakePlugin{name: "MySQL"},
		fakePlugin{name: "ftp"},
	}
	filtered := FilterPluginsByFamily(candidates, ProtocolFamilyMySQL)
	if len(filtered) != 1 || filtered[0].Name() != "MySQL" {
		t.Errorf("FilterPluginsByFamily(MySQL) = %v, want only the MySQL plugin", filtered)
	}
}

func TestFilterPluginsByFamily_HTTPIncludesHTTPS(t *testing.T) {
	candidates := []plugins.Plugin{
		fakePlugin{name: "http"},
		fakePlugin{name: "https"},
		fakePlugin{name: "ftp"},
	}
	filtered := FilterPluginsByFamily(candidates, ProtocolFamilyHTTP)
	if len(filtered) != 2 {
		t.Errorf("FilterPluginsByFamily(HTTP) = %v, want http and https plugins only", filtered)
	}
}

func TestFilterPluginsByFamily_UnknownReturnsAllUnmodified(t *testing.T) {
	candidates := []plugins.Plugin{
		fakePlugin{name: "ssh"},
		fakePlugin{name: "ftp"},
	}
	filtered := FilterPluginsByFamily(candidates, ProtocolFamilyUnknown)
	if len(filtered) != len(candidates) {
		t.Errorf("FilterPluginsByFamily(Unknown) narrowed candidates, want all %d plugins unmodified, got %d", len(candidates), len(filtered))
	}
}

func TestFilterPluginsByFamily_TLSReturnsAllUnmodified(t *testing.T) {
	candidates := []plugins.Plugin{
		fakePlugin{name: "https"},
		fakePlugin{name: "smtps"},
		fakePlugin{name: "ftp"},
	}
	filtered := FilterPluginsByFamily(candidates, ProtocolFamilyTLS)
	if len(filtered) != len(candidates) {
		t.Errorf("FilterPluginsByFamily(TLS) narrowed candidates, want all %d plugins unmodified, got %d", len(candidates), len(filtered))
	}
}

func TestFilterPluginsByFamily_NoMatchFallsBackToAllCandidates(t *testing.T) {
	// None of these candidates are an ssh plugin, so narrowing to SSH would
	// produce an empty list. The safe fallback is to return everything
	// rather than scanning nothing.
	candidates := []plugins.Plugin{
		fakePlugin{name: "ftp"},
		fakePlugin{name: "telnet"},
	}
	filtered := FilterPluginsByFamily(candidates, ProtocolFamilySSH)
	if len(filtered) != len(candidates) {
		t.Errorf("FilterPluginsByFamily(SSH) with no ssh candidates = %v, want safe fallback to all %d candidates", filtered, len(candidates))
	}
}

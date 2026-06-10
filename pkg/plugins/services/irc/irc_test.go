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

package irc

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// TestParseIRCLine tests the IRC message line parser.
func TestParseIRCLine(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		wantPrefix      string
		wantCommand     string
		wantParamsCount int
		wantTrail       string
	}{
		{
			name:        "simple command no prefix",
			input:       "PING :server.example.com",
			wantCommand: "PING",
			wantTrail:   "server.example.com",
		},
		{
			name:            "numeric with prefix",
			input:           ":irc.example.com 001 nervaprobe :Welcome to ExampleNet",
			wantPrefix:      "irc.example.com",
			wantCommand:     "001",
			wantParamsCount: 1,
			wantTrail:       "Welcome to ExampleNet",
		},
		{
			name:            "004 with multiple params",
			input:           ":irc.example.com 004 nervaprobe irc.example.com InspIRCd-4.0.1 iosw bklosu",
			wantPrefix:      "irc.example.com",
			wantCommand:     "004",
			wantParamsCount: 5, // nervaprobe irc.example.com InspIRCd-4.0.1 iosw bklosu
		},
		{
			name:        "error message",
			input:       "ERROR :Closing Link: nervaprobe (K-Lined)",
			wantCommand: "ERROR",
			wantTrail:   "Closing Link: nervaprobe (K-Lined)",
		},
		{
			name:            "command with crlf",
			input:           ":srv 001 nick :Welcome\r\n",
			wantPrefix:      "srv",
			wantCommand:     "001",
			wantParamsCount: 1, // nick
			wantTrail:       "Welcome",
		},
		{
			name:        "empty input",
			input:       "",
			wantCommand: "",
		},
		{
			name:        "prefix only no space",
			input:       ":onlyprefixnocommand",
			wantPrefix:  "onlyprefixnocommand",
			wantCommand: "",
		},
		{
			name:            "numeric without trailing",
			input:           ":irc.test.net 003 nervaprobe irc.test.net",
			wantPrefix:      "irc.test.net",
			wantCommand:     "003",
			wantParamsCount: 2, // nervaprobe irc.test.net
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := parseIRCLine(tc.input)
			if msg.prefix != tc.wantPrefix {
				t.Errorf("prefix: got %q, want %q", msg.prefix, tc.wantPrefix)
			}
			if msg.command != tc.wantCommand {
				t.Errorf("command: got %q, want %q", msg.command, tc.wantCommand)
			}
			if len(msg.params) != tc.wantParamsCount {
				t.Errorf("params count: got %d, want %d (params=%v)", len(msg.params), tc.wantParamsCount, msg.params)
			}
			if msg.trail != tc.wantTrail {
				t.Errorf("trail: got %q, want %q", msg.trail, tc.wantTrail)
			}
		})
	}
}

// buildWelcome joins IRC welcome burst lines into a single response string.
func buildWelcome(lines []string) string {
	return strings.Join(lines, "\n")
}

// TestParseIRCResponse_InspIRCd tests parsing of a full InspIRCd welcome sequence.
func TestParseIRCResponse_InspIRCd(t *testing.T) {
	response := buildWelcome([]string{
		":irc.example.com 001 nervaprobe :Welcome to the ExampleNet Internet Relay Chat Network nervaprobe\r",
		":irc.example.com 002 nervaprobe :Your host is irc.example.com, running version InspIRCd-4.0.1\r",
		":irc.example.com 003 nervaprobe :This server was created 2024-01-15\r",
		":irc.example.com 004 nervaprobe irc.example.com InspIRCd-4.0.1 iosw bklosu\r",
		":irc.example.com 005 nervaprobe CHANTYPES=# PREFIX=(ov)@+ :are supported by this server\r",
		":irc.example.com 251 nervaprobe :There are 42 users and 3 services on 2 servers\r",
	})

	result := parseIRCResponse(response)
	if result == nil {
		t.Fatal("expected non-nil result for valid InspIRCd response")
	}
	if result.serverName != "irc.example.com" {
		t.Errorf("serverName: got %q, want %q", result.serverName, "irc.example.com")
	}
	if result.networkName != "ExampleNet" {
		t.Errorf("networkName: got %q, want %q", result.networkName, "ExampleNet")
	}
	if result.serverSoftware != "InspIRCd" {
		t.Errorf("serverSoftware: got %q, want %q", result.serverSoftware, "InspIRCd")
	}
	if result.version != "4.0.1" {
		t.Errorf("version: got %q, want %q", result.version, "4.0.1")
	}
	if result.createdDate != "2024-01-15" {
		t.Errorf("createdDate: got %q, want %q", result.createdDate, "2024-01-15")
	}
	if result.userModes != "iosw" {
		t.Errorf("userModes: got %q, want %q", result.userModes, "iosw")
	}
	if result.channelModes != "bklosu" {
		t.Errorf("channelModes: got %q, want %q", result.channelModes, "bklosu")
	}
	if result.userCount != 42 {
		t.Errorf("userCount: got %d, want %d", result.userCount, 42)
	}
}

// TestParseIRCResponse_UnrealIRCd tests parsing of a full UnrealIRCd welcome sequence.
func TestParseIRCResponse_UnrealIRCd(t *testing.T) {
	response := buildWelcome([]string{
		":irc.test.net 001 nervaprobe :Welcome to the TestNetwork Internet Relay Chat Network nervaprobe\r",
		":irc.test.net 002 nervaprobe :Your host is irc.test.net, running version UnrealIRCd-6.1.3\r",
		":irc.test.net 003 nervaprobe :This server was created 2023-06-01\r",
		":irc.test.net 004 nervaprobe irc.test.net UnrealIRCd-6.1.3 iowrsxzdHtIDZRqpWGTSB lvhopsmntikraqbeIMjfSKLzgZNQcRXGTOVHdDuw\r",
		":irc.test.net 251 nervaprobe :There are 100 users and 5 services on 3 servers\r",
	})

	result := parseIRCResponse(response)
	if result == nil {
		t.Fatal("expected non-nil result for valid UnrealIRCd response")
	}
	if result.serverName != "irc.test.net" {
		t.Errorf("serverName: got %q, want %q", result.serverName, "irc.test.net")
	}
	if result.networkName != "TestNetwork" {
		t.Errorf("networkName: got %q, want %q", result.networkName, "TestNetwork")
	}
	if result.serverSoftware != "UnrealIRCd" {
		t.Errorf("serverSoftware: got %q, want %q", result.serverSoftware, "UnrealIRCd")
	}
	if result.version != "6.1.3" {
		t.Errorf("version: got %q, want %q", result.version, "6.1.3")
	}
	if result.userCount != 100 {
		t.Errorf("userCount: got %d, want %d", result.userCount, 100)
	}
}

// TestParseIRCResponse_IRCdHybrid tests parsing of a full ircd-hybrid welcome sequence.
func TestParseIRCResponse_IRCdHybrid(t *testing.T) {
	response := buildWelcome([]string{
		":hybrid.example.org 001 nervaprobe :Welcome to the HybridNet Internet Relay Chat Network nervaprobe\r",
		":hybrid.example.org 002 nervaprobe :Your host is hybrid.example.org, running version ircd-hybrid-8.2.43\r",
		":hybrid.example.org 003 nervaprobe :This server was created 2024-03-20\r",
		":hybrid.example.org 004 nervaprobe hybrid.example.org ircd-hybrid-8.2.43 oiws bkloveqjfI\r",
		":hybrid.example.org 251 nervaprobe :There are 15 users and 0 services on 1 servers\r",
	})

	result := parseIRCResponse(response)
	if result == nil {
		t.Fatal("expected non-nil result for valid ircd-hybrid response")
	}
	if result.serverName != "hybrid.example.org" {
		t.Errorf("serverName: got %q, want %q", result.serverName, "hybrid.example.org")
	}
	if result.networkName != "HybridNet" {
		t.Errorf("networkName: got %q, want %q", result.networkName, "HybridNet")
	}
	if result.serverSoftware != "ircd-hybrid" {
		t.Errorf("serverSoftware: got %q, want %q", result.serverSoftware, "ircd-hybrid")
	}
	if result.version != "8.2.43" {
		t.Errorf("version: got %q, want %q", result.version, "8.2.43")
	}
	if result.userCount != 15 {
		t.Errorf("userCount: got %d, want %d", result.userCount, 15)
	}
}

// TestParseIRCResponse_ngIRCd tests parsing of a full ngIRCd welcome sequence.
func TestParseIRCResponse_ngIRCd(t *testing.T) {
	response := buildWelcome([]string{
		":ngircd.local 001 nervaprobe :Welcome to the LocalNet Internet Relay Chat Network nervaprobe\r",
		":ngircd.local 002 nervaprobe :Your host is ngircd.local, running version ngIRCd-27\r",
		":ngircd.local 003 nervaprobe :This server was created 2024-02-28\r",
		":ngircd.local 004 nervaprobe ngircd.local ngIRCd-27 aioqr abeiIklmnoOpqrstv\r",
		":ngircd.local 251 nervaprobe :There are 5 users and 0 services on 1 servers\r",
	})

	result := parseIRCResponse(response)
	if result == nil {
		t.Fatal("expected non-nil result for valid ngIRCd response")
	}
	if result.serverName != "ngircd.local" {
		t.Errorf("serverName: got %q, want %q", result.serverName, "ngircd.local")
	}
	if result.networkName != "LocalNet" {
		t.Errorf("networkName: got %q, want %q", result.networkName, "LocalNet")
	}
	if result.serverSoftware != "ngIRCd" {
		t.Errorf("serverSoftware: got %q, want %q", result.serverSoftware, "ngIRCd")
	}
	if result.version != "27" {
		t.Errorf("version: got %q, want %q", result.version, "27")
	}
	if result.userCount != 5 {
		t.Errorf("userCount: got %d, want %d", result.userCount, 5)
	}
}

// TestParseIRCResponse_Charybdis tests parsing of a full Charybdis welcome sequence.
func TestParseIRCResponse_Charybdis(t *testing.T) {
	response := buildWelcome([]string{
		":charybdis.test 001 nervaprobe :Welcome to the CharybdisNet Internet Relay Chat Network nervaprobe\r",
		":charybdis.test 002 nervaprobe :Your host is charybdis.test, running version charybdis-4.1.2\r",
		":charybdis.test 003 nervaprobe :This server was created 2024-05-10\r",
		":charybdis.test 004 nervaprobe charybdis.test charybdis-4.1.2 DQRSZaghilopswz CFILMPQSTbcefgijklmnopqrstvz bkloveqjfI\r",
		":charybdis.test 251 nervaprobe :There are 200 users and 10 services on 5 servers\r",
	})

	result := parseIRCResponse(response)
	if result == nil {
		t.Fatal("expected non-nil result for valid Charybdis response")
	}
	if result.serverName != "charybdis.test" {
		t.Errorf("serverName: got %q, want %q", result.serverName, "charybdis.test")
	}
	if result.networkName != "CharybdisNet" {
		t.Errorf("networkName: got %q, want %q", result.networkName, "CharybdisNet")
	}
	if result.serverSoftware != "charybdis" {
		t.Errorf("serverSoftware: got %q, want %q", result.serverSoftware, "charybdis")
	}
	if result.version != "4.1.2" {
		t.Errorf("version: got %q, want %q", result.version, "4.1.2")
	}
	if result.userCount != 200 {
		t.Errorf("userCount: got %d, want %d", result.userCount, 200)
	}
}

// TestExtractNetworkName tests the network name extraction from RPL_WELCOME messages.
func TestExtractNetworkName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "standard IRC Network suffix",
			input: "Welcome to the ExampleNet Internet Relay Chat Network nervaprobe",
			want:  "ExampleNet",
		},
		{
			name:  "IRC Network suffix",
			input: "Welcome to the TestIRC IRC Network nervaprobe",
			want:  "TestIRC",
		},
		{
			name:  "Network suffix only",
			input: "Welcome to the FooNetwork Network nervaprobe",
			want:  "FooNetwork",
		},
		{
			name:  "no prefix",
			input: "Something else entirely",
			want:  "",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "just prefix and nick",
			input: "Welcome to the nervaprobe",
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractNetworkName(tc.input)
			if got != tc.want {
				t.Errorf("extractNetworkName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestExtractVersionInfo tests version string splitting into software+version.
func TestExtractVersionInfo(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantSoftware string
		wantVersion  string
	}{
		{
			name:         "UnrealIRCd",
			input:        "Your host is irc.test.net, running version UnrealIRCd-6.1.3",
			wantSoftware: "UnrealIRCd",
			wantVersion:  "6.1.3",
		},
		{
			name:         "InspIRCd",
			input:        "Your host is irc.example.com, running version InspIRCd-4.0.1",
			wantSoftware: "InspIRCd",
			wantVersion:  "4.0.1",
		},
		{
			name:         "ircd-hybrid",
			input:        "Your host is hybrid.example.org, running version ircd-hybrid-8.2.43",
			wantSoftware: "ircd-hybrid",
			wantVersion:  "8.2.43",
		},
		{
			name:         "ngIRCd numeric only version",
			input:        "Your host is ngircd.local, running version ngIRCd-27",
			wantSoftware: "ngIRCd",
			wantVersion:  "27",
		},
		{
			name:         "charybdis",
			input:        "Your host is charybdis.test, running version charybdis-4.1.2",
			wantSoftware: "charybdis",
			wantVersion:  "4.1.2",
		},
		{
			name:         "no running version phrase",
			input:        "Your host is server.example.com, no version info",
			wantSoftware: "",
			wantVersion:  "",
		},
		{
			name:         "empty string",
			input:        "",
			wantSoftware: "",
			wantVersion:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotSoftware, gotVersion := extractVersionInfo(tc.input)
			if gotSoftware != tc.wantSoftware {
				t.Errorf("software: got %q, want %q", gotSoftware, tc.wantSoftware)
			}
			if gotVersion != tc.wantVersion {
				t.Errorf("version: got %q, want %q", gotVersion, tc.wantVersion)
			}
		})
	}
}

// TestParseIRCResponse_Error_KLined tests that ERROR responses return nil (not IRC to report).
func TestParseIRCResponse_Error_KLined(t *testing.T) {
	response := "ERROR :Closing Link: nervaprobe[1.2.3.4] (K-lined)\r\n"
	result := parseIRCResponse(response)
	if result != nil {
		t.Errorf("expected nil for ERROR response (K-lined), got %+v", result)
	}
}

// TestParseIRCResponse_Error_ServerFull tests that ERROR :Server full returns nil.
func TestParseIRCResponse_Error_ServerFull(t *testing.T) {
	response := "ERROR :Server full. Please try again later.\r\n"
	result := parseIRCResponse(response)
	if result != nil {
		t.Errorf("expected nil for ERROR response (server full), got %+v", result)
	}
}

// TestParseIRCResponse_IncompleteWelcome tests that a partial welcome (only 001) is still detected.
func TestParseIRCResponse_IncompleteWelcome(t *testing.T) {
	response := ":irc.example.com 001 nervaprobe :Welcome to the TestNet Internet Relay Chat Network nervaprobe\r\n"
	result := parseIRCResponse(response)
	if result == nil {
		t.Fatal("expected non-nil result for response with only 001")
	}
	if result.serverName != "irc.example.com" {
		t.Errorf("serverName: got %q, want %q", result.serverName, "irc.example.com")
	}
	if result.networkName != "TestNet" {
		t.Errorf("networkName: got %q, want %q", result.networkName, "TestNet")
	}
}

// TestParseIRCResponse_NonIRC tests that non-IRC responses return nil.
func TestParseIRCResponse_NonIRC(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
	result := parseIRCResponse(response)
	if result != nil {
		t.Errorf("expected nil for HTTP response, got %+v", result)
	}
}

// TestParseIRCResponse_Empty tests that an empty response returns nil.
func TestParseIRCResponse_Empty(t *testing.T) {
	result := parseIRCResponse("")
	if result != nil {
		t.Errorf("expected nil for empty response, got %+v", result)
	}
}

// TestParseIRCResponse_LuserClient tests user count extraction from RPL_LUSERCLIENT.
func TestParseIRCResponse_LuserClient(t *testing.T) {
	response := buildWelcome([]string{
		":irc.srv 001 nervaprobe :Welcome to the Net Network nervaprobe\r",
		":irc.srv 251 nervaprobe :There are 1234 users and 56 services on 7 servers\r",
	})

	result := parseIRCResponse(response)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.userCount != 1234 {
		t.Errorf("userCount: got %d, want 1234", result.userCount)
	}
}

// TestParseIRCResponse_LuserChannels tests channel count extraction from RPL_LUSERCHANNELS (254).
func TestParseIRCResponse_LuserChannels(t *testing.T) {
	response := buildWelcome([]string{
		":irc.srv 001 nervaprobe :Welcome to the Net Network nervaprobe\r",
		":irc.srv 254 nervaprobe 42 :channels formed\r",
	})

	result := parseIRCResponse(response)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.channelCount != 42 {
		t.Errorf("channelCount: got %d, want 42", result.channelCount)
	}
}

// TestGenerateCPE_KnownDaemon tests CPE generation for a known daemon (UnrealIRCd).
func TestGenerateCPE_KnownDaemon(t *testing.T) {
	cpes := generateCPE("UnrealIRCd", "6.1.3")
	if len(cpes) != 1 {
		t.Fatalf("expected 1 CPE, got %d: %v", len(cpes), cpes)
	}
	want := "cpe:2.3:a:unrealircd:unrealircd:6.1.3:*:*:*:*:*:*:*"
	if cpes[0] != want {
		t.Errorf("CPE: got %q, want %q", cpes[0], want)
	}
}

// TestGenerateCPE_UnknownDaemon tests CPE generation for an unknown IRC daemon.
func TestGenerateCPE_UnknownDaemon(t *testing.T) {
	cpes := generateCPE("SomeUnknownIRCd", "1.2.3")
	if len(cpes) != 1 {
		t.Fatalf("expected 1 CPE, got %d: %v", len(cpes), cpes)
	}
	// Unknown daemons use normalized name as vendor+product; version is used as-is
	if !strings.HasPrefix(cpes[0], "cpe:2.3:a:") {
		t.Errorf("CPE should start with cpe:2.3:a:, got %q", cpes[0])
	}
	// Version should appear in CPE (as-is, not normalized)
	if !strings.Contains(cpes[0], "1.2.3") {
		t.Errorf("CPE should contain version '1.2.3', got %q", cpes[0])
	}
}

// TestGenerateCPE_Empty tests CPE generation with no server software returns nil.
func TestGenerateCPE_Empty(t *testing.T) {
	cpes := generateCPE("", "")
	if cpes != nil {
		t.Errorf("expected nil CPEs for empty software, got %v", cpes)
	}
}

// TestNormalizeCPE tests CPE string normalization.
func TestNormalizeCPE(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"UnrealIRCd", "unrealircd"},
		{"InspIRCd-4.0.1", "inspircd_4_0_1"},
		{"ircd hybrid", "ircd_hybrid"},
		{"ngIRCd-27", "ngircd_27"},
		{"charybdis", "charybdis"},
		{"6.1.3", "6_1_3"},
		{"", "*"},
		{"---", "*"},
		// trimmed != result: leading/trailing underscores should be removed
		{"-foo-", "foo"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := normalizeCPE(tc.input)
			if got != tc.want {
				t.Errorf("normalizeCPE(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestTCPPlugin_Interface verifies TCPPlugin metadata methods.
func TestTCPPlugin_Interface(t *testing.T) {
	p := &TCPPlugin{}

	if p.Name() != plugins.ProtoIRC {
		t.Errorf("Name(): got %q, want %q", p.Name(), plugins.ProtoIRC)
	}
	if p.Type() != plugins.TCP {
		t.Errorf("Type(): got %v, want %v", p.Type(), plugins.TCP)
	}
	if p.Priority() != ircPriority {
		t.Errorf("Priority(): got %d, want %d", p.Priority(), ircPriority)
	}

	portTests := []struct {
		port uint16
		want bool
	}{
		{6667, true},
		{6660, true},
		{6669, true},
		{7000, true},
		{6697, false},
		{80, false},
		{443, false},
	}
	for _, tc := range portTests {
		got := p.PortPriority(tc.port)
		if got != tc.want {
			t.Errorf("PortPriority(%d): got %v, want %v", tc.port, got, tc.want)
		}
	}
}

// TestTLSPlugin_Interface verifies TLSPlugin metadata methods.
func TestTLSPlugin_Interface(t *testing.T) {
	p := &TLSPlugin{}

	if p.Name() != plugins.ProtoIRCS {
		t.Errorf("Name(): got %q, want %q", p.Name(), plugins.ProtoIRCS)
	}
	if p.Type() != plugins.TCPTLS {
		t.Errorf("Type(): got %v, want %v", p.Type(), plugins.TCPTLS)
	}
	if p.Priority() != ircPriority+1 {
		t.Errorf("Priority(): got %d, want %d", p.Priority(), ircPriority+1)
	}

	portTests := []struct {
		port uint16
		want bool
	}{
		{6697, true},
		{6667, false},
		{443, false},
		{80, false},
	}
	for _, tc := range portTests {
		got := p.PortPriority(tc.port)
		if got != tc.want {
			t.Errorf("PortPriority(%d): got %v, want %v", tc.port, got, tc.want)
		}
	}
}

// TestTCPPlugin_Run verifies TCPPlugin.Run() against a simulated IRC server.
func TestTCPPlugin_Run(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Simulate IRC server: read NICK+USER, respond with welcome burst.
	go func() {
		buf := make([]byte, 4096)
		n, _ := server.Read(buf)
		if n == 0 {
			return
		}
		data := string(buf[:n])
		if !strings.Contains(data, "NICK") || !strings.Contains(data, "USER") {
			return
		}

		welcome := ":irc.test.com 001 nervaprobe :Welcome to the TestNet Internet Relay Chat Network nervaprobe\r\n" +
			":irc.test.com 002 nervaprobe :Your host is irc.test.com, running version InspIRCd-4.0.1\r\n" +
			":irc.test.com 003 nervaprobe :This server was created 2024-01-01\r\n" +
			":irc.test.com 004 nervaprobe irc.test.com InspIRCd-4.0.1 iosw bklosu\r\n" +
			":irc.test.com 251 nervaprobe :There are 10 users and 0 services on 1 servers\r\n" +
			":irc.test.com 254 nervaprobe 5 :channels formed\r\n"
		server.Write([]byte(welcome))

		// Drain any remaining reads (QUIT, second read attempt).
		server.Read(buf)
	}()

	p := &TCPPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:6667"),
		Host:    "127.0.0.1",
	}

	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service")
	}
	if svc.Protocol != plugins.ProtoIRC {
		t.Errorf("Protocol: got %q, want %q", svc.Protocol, plugins.ProtoIRC)
	}
	if svc.TLS {
		t.Errorf("TLS: got true, want false")
	}
	if svc.Version != "4.0.1" {
		t.Errorf("Version: got %q, want %q", svc.Version, "4.0.1")
	}

	meta, ok := svc.Metadata().(plugins.ServiceIRC)
	if !ok {
		t.Fatalf("Metadata type: got %T, want plugins.ServiceIRC", svc.Metadata())
	}
	if meta.ServerName != "irc.test.com" {
		t.Errorf("ServerName: got %q, want %q", meta.ServerName, "irc.test.com")
	}
	if meta.NetworkName != "TestNet" {
		t.Errorf("NetworkName: got %q, want %q", meta.NetworkName, "TestNet")
	}
	if meta.Version != "4.0.1" {
		t.Errorf("meta.Version: got %q, want %q", meta.Version, "4.0.1")
	}
	if meta.ServerSoftware != "InspIRCd" {
		t.Errorf("ServerSoftware: got %q, want %q", meta.ServerSoftware, "InspIRCd")
	}
	if meta.UserCount != 10 {
		t.Errorf("UserCount: got %d, want 10", meta.UserCount)
	}
	if meta.ChannelCount != 5 {
		t.Errorf("ChannelCount: got %d, want 5", meta.ChannelCount)
	}
}

// TestTLSPlugin_Run_Protocol verifies that TLSPlugin.Run() produces a service
// with the ProtoIRCS protocol and the TLS flag set.
func TestTLSPlugin_Run_Protocol(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		n, _ := server.Read(buf)
		if n == 0 {
			return
		}
		welcome := ":ircs.test.com 001 nervaprobe :Welcome to the SecureNet Internet Relay Chat Network nervaprobe\r\n" +
			":ircs.test.com 002 nervaprobe :Your host is ircs.test.com, running version UnrealIRCd-6.1.3\r\n" +
			":ircs.test.com 251 nervaprobe :There are 5 users and 0 services on 1 servers\r\n"
		server.Write([]byte(welcome))
		server.Read(buf)
	}()

	p := &TLSPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:6697"),
		Host:    "127.0.0.1",
	}

	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service")
	}
	if svc.Protocol != plugins.ProtoIRCS {
		t.Errorf("Protocol: got %q, want %q", svc.Protocol, plugins.ProtoIRCS)
	}
	if !svc.TLS {
		t.Errorf("TLS: got false, want true")
	}

	if _, ok := svc.Metadata().(plugins.ServiceIRCS); !ok {
		t.Errorf("Metadata type: got %T, want plugins.ServiceIRCS", svc.Metadata())
	}
}

// buildIRCMockServer returns a net.Pipe pair and starts a goroutine that simulates a
// minimal IRC welcome burst. The goroutine reads NICK+USER, writes the burst, then
// drains subsequent reads so the plugin can finish gracefully.
func buildIRCMockServer(t *testing.T) (server net.Conn, client net.Conn) {
	t.Helper()
	server, client = net.Pipe()
	go func() {
		buf := make([]byte, 4096)
		n, _ := server.Read(buf)
		if n == 0 {
			return
		}
		welcome := ":irc.test.com 001 nervaprobe :Welcome to the TestNet Internet Relay Chat Network nervaprobe\r\n" +
			":irc.test.com 002 nervaprobe :Your host is irc.test.com, running version InspIRCd-4.0.1\r\n" +
			":irc.test.com 003 nervaprobe :This server was created 2024-01-01\r\n" +
			":irc.test.com 004 nervaprobe irc.test.com InspIRCd-4.0.1 iosw bklosu\r\n" +
			":irc.test.com 251 nervaprobe :There are 10 users and 0 services on 1 servers\r\n"
		server.Write([]byte(welcome))
		server.Read(buf)
	}()
	return server, client
}

// TestIRCSecurityFindings verifies that the irc-unauthenticated finding is emitted and
// AnonymousAccess is set when Misconfigs=true.
func TestIRCSecurityFindings(t *testing.T) {
	server, client := buildIRCMockServer(t)
	defer server.Close()
	defer client.Close()

	p := &TCPPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:6667"),
		Host:       "127.0.0.1",
		Misconfigs: true,
	}

	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service")
	}

	if !svc.AnonymousAccess {
		t.Errorf("AnonymousAccess: got false, want true")
	}
	if len(svc.SecurityFindings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(svc.SecurityFindings))
	}
	if svc.SecurityFindings[0].ID != "irc-unauthenticated" {
		t.Errorf("expected finding ID 'irc-unauthenticated', got %q", svc.SecurityFindings[0].ID)
	}
	if svc.SecurityFindings[0].Severity != plugins.SeverityLow {
		t.Errorf("expected severity low, got %s", svc.SecurityFindings[0].Severity)
	}
}

// TestIRCSecurityFindingsDisabled verifies that no findings are emitted and AnonymousAccess
// is false when Misconfigs=false.
func TestIRCSecurityFindingsDisabled(t *testing.T) {
	server, client := buildIRCMockServer(t)
	defer server.Close()
	defer client.Close()

	p := &TCPPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:6667"),
		Host:       "127.0.0.1",
		Misconfigs: false,
	}

	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service")
	}

	if svc.AnonymousAccess {
		t.Errorf("AnonymousAccess: got true, want false")
	}
	if len(svc.SecurityFindings) != 0 {
		t.Errorf("expected no findings when Misconfigs=false, got %d", len(svc.SecurityFindings))
	}
}

// TestIRCTLSSecurityFindings verifies that the irc-unauthenticated finding is emitted and
// AnonymousAccess is set when Misconfigs=true for the TLS plugin.
func TestIRCTLSSecurityFindings(t *testing.T) {
	server, client := buildIRCMockServer(t)
	defer server.Close()
	defer client.Close()

	p := &TLSPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:6697"),
		Host:       "127.0.0.1",
		Misconfigs: true,
	}

	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service")
	}

	if !svc.AnonymousAccess {
		t.Errorf("AnonymousAccess: got false, want true")
	}
	if len(svc.SecurityFindings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(svc.SecurityFindings))
	}
	if svc.SecurityFindings[0].ID != "irc-unauthenticated" {
		t.Errorf("expected finding ID 'irc-unauthenticated', got %q", svc.SecurityFindings[0].ID)
	}
	if svc.SecurityFindings[0].Severity != plugins.SeverityLow {
		t.Errorf("expected severity low, got %s", svc.SecurityFindings[0].Severity)
	}
}

// TestIRCTLSSecurityFindingsDisabled verifies that no findings are emitted and AnonymousAccess
// is false when Misconfigs=false for the TLS plugin.
func TestIRCTLSSecurityFindingsDisabled(t *testing.T) {
	server, client := buildIRCMockServer(t)
	defer server.Close()
	defer client.Close()

	p := &TLSPlugin{}
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:6697"),
		Host:       "127.0.0.1",
		Misconfigs: false,
	}

	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned error: %v", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service")
	}

	if svc.AnonymousAccess {
		t.Errorf("AnonymousAccess: got true, want false")
	}
	if len(svc.SecurityFindings) != 0 {
		t.Errorf("expected no findings when Misconfigs=false, got %d", len(svc.SecurityFindings))
	}
}

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

package mgcp

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// --- Response Pattern Tests ---

func TestResponsePattern_SuccessWithOK(t *testing.T) {
	if !responsePattern.MatchString("200 9 OK") {
		t.Error("expected '200 9 OK' to match responsePattern")
	}
}

func TestResponsePattern_SuccessBare(t *testing.T) {
	if !responsePattern.MatchString("200 9") {
		t.Error("expected '200 9' to match responsePattern")
	}
}

func TestResponsePattern_ErrorCode(t *testing.T) {
	if !responsePattern.MatchString("500 9") {
		t.Error("expected '500 9' to match responsePattern")
	}
}

func TestResponsePattern_WrongTransactionID(t *testing.T) {
	if responsePattern.MatchString("200 42 OK") {
		t.Error("expected '200 42 OK' to NOT match responsePattern")
	}
}

func TestResponsePattern_NonMGCP(t *testing.T) {
	if responsePattern.MatchString("HTTP/1.1 200 OK") {
		t.Error("expected 'HTTP/1.1 200 OK' to NOT match responsePattern")
	}
}

func TestResponsePattern_InvalidFormat(t *testing.T) {
	if responsePattern.MatchString("MGCP 1.0") {
		t.Error("expected 'MGCP 1.0' to NOT match responsePattern")
	}
}

// --- Plugin.Run Integration Tests ---

func TestPlugin_Run_SuccessWithOK(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf) // consume probe
		server.Write([]byte("200 9 OK\r\n\r\n"))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2427"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	if svc.Protocol != "mgcp" {
		t.Errorf("expected protocol 'mgcp', got '%s'", svc.Protocol)
	}
	var meta plugins.ServiceMGCP
	if err := json.Unmarshal(svc.Raw, &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}
	if meta.ResponseCode != 200 {
		t.Errorf("expected response code 200, got %d", meta.ResponseCode)
	}
}

func TestPlugin_Run_ErrorEndpointUnknown(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte("500 9\r\n\r\n"))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2427"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service for 500 response (MGCP detected)")
	}
	var meta plugins.ServiceMGCP
	if err := json.Unmarshal(svc.Raw, &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}
	if meta.ResponseCode != 500 {
		t.Errorf("expected response code 500, got %d", meta.ResponseCode)
	}
}

func TestPlugin_Run_WithEndpoints(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte("200 9 OK\r\nZ: aaln/1@gw.example.com\r\nZ: aaln/2@gw.example.com\r\n\r\n"))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2427"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	var meta plugins.ServiceMGCP
	if err := json.Unmarshal(svc.Raw, &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}
	if len(meta.Endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(meta.Endpoints))
	}
	if meta.Endpoints[0] != "aaln/1@gw.example.com" {
		t.Errorf("expected endpoint[0] = 'aaln/1@gw.example.com', got '%s'", meta.Endpoints[0])
	}
	if meta.Endpoints[1] != "aaln/2@gw.example.com" {
		t.Errorf("expected endpoint[1] = 'aaln/2@gw.example.com', got '%s'", meta.Endpoints[1])
	}
}

func TestPlugin_Run_WithCapabilities(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte("200 9\r\nL: p:10-20, a:PCMU;PCMA, b:64, v:T;G;D;L\r\n\r\n"))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2427"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	var meta plugins.ServiceMGCP
	if err := json.Unmarshal(svc.Raw, &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}
	expectedPackages := []string{"T", "G", "D", "L"}
	if len(meta.Packages) != len(expectedPackages) {
		t.Fatalf("expected %d packages, got %d: %v", len(expectedPackages), len(meta.Packages), meta.Packages)
	}
	for i, pkg := range expectedPackages {
		if meta.Packages[i] != pkg {
			t.Errorf("expected package[%d] = '%s', got '%s'", i, pkg, meta.Packages[i])
		}
	}
}

func TestPlugin_Run_CiscoIOS(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	ciscoResponse := "200 9 OK\r\n" +
		"I: 0\r\n" +
		"X: 1234567890\r\n" +
		"L: a:PCMU;PCMA;G729, p:10-200, e:on, s:off, v:T;G;D;L;H;R;ATM;SST;PRE, m:sendrecv\r\n" +
		"\r\n"

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte(ciscoResponse))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2427"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service for Cisco IOS MGCP response")
	}
	var meta plugins.ServiceMGCP
	if err := json.Unmarshal(svc.Raw, &meta); err != nil {
		t.Fatalf("failed to unmarshal metadata: %v", err)
	}
	if meta.ResponseCode != 200 {
		t.Errorf("expected response code 200, got %d", meta.ResponseCode)
	}
	expectedPackages := []string{"T", "G", "D", "L", "H", "R", "ATM", "SST", "PRE"}
	if len(meta.Packages) != len(expectedPackages) {
		t.Fatalf("expected %d packages, got %d: %v", len(expectedPackages), len(meta.Packages), meta.Packages)
	}
	for i, pkg := range expectedPackages {
		if meta.Packages[i] != pkg {
			t.Errorf("expected package[%d] = '%s', got '%s'", i, pkg, meta.Packages[i])
		}
	}
}

func TestPlugin_Run_EmptyResponse(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Close() // close without sending
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2427"),
	}
	svc, _ := p.Run(client, 2*time.Second, target)
	if svc != nil {
		t.Error("expected nil service for empty response")
	}
}

func TestPlugin_Run_NonMGCPResponse(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2427"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc != nil {
		t.Error("expected nil service for non-MGCP response")
	}
}

func TestPlugin_Run_WrongTransactionID(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte("200 42 OK\r\n\r\n"))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2427"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc != nil {
		t.Error("expected nil service for wrong transaction ID")
	}
}

// --- Plugin Method Tests ---

func TestPlugin_PortPriority(t *testing.T) {
	p := &Plugin{}
	tests := []struct {
		port     uint16
		expected bool
	}{
		{2427, true},
		{2727, true},
		{80, false},
		{0, false},
	}
	for _, tt := range tests {
		result := p.PortPriority(tt.port)
		if result != tt.expected {
			t.Errorf("PortPriority(%d) = %v, want %v", tt.port, result, tt.expected)
		}
	}
}

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	if p.Name() != "mgcp" {
		t.Errorf("Name() = %s, want 'mgcp'", p.Name())
	}
}

func TestPlugin_Type(t *testing.T) {
	p := &Plugin{}
	if p.Type() != plugins.UDP {
		t.Errorf("Type() = %v, want plugins.UDP", p.Type())
	}
}

func TestPlugin_Priority(t *testing.T) {
	p := &Plugin{}
	if p.Priority() != 90 {
		t.Errorf("Priority() = %d, want 90", p.Priority())
	}
}

// --- Probe Tests ---

func TestBuildProbe(t *testing.T) {
	if !bytes.Contains(probe, []byte("AUEP")) {
		t.Error("probe does not contain 'AUEP'")
	}
	if !bytes.Contains(probe, []byte("MGCP 1.0")) {
		t.Error("probe does not contain 'MGCP 1.0'")
	}
	if !bytes.HasSuffix(probe, []byte("\r\n\r\n")) {
		t.Error("probe does not end with '\\r\\n\\r\\n'")
	}
}

// --- Regex Boundary Tests ---

// Transaction ID boundaries - "9" must be exactly "9", not "90", "99", "19", etc.
func TestResponsePattern_TransactionID90(t *testing.T) {
	if responsePattern.MatchString("200 90 OK") {
		t.Error("'200 90 OK' should NOT match - transaction ID is 90, not 9")
	}
}

func TestResponsePattern_TransactionID99(t *testing.T) {
	if responsePattern.MatchString("200 99 OK") {
		t.Error("'200 99 OK' should NOT match - transaction ID is 99, not 9")
	}
}

func TestResponsePattern_TransactionID19(t *testing.T) {
	if responsePattern.MatchString("200 19 OK") {
		t.Error("'200 19 OK' should NOT match - transaction ID is 19, not 9")
	}
}

func TestResponsePattern_TransactionID9WithLongCommentary(t *testing.T) {
	if !responsePattern.MatchString("200 9 Connection was deleted successfully") {
		t.Error("'200 9 Connection was deleted...' should match - txid 9 with long commentary")
	}
}

func TestResponsePattern_ResponseCode100(t *testing.T) {
	if !responsePattern.MatchString("100 9") {
		t.Error("'100 9' should match - provisional response")
	}
}

func TestResponsePattern_ResponseCode999(t *testing.T) {
	if !responsePattern.MatchString("999 9") {
		t.Error("'999 9' should match - any 3-digit code is valid")
	}
}

func TestResponsePattern_FourDigitCode(t *testing.T) {
	if responsePattern.MatchString("2000 9 OK") {
		t.Error("'2000 9 OK' should NOT match - code must be exactly 3 digits")
	}
}

func TestResponsePattern_TwoDigitCode(t *testing.T) {
	if responsePattern.MatchString("20 9 OK") {
		t.Error("'20 9 OK' should NOT match - code must be exactly 3 digits")
	}
}

// --- False Positive Prevention Tests (via Run) ---

func TestPlugin_Run_SIPResponse(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.1\r\n\r\n"))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:5060"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc != nil {
		t.Error("SIP response should NOT be detected as MGCP")
	}
}

func TestPlugin_Run_MEGACOResponse(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte("MEGACO/1 [10.0.0.1]\nReply = 1 {}\n"))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2944"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc != nil {
		t.Error("MEGACO response should NOT be detected as MGCP")
	}
}

func TestPlugin_Run_DNSResponse(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// DNS responses are binary
	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte{0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01})
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:53"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc != nil {
		t.Error("binary DNS response should NOT be detected as MGCP")
	}
}

// --- Header Parsing Edge Cases (via Run) ---

func TestPlugin_Run_LLineWithNoVParam(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte("200 9\r\nL: p:10-20, a:PCMU;PCMA, b:64\r\n\r\n"))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2427"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	var meta plugins.ServiceMGCP
	if err := json.Unmarshal(svc.Raw, &meta); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(meta.Packages) != 0 {
		t.Errorf("expected 0 packages when L: has no v: param, got %d: %v", len(meta.Packages), meta.Packages)
	}
}

func TestPlugin_Run_MultipleLLines(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Two L: lines with different v: values - second should overwrite first
	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte("200 9\r\nL: p:10-20, v:T;G;D\r\nL: p:10-220, v:L;H;R\r\n\r\n"))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2427"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	var meta plugins.ServiceMGCP
	if err := json.Unmarshal(svc.Raw, &meta); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	// Second L: line should overwrite packages
	if len(meta.Packages) != 3 {
		t.Fatalf("expected 3 packages from second L: line, got %d: %v", len(meta.Packages), meta.Packages)
	}
	expectedPackages := []string{"L", "H", "R"}
	for i, pkg := range expectedPackages {
		if meta.Packages[i] != pkg {
			t.Errorf("expected package[%d] = '%s', got '%s'", i, pkg, meta.Packages[i])
		}
	}
}

func TestPlugin_Run_EmptyZLine(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Z: with empty value should be skipped
	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte("200 9 OK\r\nZ: \r\nZ: aaln/1@gw\r\n\r\n"))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2427"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	var meta plugins.ServiceMGCP
	if err := json.Unmarshal(svc.Raw, &meta); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(meta.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint (empty Z: skipped), got %d: %v", len(meta.Endpoints), meta.Endpoints)
	}
	if meta.Endpoints[0] != "aaln/1@gw" {
		t.Errorf("expected 'aaln/1@gw', got '%s'", meta.Endpoints[0])
	}
}

func TestPlugin_Run_InterleavedHeaders(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Z: and L: headers interleaved (not grouped)
	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte("200 9 OK\r\nZ: aaln/1@gw\r\nL: v:T;G\r\nZ: aaln/2@gw\r\n\r\n"))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2427"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	var meta plugins.ServiceMGCP
	if err := json.Unmarshal(svc.Raw, &meta); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(meta.Endpoints) != 2 {
		t.Errorf("expected 2 endpoints from interleaved Z: lines, got %d", len(meta.Endpoints))
	}
	if len(meta.Packages) != 2 {
		t.Errorf("expected 2 packages from interleaved L: line, got %d", len(meta.Packages))
	}
}

// --- Service Output Field Tests ---

func TestPlugin_Run_ServiceOutputFields(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte("200 9 OK\r\n\r\n"))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "mgcp-gw.example.com",
		Address: netip.MustParseAddrPort("192.168.1.100:2427"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	if svc.Protocol != "mgcp" {
		t.Errorf("Protocol = %s, want 'mgcp'", svc.Protocol)
	}
	if svc.Transport != "udp" {
		t.Errorf("Transport = %s, want 'udp'", svc.Transport)
	}
	if svc.Port != 2427 {
		t.Errorf("Port = %d, want 2427", svc.Port)
	}
	if svc.IP != "192.168.1.100" {
		t.Errorf("IP = %s, want '192.168.1.100'", svc.IP)
	}
	if svc.Host != "mgcp-gw.example.com" {
		t.Errorf("Host = %s, want 'mgcp-gw.example.com'", svc.Host)
	}
	if svc.TLS {
		t.Error("TLS should be false for MGCP")
	}
	if svc.Version != "" {
		t.Errorf("Version should be empty, got '%s'", svc.Version)
	}
}

// --- Malformed Response Edge Cases ---

func TestPlugin_Run_BareNewlines(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Response with only LF instead of CRLF — malformed line endings
	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte("200 9 OK\nZ: aaln/1@gw\n\n"))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2427"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// With bare LF, strings.Split on "\r\n" won't split properly,
	// so the entire response is one "line". The regex should still
	// match if the first segment contains "200 9 OK" followed by
	// LF characters. Since regex $ matches end of string and the
	// unsplit line would be "200 9 OK\nZ: aaln/1@gw\n\n",
	// $ won't match after "OK" — so this should NOT detect.
	if svc != nil {
		t.Error("bare LF response should not be detected (non-conformant CRLF)")
	}
}

func TestPlugin_Run_OnlyResponseLine(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Just the response line, no headers, no trailing CRLF pair
	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte("200 9"))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2427"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// "200 9" with no CRLF - Split on "\r\n" gives one element ["200 9"]
	// TrimSpace → "200 9" → regex matches → should detect
	if svc == nil {
		t.Fatal("expected non-nil service for minimal '200 9' response")
	}
	var meta plugins.ServiceMGCP
	if err := json.Unmarshal(svc.Raw, &meta); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if meta.ResponseCode != 200 {
		t.Errorf("expected code 200, got %d", meta.ResponseCode)
	}
}

func TestPlugin_Run_ResponseWithMGCPCommand(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// An MGCP command (not a response) - should NOT be detected
	// Commands start with a verb, not a 3-digit code
	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte("RSIP 39380951 * MGCP 1.0\r\nRM: restart\r\n\r\n"))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2427"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc != nil {
		t.Error("MGCP command (RSIP) should NOT be detected as response")
	}
}

func TestPlugin_Run_ManyEndpoints(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Response with many endpoints (stress test header parsing)
	var response strings.Builder
	response.WriteString("200 9 OK\r\n")
	for i := 0; i < 50; i++ {
		response.WriteString("Z: aaln/" + strconv.Itoa(i) + "@gw.example.com\r\n")
	}
	response.WriteString("\r\n")

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte(response.String()))
		server.Close()
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2427"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	var meta plugins.ServiceMGCP
	if err := json.Unmarshal(svc.Raw, &meta); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(meta.Endpoints) != 50 {
		t.Errorf("expected 50 endpoints, got %d", len(meta.Endpoints))
	}
}

// --- Additional Probe Tests ---

func TestProbeContainsTransactionID(t *testing.T) {
	if !bytes.Contains(probe, []byte(" 9 ")) {
		t.Error("probe should contain transaction ID ' 9 '")
	}
}

func TestProbeContainsWildcard(t *testing.T) {
	if !bytes.Contains(probe, []byte("* MGCP")) {
		t.Error("probe should contain wildcard endpoint '* MGCP'")
	}
}

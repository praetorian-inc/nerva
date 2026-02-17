package megaco

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestParseMegacoResponse_PrettyFormat(t *testing.T) {
	response := []byte("MEGACO/1 [10.0.0.1]\nReply = 1 {\n  Context = - {\n    ServiceChange = ROOT {\n      Services {\n        Profile = ResGW/1\n      }\n    }\n  }\n}\n")
	result := parseMegacoResponse(response)
	if result == nil {
		t.Fatal("expected non-nil result for pretty MEGACO response")
	}
	if result.Version != "1" {
		t.Errorf("expected version '1', got '%s'", result.Version)
	}
	if result.MID != "10.0.0.1" {
		t.Errorf("expected MID '10.0.0.1', got '%s'", result.MID)
	}
	if result.Profile != "ResGW/1" {
		t.Errorf("expected profile 'ResGW/1', got '%s'", result.Profile)
	}
	if result.ErrorCode != 0 {
		t.Errorf("expected error code 0, got %d", result.ErrorCode)
	}
}

func TestParseMegacoResponse_CompactFormat(t *testing.T) {
	response := []byte("!/1 [mgc.example.com] P=1{C=-{SC=ROOT{SV{PF=ResGW/1}}}}")
	result := parseMegacoResponse(response)
	if result == nil {
		t.Fatal("expected non-nil result for compact MEGACO response")
	}
	if result.Version != "1" {
		t.Errorf("expected version '1', got '%s'", result.Version)
	}
	if result.MID != "mgc.example.com" {
		t.Errorf("expected MID 'mgc.example.com', got '%s'", result.MID)
	}
	if result.Profile != "ResGW/1" {
		t.Errorf("expected profile 'ResGW/1', got '%s'", result.Profile)
	}
}

func TestParseMegacoResponse_ErrorResponse(t *testing.T) {
	response := []byte("MEGACO/1 [10.0.0.1]\nReply = 1 {\n  Context = - {\n    Error = 504 {\n      \"Command Received From Unauthorized Entity\"\n    }\n  }\n}\n")
	result := parseMegacoResponse(response)
	if result == nil {
		t.Fatal("expected non-nil result for MEGACO error response")
	}
	if result.Version != "1" {
		t.Errorf("expected version '1', got '%s'", result.Version)
	}
	if result.ErrorCode != 504 {
		t.Errorf("expected error code 504, got %d", result.ErrorCode)
	}
}

func TestParseMegacoResponse_CompactError(t *testing.T) {
	response := []byte("!/1 [10.0.0.1] P=1{C=-{ER=402{\"Unauthorized\"}}}")
	result := parseMegacoResponse(response)
	if result == nil {
		t.Fatal("expected non-nil result for compact MEGACO error response")
	}
	if result.Version != "1" {
		t.Errorf("expected version '1', got '%s'", result.Version)
	}
	if result.ErrorCode != 402 {
		t.Errorf("expected error code 402, got %d", result.ErrorCode)
	}
}

func TestParseMegacoResponse_EmptyResponse(t *testing.T) {
	result := parseMegacoResponse([]byte{})
	if result != nil {
		t.Error("expected nil result for empty response")
	}
}

func TestParseMegacoResponse_NonMegaco(t *testing.T) {
	result := parseMegacoResponse([]byte("HTTP/1.1 200 OK\r\n"))
	if result != nil {
		t.Error("expected nil result for non-MEGACO response")
	}
}

func TestParseMegacoResponse_WhitespaceOnly(t *testing.T) {
	result := parseMegacoResponse([]byte("   \n\t  "))
	if result != nil {
		t.Error("expected nil result for whitespace-only response")
	}
}

func TestParseMegacoResponse_Version2(t *testing.T) {
	response := []byte("MEGACO/2 [10.0.0.1]\nReply = 1 {\n  Context = - {\n    ServiceChange = ROOT {}\n  }\n}\n")
	result := parseMegacoResponse(response)
	if result == nil {
		t.Fatal("expected non-nil result for MEGACO v2 response")
	}
	if result.Version != "2" {
		t.Errorf("expected version '2', got '%s'", result.Version)
	}
}

func TestParseMegacoResponse_CaseInsensitive(t *testing.T) {
	response := []byte("megaco/1 [10.0.0.1]\nReply = 1 {}")
	result := parseMegacoResponse(response)
	if result == nil {
		t.Fatal("expected non-nil result for lowercase megaco response")
	}
	if result.Version != "1" {
		t.Errorf("expected version '1', got '%s'", result.Version)
	}
}

func TestBuildProbe(t *testing.T) {
	if len(probeMessage) == 0 {
		t.Error("probe message should not be empty")
	}
	if !bytes.Contains(probeMessage, []byte("MEGACO/1")) {
		t.Error("probe should contain MEGACO/1 header")
	}
	if !bytes.Contains(probeMessage, []byte("ServiceChange")) {
		t.Error("probe should contain ServiceChange command")
	}
	if !bytes.Contains(probeMessage, []byte("Method = Restart")) {
		t.Error("probe should contain Method = Restart")
	}
}

func TestPlugin_PortPriority(t *testing.T) {
	p := &Plugin{}
	if !p.PortPriority(2944) {
		t.Error("expected true for port 2944")
	}
	if !p.PortPriority(2945) {
		t.Error("expected true for port 2945")
	}
	if p.PortPriority(80) {
		t.Error("expected false for port 80")
	}
	if p.PortPriority(0) {
		t.Error("expected false for port 0")
	}
}

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	if p.Name() != "megaco" {
		t.Errorf("expected 'megaco', got '%s'", p.Name())
	}
}

func TestPlugin_Type(t *testing.T) {
	p := &Plugin{}
	if p.Type() != plugins.UDP {
		t.Errorf("expected UDP, got %v", p.Type())
	}
}

func TestPlugin_Priority(t *testing.T) {
	p := &Plugin{}
	if p.Priority() != 90 {
		t.Errorf("expected 90, got %d", p.Priority())
	}
}

func TestParseMegacoResponse_BinaryGarbage(t *testing.T) {
	result := parseMegacoResponse([]byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0x80})
	if result != nil {
		t.Error("expected nil result for binary garbage")
	}
}

func TestPlugin_Run_ValidResponse(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf) // consume probe
		server.Write([]byte("MEGACO/1 [10.0.0.1]\nReply = 1 {\n  Context = - {\n    ServiceChange = ROOT {}\n  }\n}\n"))
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
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestPlugin_Run_EmptyResponse(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf) // consume probe
		server.Close()    // close without sending data
	}()

	p := &Plugin{}
	target := plugins.Target{
		Host:    "10.0.0.1",
		Address: netip.MustParseAddrPort("10.0.0.1:2944"),
	}
	svc, err := p.Run(client, 2*time.Second, target)
	// SendRecv returns an error on EOF, which is expected when server closes without sending data
	if err == nil {
		t.Fatal("expected error for empty response with closed connection")
	}
	if svc != nil {
		t.Error("expected nil service for empty response")
	}
}

func TestPlugin_Run_NonMegacoResponse(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf) // consume probe
		server.Write([]byte("HTTP/1.1 200 OK\r\n"))
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
		t.Error("expected nil service for non-MEGACO response")
	}
}

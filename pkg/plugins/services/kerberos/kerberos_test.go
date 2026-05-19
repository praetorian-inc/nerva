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

package kerberos

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// mockKerberosConn is a net.Conn that replays a fixed response then times out.
type mockKerberosConn struct {
	responseData []byte
	readOffset   int
}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

func (m *mockKerberosConn) Read(b []byte) (int, error) {
	if m.readOffset >= len(m.responseData) {
		return 0, &net.OpError{Op: "read", Err: &timeoutError{}}
	}
	n := copy(b, m.responseData[m.readOffset:])
	m.readOffset += n
	return n, nil
}

func (m *mockKerberosConn) Write(b []byte) (int, error)  { return len(b), nil }
func (m *mockKerberosConn) Close() error                  { return nil }
func (m *mockKerberosConn) SetDeadline(t time.Time) error { return nil }
func (m *mockKerberosConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (m *mockKerberosConn) SetWriteDeadline(t time.Time) error { return nil }
func (m *mockKerberosConn) LocalAddr() net.Addr                { return nil }
func (m *mockKerberosConn) RemoteAddr() net.Addr               { return nil }

func TestParseDERLength(t *testing.T) {
	tests := []struct {
		name         string
		input        []byte
		wantLength   int
		wantConsumed int
	}{
		{"empty input", []byte{}, 0, 0},
		{"short form zero", []byte{0x00}, 0, 1},
		{"short form small", []byte{0x05}, 5, 1},
		{"short form max", []byte{0x7f}, 127, 1},
		{"long form one byte", []byte{0x81, 0x80}, 128, 2},
		{"long form one byte large", []byte{0x81, 0xff}, 255, 2},
		{"long form two bytes", []byte{0x82, 0x01, 0x00}, 256, 3},
		{"long form two bytes large", []byte{0x82, 0x04, 0x00}, 1024, 3},
		{"long form truncated", []byte{0x82, 0x01}, 0, 0}, // missing second length byte
		{"indefinite length", []byte{0x80}, 0, 0},         // numBytes=0, not supported
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLength, gotConsumed := parseDERLength(tt.input)
			if gotLength != tt.wantLength || gotConsumed != tt.wantConsumed {
				t.Errorf("parseDERLength(%x) = (%d, %d), want (%d, %d)",
					tt.input, gotLength, gotConsumed, tt.wantLength, tt.wantConsumed)
			}
		})
	}
}

func TestDetectKerberosResponse(t *testing.T) {
	// Test that we can validate bytes patterns correctly
	tests := []struct {
		name         string
		response     []byte // raw response including 4-byte TCP length prefix
		wantDetected bool
	}{
		{
			name: "valid KRB-ERROR response",
			// 4-byte TCP length + 0x7E (KRB-ERROR) + SEQUENCE + pvno=5 pattern
			response: append([]byte{0x00, 0x00, 0x00, 0x20, 0x7e, 0x81, 0x1d, 0x30, 0x81, 0x1a},
				append([]byte{0xa0, 0x03, 0x02, 0x01, 0x05}, // pvno=5
					append([]byte{0xa1, 0x03, 0x02, 0x01, 0x1e}, // msg-type=30
						make([]byte, 14)...)...)...),
			wantDetected: true,
		},
		{
			name: "valid AS-REP response",
			response: append([]byte{0x00, 0x00, 0x00, 0x20, 0x6b, 0x81, 0x1d, 0x30, 0x81, 0x1a},
				append([]byte{0xa0, 0x03, 0x02, 0x01, 0x05}, // pvno=5
					append([]byte{0xa1, 0x03, 0x02, 0x01, 0x0b}, // msg-type=11
						make([]byte, 14)...)...)...),
			wantDetected: true,
		},
		{
			name:         "too short response",
			response:     []byte{0x00, 0x00, 0x00, 0x02, 0x7e, 0x00},
			wantDetected: false,
		},
		{
			name: "wrong message type",
			response: append([]byte{0x00, 0x00, 0x00, 0x20, 0x60, 0x81, 0x1d, 0x30, 0x81, 0x1a},
				append([]byte{0xa0, 0x03, 0x02, 0x01, 0x05},
					make([]byte, 19)...)...),
			wantDetected: false,
		},
		{
			name: "missing pvno pattern",
			response: append([]byte{0x00, 0x00, 0x00, 0x20, 0x7e, 0x81, 0x1d, 0x30, 0x81, 0x1a},
				append([]byte{0xa0, 0x03, 0x02, 0x01, 0x04}, // pvno=4 (not Kerberos v5)
					make([]byte, 19)...)...),
			wantDetected: false,
		},
		{
			name:         "empty response",
			response:     []byte{},
			wantDetected: false,
		},
		{
			name: "HTTP response on port 88",
			response: append([]byte{0x00, 0x00, 0x00, 0x10},
				[]byte("HTTP/1.1 200 OK\r")...),
			wantDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate what detectKerberos does with the response
			detected := false
			if len(tt.response) >= 10 {
				kerberosData := tt.response[4:]
				messageType := kerberosData[0]
				if (messageType == tagKRBError || messageType == tagASREP) &&
					bytes.Contains(kerberosData, pvnoPattern) {
					detected = true
				}
			}
			if detected != tt.wantDetected {
				t.Errorf("detection for %q: got %v, want %v", tt.name, detected, tt.wantDetected)
			}
		})
	}
}

func TestParseKerberosError(t *testing.T) {
	tests := []struct {
		name          string
		response      []byte
		wantRealm     string
		wantErrorCode int
		wantErrorText string
	}{
		{
			name:          "empty response",
			response:      []byte{},
			wantRealm:     "",
			wantErrorCode: 0,
			wantErrorText: "",
		},
		{
			name:          "too short for TCP prefix",
			response:      []byte{0x00, 0x00},
			wantRealm:     "",
			wantErrorCode: 0,
			wantErrorText: "",
		},
		{
			name: "realistic KRB-ERROR with realm and error code",
			// TCP length prefix + APPLICATION 30 + SEQUENCE + fields
			response:      buildTestKRBError(6, "EXAMPLE.COM", ""),
			wantRealm:     "EXAMPLE.COM",
			wantErrorCode: 6,
			wantErrorText: "",
		},
		{
			name:          "not a KRB-ERROR (wrong tag)",
			response:      []byte{0x00, 0x00, 0x00, 0x10, 0x6b, 0x0e, 0x30, 0x0c, 0xa0, 0x03, 0x02, 0x01, 0x05, 0xa1, 0x03, 0x02, 0x01, 0x0b, 0x00, 0x00},
			wantRealm:     "",
			wantErrorCode: 0,
			wantErrorText: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			realm, errorCode, errorText := parseKerberosError(tt.response)
			if realm != tt.wantRealm {
				t.Errorf("realm: got %q, want %q", realm, tt.wantRealm)
			}
			if errorCode != tt.wantErrorCode {
				t.Errorf("errorCode: got %d, want %d", errorCode, tt.wantErrorCode)
			}
			if errorText != tt.wantErrorText {
				t.Errorf("errorText: got %q, want %q", errorText, tt.wantErrorText)
			}
		})
	}
}

// buildTestKRBError constructs a synthetic KRB-ERROR response for testing.
// It builds a valid DER-encoded KRB-ERROR with the given error code, realm, and optional e-text.
func buildTestKRBError(errorCode int, realm string, etext string) []byte {
	// Build the inner SEQUENCE fields
	var fields []byte

	// [0] pvno = 5
	fields = append(fields, 0xa0, 0x03, 0x02, 0x01, 0x05)

	// [1] msg-type = 30 (KRB-ERROR)
	fields = append(fields, 0xa1, 0x03, 0x02, 0x01, 0x1e)

	// [4] stime (GeneralizedTime "20260213000000Z")
	stime := []byte("20260213000000Z")
	fields = append(fields, 0xa4, byte(2+len(stime)), 0x18, byte(len(stime)))
	fields = append(fields, stime...)

	// [5] susec = 0
	fields = append(fields, 0xa5, 0x03, 0x02, 0x01, 0x00)

	// [6] error-code
	fields = append(fields, 0xa6, 0x03, 0x02, 0x01, byte(errorCode))

	// [9] realm
	if realm != "" {
		realmBytes := []byte(realm)
		fields = append(fields, 0xa9, byte(2+len(realmBytes)), 0x1b, byte(len(realmBytes)))
		fields = append(fields, realmBytes...)
	}

	// [10] sname (PrincipalName for krbtgt/realm) - simplified
	sname := []byte("krbtgt")
	snameSeq := []byte{0x30, byte(6 + len(sname)), 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, byte(2 + len(sname)), 0x30, byte(len(sname))}
	// This is a simplified version - real sname is more complex
	snameField := append([]byte{0xaa, byte(2 + len(snameSeq) + len(sname))}, append(snameSeq, sname...)...)
	fields = append(fields, snameField...)

	// [11] e-text (optional)
	if etext != "" {
		etextBytes := []byte(etext)
		fields = append(fields, 0xab, byte(2+len(etextBytes)), 0x1b, byte(len(etextBytes)))
		fields = append(fields, etextBytes...)
	}

	// Wrap in SEQUENCE
	seqLen := len(fields)
	var seq []byte
	seq = append(seq, 0x30)
	if seqLen < 128 {
		seq = append(seq, byte(seqLen))
	} else {
		seq = append(seq, 0x81, byte(seqLen))
	}
	seq = append(seq, fields...)

	// Wrap in APPLICATION 30
	appLen := len(seq)
	var app []byte
	app = append(app, 0x7e)
	if appLen < 128 {
		app = append(app, byte(appLen))
	} else {
		app = append(app, 0x81, byte(appLen))
	}
	app = append(app, seq...)

	// Prepend TCP length prefix
	tcpLen := make([]byte, 4)
	binary.BigEndian.PutUint32(tcpLen, uint32(len(app)))
	return append(tcpLen, app...)
}

func TestKerberosWeakEtypesFindingHelper(t *testing.T) {
	t.Run("returns correct fields for non-empty realm", func(t *testing.T) {
		f := kerberosWeakEtypesFinding("EXAMPLE.COM")
		if f.ID != "kerberos-weak-etypes" {
			t.Errorf("ID: got %q, want %q", f.ID, "kerberos-weak-etypes")
		}
		if f.Severity != plugins.SeverityMedium {
			t.Errorf("Severity: got %q, want %q", f.Severity, plugins.SeverityMedium)
		}
		if !strings.Contains(f.Description, "RC4-HMAC") {
			t.Errorf("Description missing RC4-HMAC: %q", f.Description)
		}
		if !strings.Contains(f.Evidence, "RC4-HMAC") {
			t.Errorf("Evidence missing RC4-HMAC: %q", f.Evidence)
		}
		if !strings.Contains(f.Evidence, "EXAMPLE.COM") {
			t.Errorf("Evidence missing realm EXAMPLE.COM: %q", f.Evidence)
		}
	})

	t.Run("empty realm omits realm from evidence", func(t *testing.T) {
		f := kerberosWeakEtypesFinding("")
		if !strings.Contains(f.Evidence, "RC4-HMAC") {
			t.Errorf("Evidence missing RC4-HMAC: %q", f.Evidence)
		}
		if strings.Contains(f.Evidence, "realm") {
			t.Errorf("Evidence should not mention realm for empty realm: %q", f.Evidence)
		}
	})
}

func TestKerberosNoFindingWhenMisconfigsDisabled(t *testing.T) {
	response := buildTestKRBError(6, "EXAMPLE.COM", "")
	conn := &mockKerberosConn{responseData: response}

	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:88"),
		Host:       "127.0.0.1",
		Misconfigs: false,
	}

	p := &KerberosPlugin{}
	service, err := p.Run(conn, 2*time.Second, target)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if service == nil {
		t.Fatal("expected a detected service, got nil")
	}
	if len(service.SecurityFindings) != 0 {
		t.Errorf("expected no SecurityFindings when Misconfigs=false, got %d", len(service.SecurityFindings))
	}
}

func TestBuildRC4Probe(t *testing.T) {
	// Test with "NM" realm — should match the static probe exactly
	probe := buildRC4Probe("NM")
	if !bytes.Equal(probe, rc4OnlyProbe) {
		t.Errorf("buildRC4Probe(\"NM\") differs from static rc4OnlyProbe\nGot:  %x\nWant: %x", probe, rc4OnlyProbe)
	}

	// Test with longer realm
	probe = buildRC4Probe("EXAMPLE.COM")
	if len(probe) == 0 {
		t.Fatal("buildRC4Probe(\"EXAMPLE.COM\") returned empty")
	}
	// Verify APPLICATION 10 tag
	if probe[0] != 0x6a {
		t.Errorf("APPLICATION tag: got 0x%02x, want 0x6a", probe[0])
	}
	// Verify pvno=5 pattern present (context tag [1] = 0xa1 in AS-REQ encoding)
	asReqPvnoPattern := []byte{0xa1, 0x03, 0x02, 0x01, 0x05}
	if !bytes.Contains(probe, asReqPvnoPattern) {
		t.Error("pvno pattern not found in probe")
	}
	// Verify realm bytes present
	if !bytes.Contains(probe, []byte("EXAMPLE.COM")) {
		t.Error("realm bytes not found in probe")
	}
	// Verify etype 23 present
	etypePattern := []byte{0xa8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x17}
	if !bytes.Contains(probe, etypePattern) {
		t.Error("etype-23-only pattern not found in probe")
	}

	// Empty realm falls back to static probe
	probe = buildRC4Probe("")
	if !bytes.Equal(probe, rc4OnlyProbe) {
		t.Error("buildRC4Probe(\"\") should return rc4OnlyProbe")
	}

	// Too-long realm falls back to static probe
	probe = buildRC4Probe(strings.Repeat("A", 101))
	if !bytes.Equal(probe, rc4OnlyProbe) {
		t.Error("buildRC4Probe with 101-char realm should return rc4OnlyProbe")
	}
}

func TestKerberosWithMisconfigsEnabled(t *testing.T) {
	response := buildTestKRBError(6, "EXAMPLE.COM", "")
	conn := &mockKerberosConn{responseData: response}

	// TEST-NET address (RFC 5737) — guaranteed not to route/connect.
	target := plugins.Target{
		Address:    netip.MustParseAddrPort("192.0.2.1:88"),
		Host:       "192.0.2.1",
		Misconfigs: true,
	}

	p := &KerberosPlugin{}
	// Short timeout so checkWeakEtypes fails quickly on the unreachable address.
	service, err := p.Run(conn, 100*time.Millisecond, target)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if service == nil {
		t.Fatal("expected a detected service, got nil")
	}
	// checkWeakEtypes dials 192.0.2.1:88 which fails, so returns false → no finding.
	if len(service.SecurityFindings) != 0 {
		t.Errorf("expected no SecurityFindings when checkWeakEtypes cannot connect, got %d", len(service.SecurityFindings))
	}
}

func TestProbeRC4SupportAmbiguousErrorCode(t *testing.T) {
	// KRB-ERROR with error code 68 (KDC_ERR_WRONG_REALM) — the only remaining
	// ambiguous code. The KDC rejected the realm before evaluating the etype
	// list. probeRC4Support should return false.
	response := buildTestKRBError(68, "EXAMPLE.COM", "")
	conn := &mockKerberosConn{responseData: response}
	if probeRC4Support(conn, 2*time.Second, "EXAMPLE.COM") {
		t.Error("expected probeRC4Support to return false for ambiguous error code 68 (WRONG_REALM)")
	}
}

func TestProbeRC4SupportPrincipalUnknown(t *testing.T) {
	// KRB-ERROR with error code 6 (KDC_ERR_C_PRINCIPAL_UNKNOWN) — with the
	// correct realm, this means the KDC processed past etype validation and
	// then failed on principal lookup. RC4-HMAC is supported.
	response := buildTestKRBError(6, "EXAMPLE.COM", "")
	conn := &mockKerberosConn{responseData: response}
	if !probeRC4Support(conn, 2*time.Second, "EXAMPLE.COM") {
		t.Error("expected probeRC4Support to return true for error code 6 with correct realm")
	}
}

func TestProbeRC4SupportAccepted(t *testing.T) {
	// KRB-ERROR with error code 12 (KDC_ERR_POLICY) — this is not ambiguous.
	// A KDC that reaches policy evaluation has already accepted the etype list,
	// so RC4-HMAC is supported. probeRC4Support should return true.
	response := buildTestKRBError(12, "EXAMPLE.COM", "")
	conn := &mockKerberosConn{responseData: response}
	if !probeRC4Support(conn, 2*time.Second, "EXAMPLE.COM") {
		t.Error("expected probeRC4Support to return true for error code 12 (KDC_ERR_POLICY)")
	}
}

func TestProbeRC4SupportRejected(t *testing.T) {
	// KRB-ERROR with error code 14 (KDC_ERR_ETYPE_NOSUPP) — RC4 rejected.
	// probeRC4Support should return false.
	response := buildTestKRBError(14, "EXAMPLE.COM", "")
	conn := &mockKerberosConn{responseData: response}
	if probeRC4Support(conn, 2*time.Second, "EXAMPLE.COM") {
		t.Error("expected probeRC4Support to return false for error code 14")
	}
}

func TestProbeRC4SupportParseFailure(t *testing.T) {
	// KRB-ERROR tag (0x7E) followed by garbage — parseKerberosError returns errorCode=0.
	// probeRC4Support must return false (no false positive).
	garbage := make([]byte, 20)
	garbage[0] = 0x7E // KRB-ERROR tag
	// Fill rest with non-parseable bytes
	for i := 1; i < len(garbage); i++ {
		garbage[i] = 0xFF
	}
	tcpLen := make([]byte, 4)
	binary.BigEndian.PutUint32(tcpLen, uint32(len(garbage)))
	response := append(tcpLen, garbage...)

	conn := &mockKerberosConn{responseData: response}
	if probeRC4Support(conn, 2*time.Second, "EXAMPLE.COM") {
		t.Error("expected probeRC4Support to return false when parse fails (errorCode=0)")
	}
}

func TestProbeRC4SupportASREP(t *testing.T) {
	// AS-REP response (tag 0x6B) — KDC granted the request with RC4-HMAC.
	// probeRC4Support should return true.
	asrep := make([]byte, 10)
	asrep[0] = tagASREP // 0x6B
	copy(asrep[1:], pvnoPattern)
	tcpLen := make([]byte, 4)
	binary.BigEndian.PutUint32(tcpLen, uint32(len(asrep)))
	response := append(tcpLen, asrep...)

	conn := &mockKerberosConn{responseData: response}
	if !probeRC4Support(conn, 2*time.Second, "EXAMPLE.COM") {
		t.Error("expected probeRC4Support to return true for AS-REP response")
	}
}

func TestKerberos(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "kerberos",
			Port:        88,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil && res.Protocol == "kerberos" && res.Version == "5"
			},
			RunConfig: dockertest.RunOptions{
				Repository: "gcavalcante8808/krb5-server",
				Tag:        "latest",
				Env: []string{
					"KRB5_REALM=EXAMPLE.COM",
					"KRB5_KDC=localhost",
					"KRB5_PASS=admin",
				},
			},
		},
	}

	p := &KerberosPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

// resolveAddrPort converts a host:port string (which may contain "localhost") to
// a numeric netip.AddrPort suitable for plugins.Target.
func resolveAddrPort(t *testing.T, hostPort string) netip.AddrPort {
	t.Helper()
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", hostPort, err)
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ap, err := netip.ParseAddrPort(fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		t.Fatalf("ParseAddrPort: %v", err)
	}
	return ap
}

// startKerberosContainer starts the gcavalcante8808/krb5-server container and waits
// for it to accept TCP connections on port 88.
func startKerberosContainer(t *testing.T, pool *dockertest.Pool) (*dockertest.Resource, string) {
	t.Helper()

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "gcavalcante8808/krb5-server",
		Tag:          "latest",
		Env:          []string{"KRB5_REALM=EXAMPLE.COM", "KRB5_KDC=localhost", "KRB5_PASS=admin"},
		ExposedPorts: []string{"88/tcp"},
	})
	if err != nil {
		t.Fatalf("Could not start Kerberos container: %v", err)
	}

	addr := resource.GetHostPort("88/tcp")
	t.Logf("Kerberos container running at %s", addr)

	// Give the KDC time to initialize before polling.
	time.Sleep(10 * time.Second)

	err = pool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", addr, 3*time.Second)
		if dialErr != nil {
			return dialErr
		}
		conn.Close()
		return nil
	})
	if err != nil {
		pool.Purge(resource) //nolint:errcheck
		t.Fatalf("Kerberos container never became ready: %v", err)
	}

	return resource, addr
}

func TestKerberosIntegrationMisconfigs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker integration test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to Docker: %v", err)
	}

	resource, addr := startKerberosContainer(t, pool)
	defer pool.Purge(resource) //nolint:errcheck

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to Kerberos server: %v", err)
	}
	defer conn.Close()

	target := plugins.Target{
		Address:    resolveAddrPort(t, addr),
		Host:       "127.0.0.1",
		Misconfigs: true,
	}

	p := &KerberosPlugin{}
	service, err := p.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if service == nil {
		t.Fatal("expected a detected service, got nil")
	}

	if service.Protocol != "kerberos" {
		t.Errorf("expected protocol %q, got %q", "kerberos", service.Protocol)
	}
	if service.Version != "5" {
		t.Errorf("expected version %q, got %q", "5", service.Version)
	}

	if len(service.SecurityFindings) != 1 {
		t.Fatalf("Expected 1 SecurityFinding with Misconfigs=true, got %d", len(service.SecurityFindings))
	}
	f := service.SecurityFindings[0]
	if f.ID != "kerberos-weak-etypes" {
		t.Errorf("expected finding ID %q, got %q", "kerberos-weak-etypes", f.ID)
	}
	if f.Severity != plugins.SeverityMedium {
		t.Errorf("expected severity %q, got %q", plugins.SeverityMedium, f.Severity)
	}
	t.Logf("SecurityFinding: id=%s severity=%s", f.ID, f.Severity)
}

func TestKerberosIntegrationDetectionNoMisconfigs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker integration test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to Docker: %v", err)
	}

	resource, addr := startKerberosContainer(t, pool)
	defer pool.Purge(resource) //nolint:errcheck

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to Kerberos server: %v", err)
	}
	defer conn.Close()

	target := plugins.Target{
		Address:    resolveAddrPort(t, addr),
		Host:       "127.0.0.1",
		Misconfigs: false,
	}

	p := &KerberosPlugin{}
	service, err := p.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if service == nil {
		t.Fatal("expected a detected service, got nil")
	}

	if service.Protocol != "kerberos" {
		t.Errorf("expected protocol %q, got %q", "kerberos", service.Protocol)
	}
	if service.Version != "5" {
		t.Errorf("expected version %q, got %q", "5", service.Version)
	}

	if len(service.SecurityFindings) != 0 {
		t.Errorf("expected no SecurityFindings when Misconfigs=false, got %d", len(service.SecurityFindings))
	}
}

func TestProbeRC4SupportShortResponse(t *testing.T) {
	// 4-byte TCP length prefix + 2 bytes = 6 total, which is below the 10-byte minimum.
	// probeRC4Support should return false without panic.
	payload := []byte{0x7E, 0x00}
	tcpLen := make([]byte, 4)
	binary.BigEndian.PutUint32(tcpLen, uint32(len(payload)))
	response := append(tcpLen, payload...)

	conn := &mockKerberosConn{responseData: response}
	if probeRC4Support(conn, 2*time.Second, "EXAMPLE.COM") {
		t.Error("expected probeRC4Support to return false for response shorter than 10 bytes")
	}
}

func TestProbeRC4SupportWrongTag(t *testing.T) {
	// First Kerberos byte is 0x60 (not tagKRBError 0x7E or tagASREP 0x6B).
	// probeRC4Support should return false.
	payload := make([]byte, 14)
	payload[0] = 0x60
	tcpLen := make([]byte, 4)
	binary.BigEndian.PutUint32(tcpLen, uint32(len(payload)))
	response := append(tcpLen, payload...)

	conn := &mockKerberosConn{responseData: response}
	if probeRC4Support(conn, 2*time.Second, "EXAMPLE.COM") {
		t.Error("expected probeRC4Support to return false for non-Kerberos tag 0x60")
	}
}

func TestProbeRC4SupportErrorCode0FromValidKRBError(t *testing.T) {
	// buildTestKRBError(0, ...) produces a well-formed KRB-ERROR whose error-code
	// field encodes the integer 0. parseKerberosError returns errorCode=0, which
	// probeRC4Support treats as a parse failure and returns false (no false positive).
	response := buildTestKRBError(0, "EXAMPLE.COM", "")
	conn := &mockKerberosConn{responseData: response}
	if probeRC4Support(conn, 2*time.Second, "EXAMPLE.COM") {
		t.Error("expected probeRC4Support to return false when errorCode==0 (treated as parse failure)")
	}
}

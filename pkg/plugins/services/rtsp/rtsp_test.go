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

package rtsp

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// mockConn is a mock net.Conn for testing
type mockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return m.readBuf.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return m.writeBuf.Write(b)
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestRtsp(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "rtsp",
			Port:        8554,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository:   "aler9/rtsp-simple-server",
				ExposedPorts: []string{"8554"},
			},
		},
	}

	p := &RTSPPlugin{}

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

// TestRtspTruncatedResponse tests that the plugin handles truncated responses
// gracefully without panicking due to slice bounds errors
func TestRtspTruncatedResponse(t *testing.T) {
	p := &RTSPPlugin{}

	// Test case 1: Response truncated after CSeq header but before full value
	// This would cause a panic without bounds checking on line 91
	truncatedResponse := "RTSP/1.0 200 OK\r\nCSeq: 12"

	conn := &mockConn{
		readBuf:  bytes.NewBufferString(truncatedResponse),
		writeBuf: &bytes.Buffer{},
	}

	addr := netip.MustParseAddrPort("127.0.0.1:554")
	target := plugins.Target{
		Address: addr,
		Host:    "127.0.0.1",
	}

	// This should not panic - should return nil, nil for malformed response
	result, err := p.Run(conn, 5*time.Second, target)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if result != nil {
		t.Errorf("Expected nil result for truncated response, got: %v", result)
	}

	// Test case 2: Response truncated in middle of CSeq value
	truncatedResponse2 := "RTSP/1.0 200 OK\r\nCSeq: "

	conn2 := &mockConn{
		readBuf:  bytes.NewBufferString(truncatedResponse2),
		writeBuf: &bytes.Buffer{},
	}

	// This should also not panic
	result2, err2 := p.Run(conn2, 5*time.Second, target)

	if err2 != nil {
		t.Errorf("Expected no error, got: %v", err2)
	}

	if result2 != nil {
		t.Errorf("Expected nil result for truncated response, got: %v", result2)
	}
}

// TestParseRTSPStatusCode tests the parseRTSPStatusCode helper function.
func TestParseRTSPStatusCode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantCode int
	}{
		{"200 OK", "RTSP/1.0 200 OK\r\n", 200},
		{"401 Unauthorized", "RTSP/1.0 401 Unauthorized\r\n", 401},
		{"403 Forbidden", "RTSP/1.0 403 Forbidden\r\n", 403},
		{"404 Not Found", "RTSP/1.0 404 Not Found\r\n", 404},
		{"empty string", "", 0},
		{"wrong protocol HTTP", "HTTP/1.1 200 OK\r\n", 0},
		{"truncated after prefix", "RTSP/1.0 ", 0},
		{"only 1 digit", "RTSP/1.0 2\r\n", 0},
		{"only 2 digits", "RTSP/1.0 20\r\n", 0},
		{"non-numeric status", "RTSP/1.0 abc\r\n", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRTSPStatusCode(tt.input)
			assert.Equal(t, tt.wantCode, got)
		})
	}
}

// TestRTSPSecurityFindings verifies security findings when the DESCRIBE probe
// is used against a mock TCP server.
func TestRTSPSecurityFindings(t *testing.T) {
	tests := []struct {
		name                   string
		misconfigs             bool
		describeStatusLine     string // status line to write for DESCRIBE response; empty = no DESCRIBE
		wantAnonymousAccess    bool
		wantFindingCount       int
		wantFindingID          string
		wantFindingSeverity    plugins.Severity
	}{
		{
			name:                "misconfigs enabled, DESCRIBE 200 => unauthenticated access",
			misconfigs:          true,
			describeStatusLine:  "RTSP/1.0 200 OK",
			wantAnonymousAccess: true,
			wantFindingCount:    1,
			wantFindingID:       "rtsp-unauthenticated-stream",
			wantFindingSeverity: plugins.SeverityHigh,
		},
		{
			name:                "misconfigs enabled, DESCRIBE 401 => no finding",
			misconfigs:          true,
			describeStatusLine:  "RTSP/1.0 401 Unauthorized",
			wantAnonymousAccess: false,
			wantFindingCount:    0,
		},
		{
			name:                "misconfigs enabled, DESCRIBE 403 => no finding",
			misconfigs:          true,
			describeStatusLine:  "RTSP/1.0 403 Forbidden",
			wantAnonymousAccess: false,
			wantFindingCount:    0,
		},
		{
			name:                "misconfigs enabled, DESCRIBE 404 => no finding (ambiguous without auth)",
			misconfigs:          true,
			describeStatusLine:  "RTSP/1.0 404 Not Found",
			wantAnonymousAccess: false,
			wantFindingCount:    0,
		},
		{
			name:                "misconfigs disabled => no DESCRIBE, no finding",
			misconfigs:          false,
			describeStatusLine:  "", // server won't serve a DESCRIBE response
			wantAnonymousAccess: false,
			wantFindingCount:    0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to start mock server: %v", err)
			}
			defer listener.Close()

			tcpAddr := listener.Addr().(*net.TCPAddr)
			serverPort := tcpAddr.Port

			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()

				// Read the OPTIONS request and extract the CSeq value.
				buf := make([]byte, 4096)
				n, err := conn.Read(buf)
				if err != nil {
					return
				}
				request := string(buf[:n])

				// Parse the CSeq value from the request so the response matches.
				cseqVal := ""
				for _, line := range strings.Split(request, "\r\n") {
					if strings.HasPrefix(strings.ToLower(line), "cseq:") {
						cseqVal = strings.TrimSpace(line[len("cseq:"):])
						break
					}
				}

				// Write a valid OPTIONS response.
				optionsResp := fmt.Sprintf(
					"RTSP/1.0 200 OK\r\nCSeq: %s\r\nServer: TestServer\r\n\r\n",
					cseqVal,
				)
				_, _ = conn.Write([]byte(optionsResp))

				// If misconfigs is enabled, serve the DESCRIBE response too.
				if tt.misconfigs {
					_, _ = conn.Read(buf)
					describeResp := fmt.Sprintf(
						"%s\r\nCSeq: 1\r\nContent-Type: application/sdp\r\n\r\n",
						tt.describeStatusLine,
					)
					_, _ = conn.Write([]byte(describeResp))
				}
			}()

			// Give the goroutine a moment to start listening.
			time.Sleep(10 * time.Millisecond)

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
			if err != nil {
				t.Fatalf("Failed to connect to mock server: %v", err)
			}
			defer conn.Close()

			addrPort := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", serverPort))
			target := plugins.Target{
				Host:       "127.0.0.1",
				Address:    addrPort,
				Misconfigs: tt.misconfigs,
			}

			p := &RTSPPlugin{}
			service, err := p.Run(conn, 5*time.Second, target)
			if err != nil {
				t.Fatalf("Run() returned unexpected error: %v", err)
			}
			if service == nil {
				t.Fatal("Run() returned nil service, expected non-nil")
			}

			assert.Equal(t, tt.wantAnonymousAccess, service.AnonymousAccess, "AnonymousAccess mismatch")
			assert.Len(t, service.SecurityFindings, tt.wantFindingCount, "SecurityFindings length mismatch")

			if tt.wantFindingCount > 0 {
				assert.Equal(t, tt.wantFindingID, service.SecurityFindings[0].ID, "Finding ID mismatch")
				assert.Equal(t, tt.wantFindingSeverity, service.SecurityFindings[0].Severity, "Finding severity mismatch")
			}
		})
	}
}

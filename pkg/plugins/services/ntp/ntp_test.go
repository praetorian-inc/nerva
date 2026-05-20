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

package ntp

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// sequentialMockConn implements net.Conn for testing sequential SendRecv calls.
// Each call to Read returns the next response in the responses slice.
// SetDeadline methods return nil so that utils.SendRecv works without a real
// network connection.
type sequentialMockConn struct {
	responses [][]byte
	readIndex int
}

func (m *sequentialMockConn) Read(b []byte) (n int, err error) {
	if m.readIndex >= len(m.responses) {
		return 0, nil
	}
	n = copy(b, m.responses[m.readIndex])
	m.readIndex++
	return n, nil
}

func (m *sequentialMockConn) Write(b []byte) (n int, err error)      { return len(b), nil }
func (m *sequentialMockConn) Close() error                            { return nil }
func (m *sequentialMockConn) LocalAddr() net.Addr                     { return nil }
func (m *sequentialMockConn) RemoteAddr() net.Addr                    { return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 123} }
func (m *sequentialMockConn) SetDeadline(t time.Time) error           { return nil }
func (m *sequentialMockConn) SetReadDeadline(t time.Time) error       { return nil }
func (m *sequentialMockConn) SetWriteDeadline(t time.Time) error      { return nil }

// validNTPResponse returns a 48-byte NTP mode 4 (server) response.
func validNTPResponse() []byte {
	resp := make([]byte, 48)
	resp[0] = 0x24 // LI=0, VN=4, Mode=4
	return resp
}

// validMonlistResponse returns a 480-byte monlist response with mode 7 and
// response bit set.
func validMonlistResponse() []byte {
	resp := make([]byte, 480)
	resp[0] = 0x97 // Response=1, More=0, Version=2, Mode=7
	resp[1] = 0x00
	resp[2] = 0x03 // Implementation = ntpd
	resp[3] = 0x2a // Request code = 42 (MON_GETLIST_1)
	return resp
}

// ntpTarget builds a Target at 127.0.0.1:123 with Misconfigs set as specified.
func ntpTarget(misconfigs bool) plugins.Target {
	return plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:123"),
		Misconfigs: misconfigs,
	}
}

// TestNTPMonlistFinding verifies that when target.Misconfigs is true and the
// server responds to the monlist probe with a valid mode 7 response, a
// SecurityFinding with ID "ntp-monlist" and SeverityMedium is appended.
func TestNTPMonlistFinding(t *testing.T) {
	plugin := &Plugin{}
	conn := &sequentialMockConn{
		responses: [][]byte{
			validNTPResponse(),
			validMonlistResponse(),
		},
	}

	svc, err := plugin.Run(conn, 5*time.Second, ntpTarget(true))
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service, want non-nil")
	}
	if len(svc.SecurityFindings) != 1 {
		t.Fatalf("len(SecurityFindings) = %d, want 1", len(svc.SecurityFindings))
	}
	f := svc.SecurityFindings[0]
	if f.ID != "ntp-monlist" {
		t.Errorf("SecurityFinding.ID = %q, want %q", f.ID, "ntp-monlist")
	}
	if f.Severity != plugins.SeverityMedium {
		t.Errorf("SecurityFinding.Severity = %q, want %q", f.Severity, plugins.SeverityMedium)
	}
}

// TestNTPMonlistFindingDisabled verifies that when target.Misconfigs is false,
// no monlist probe is sent and no SecurityFindings are populated.
func TestNTPMonlistFindingDisabled(t *testing.T) {
	plugin := &Plugin{}
	// Only one response needed: monlist probe must not be sent.
	conn := &sequentialMockConn{
		responses: [][]byte{
			validNTPResponse(),
		},
	}

	svc, err := plugin.Run(conn, 5*time.Second, ntpTarget(false))
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service, want non-nil")
	}
	if len(svc.SecurityFindings) != 0 {
		t.Errorf("len(SecurityFindings) = %d, want 0", len(svc.SecurityFindings))
	}
}

// TestNTPMonlistRefused verifies that when target.Misconfigs is true but the
// server returns an empty response to the monlist probe (monlist disabled or
// filtered), no SecurityFinding is appended.
func TestNTPMonlistRefused(t *testing.T) {
	plugin := &Plugin{}
	conn := &sequentialMockConn{
		responses: [][]byte{
			validNTPResponse(),
			{}, // empty response: monlist disabled
		},
	}

	svc, err := plugin.Run(conn, 5*time.Second, ntpTarget(true))
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service, want non-nil")
	}
	if len(svc.SecurityFindings) != 0 {
		t.Errorf("len(SecurityFindings) = %d, want 0", len(svc.SecurityFindings))
	}
}

// errorOnSecondReadConn implements net.Conn where the first Read returns a
// provided response and the second Read returns an error. This simulates a
// connection that fails during the monlist probe but succeeds for NTP detection.
type errorOnSecondReadConn struct {
	firstResponse []byte
	callCount     int
}

func (m *errorOnSecondReadConn) Read(b []byte) (n int, err error) {
	m.callCount++
	if m.callCount == 1 {
		n = copy(b, m.firstResponse)
		return n, nil
	}
	return 0, fmt.Errorf("connection reset by peer")
}

func (m *errorOnSecondReadConn) Write(b []byte) (n int, err error)      { return len(b), nil }
func (m *errorOnSecondReadConn) Close() error                            { return nil }
func (m *errorOnSecondReadConn) LocalAddr() net.Addr                     { return nil }
func (m *errorOnSecondReadConn) RemoteAddr() net.Addr                    { return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 123} }
func (m *errorOnSecondReadConn) SetDeadline(t time.Time) error           { return nil }
func (m *errorOnSecondReadConn) SetReadDeadline(t time.Time) error       { return nil }
func (m *errorOnSecondReadConn) SetWriteDeadline(t time.Time) error      { return nil }

// TestCheckMonlistEdgeCases covers the boundary conditions of the monlist
// response bit and mode field checks, single-byte responses, the error bit
// (which current code ignores), non-NTP first responses, and connection errors
// during the monlist probe.
func TestCheckMonlistEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		buildConn     func() net.Conn
		wantService   bool
		wantFindings  int
		wantRunErr    bool
	}{
		{
			// byte 0 = 0x17: mode 7 set, response bit (0x80) NOT set.
			// checkMonlist must return nil — the check requires BOTH bits.
			name: "mode7_no_response_bit",
			buildConn: func() net.Conn {
				resp := make([]byte, 48)
				resp[0] = 0x17 // mode=7, response=0
				return &sequentialMockConn{
					responses: [][]byte{validNTPResponse(), resp},
				}
			},
			wantService:  true,
			wantFindings: 0,
		},
		{
			// byte 0 = 0x84: response bit set (0x80), mode=4 (regular NTP response).
			// checkMonlist must return nil — mode is not 7.
			name: "response_bit_wrong_mode",
			buildConn: func() net.Conn {
				resp := make([]byte, 48)
				resp[0] = 0x84 // response=1, mode=4
				return &sequentialMockConn{
					responses: [][]byte{validNTPResponse(), resp},
				}
			},
			wantService:  true,
			wantFindings: 0,
		},
		{
			// A single-byte response where byte 0 = 0x97 (response=1, mode=7).
			// checkMonlist requires at least 4 bytes, so a 1-byte response must
			// not fire the finding.
			name: "single_byte_response_too_short",
			buildConn: func() net.Conn {
				return &sequentialMockConn{
					responses: [][]byte{validNTPResponse(), {0x97}},
				}
			},
			wantService:  true,
			wantFindings: 0,
		},
		{
			// byte 0 = 0xD7: response=1, error=1, mode=7.
			// The error bit (0x40) is set, which means monlist was refused.
			// checkMonlist must not fire the finding when the error bit is set.
			name: "error_bit_set_no_finding",
			buildConn: func() net.Conn {
				resp := make([]byte, 48)
				resp[0] = 0xD7 // response=1, error=1, mode=7
				return &sequentialMockConn{
					responses: [][]byte{validNTPResponse(), resp},
				}
			},
			wantService:  true,
			wantFindings: 0,
		},
		{
			// First response is not a valid NTP reply (wrong mode bits).
			// Run() must return nil without panicking or returning an error.
			name: "non_ntp_first_response",
			buildConn: func() net.Conn {
				bad := make([]byte, 48)
				bad[0] = 0x00 // mode=0, not a server response
				return &sequentialMockConn{
					responses: [][]byte{bad},
				}
			},
			wantService:  false,
			wantFindings: 0,
		},
		{
			// First Read succeeds (valid NTP), second Read returns a connection
			// error during the monlist probe. Run() must still return the service
			// and must not propagate the monlist error to the caller.
			name: "monlist_probe_connection_error",
			buildConn: func() net.Conn {
				return &errorOnSecondReadConn{firstResponse: validNTPResponse()}
			},
			wantService:  true,
			wantFindings: 0,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			plugin := &Plugin{}
			svc, err := plugin.Run(tc.buildConn(), 5*time.Second, ntpTarget(true))

			if tc.wantRunErr && err == nil {
				t.Error("Run() error = nil, want non-nil")
			}
			if !tc.wantRunErr && err != nil {
				t.Errorf("Run() error = %v, want nil", err)
			}

			if tc.wantService && svc == nil {
				t.Fatal("Run() returned nil service, want non-nil")
			}
			if !tc.wantService && svc != nil {
				t.Errorf("Run() returned non-nil service, want nil")
			}

			if svc != nil && len(svc.SecurityFindings) != tc.wantFindings {
				t.Errorf("len(SecurityFindings) = %d, want %d", len(svc.SecurityFindings), tc.wantFindings)
			}
		})
	}
}

// TestNTPMonlistDocker spins up the cturra/ntp Docker container (chrony) and
// verifies that the monlist probe produces no finding. chrony does not support
// the ntpd-specific mode 7 protocol, so this is a false-positive regression
// test: a real NTP server without monlist must be detected as NTP but must not
// trigger the ntp-monlist finding.
func TestNTPMonlistDocker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "cturra/ntp",
	})
	if err != nil {
		t.Fatalf("could not start ntp container: %s", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	rawAddr := resource.GetHostPort("123/udp")

	time.Sleep(10 * time.Second)

	err = pool.Retry(func() error {
		conn, dialErr := net.Dial("udp", rawAddr)
		if dialErr != nil {
			return dialErr
		}
		conn.Close()
		return nil
	})
	if err != nil {
		t.Fatalf("failed to connect to ntp container: %s", err)
	}

	conn, err := net.Dial("udp", rawAddr)
	if err != nil {
		t.Fatalf("failed to open connection to ntp container: %s", err)
	}
	defer conn.Close()

	addrPort, err := netip.ParseAddrPort(rawAddr)
	if err != nil {
		// rawAddr may be 0.0.0.0:port or [::]:port on some Docker hosts; normalise.
		host, port, splitErr := net.SplitHostPort(rawAddr)
		if splitErr != nil {
			t.Fatalf("could not parse container address %q: %v", rawAddr, splitErr)
		}
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		addrPort, err = netip.ParseAddrPort(net.JoinHostPort(host, port))
		if err != nil {
			t.Fatalf("could not construct AddrPort from %q: %v", rawAddr, err)
		}
	}

	target := plugins.Target{
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &Plugin{}
	svc, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}

	// chrony responds to NTP mode 3 client queries, so the service must be detected.
	if svc == nil {
		t.Fatal("Run() returned nil service; expected NTP service to be detected")
	}

	// chrony does not implement mode 7 (monlist); no finding must be produced.
	if len(svc.SecurityFindings) != 0 {
		t.Errorf("false positive: got %d SecurityFinding(s), want 0 (chrony does not support monlist)", len(svc.SecurityFindings))
	}
}

func TestNTP(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "ntp",
			Port:        123,
			Protocol:    plugins.UDP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "cturra/ntp",
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

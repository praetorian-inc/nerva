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

package kafkanew

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// handleMockKafkaNew serves one client connection for the mock kafkaNew server.
// It always responds to the ApiVersions request. When saslRequired is false it
// also responds to the subsequent Metadata request; otherwise it closes the
// connection after ApiVersions to simulate a SASL-only broker.
func handleMockKafkaNew(conn net.Conn, saslRequired bool) {
	defer conn.Close()

	// Read the ApiVersions request (length-prefixed)
	lenBuf := make([]byte, 4)
	if err := readFull(conn, lenBuf); err != nil {
		return
	}
	reqLen := binary.BigEndian.Uint32(lenBuf)
	reqBody := make([]byte, reqLen)
	if err := readFull(conn, reqBody); err != nil {
		return
	}

	// Extract correlation_id from bytes 4-7 of the body (offset 8-11 overall)
	var cid [4]byte
	if len(reqBody) >= 8 {
		copy(cid[:], reqBody[4:8])
	}

	// Build ApiVersions v0 response: length(4) + correlation_id(4) + error_code(2) + api_keys_count(4)
	apiResp := make([]byte, 4+4+2+4)
	binary.BigEndian.PutUint32(apiResp[0:4], 4+2+4) // length of remaining bytes
	copy(apiResp[4:8], cid[:])
	// error_code = 0, api_keys_count = 0 already (zero value)
	if _, err := conn.Write(apiResp); err != nil {
		return
	}

	if saslRequired {
		// Close after ApiVersions to simulate a SASL-enabled broker
		return
	}

	// Read the Metadata request
	if err := readFull(conn, lenBuf); err != nil {
		return
	}
	metaLen := binary.BigEndian.Uint32(lenBuf)
	metaBody := make([]byte, metaLen)
	if err := readFull(conn, metaBody); err != nil {
		return
	}

	// Extract correlation_id from metadata request
	var metaCID [4]byte
	if len(metaBody) >= 8 {
		copy(metaCID[:], metaBody[4:8])
	}

	// Build Metadata v0 response: length(4) + correlation_id(4) + broker_count(4) + topic_count(4)
	metaResp := make([]byte, 4+4+4+4)
	binary.BigEndian.PutUint32(metaResp[0:4], 4+4+4) // length of remaining bytes
	copy(metaResp[4:8], metaCID[:])
	// broker_count = 0, topic_count = 0 already (zero value)
	if _, err := conn.Write(metaResp); err != nil {
		return
	}
}

// readFull reads exactly len(buf) bytes from conn.
func readFull(conn net.Conn, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return err
		}
	}
	return nil
}

// TestKafkaNewSecurityFindings verifies SASL misconfiguration detection via a
// mock TCP server, following the pattern from TestMongoDBSecurityFindings.
func TestKafkaNewSecurityFindings(t *testing.T) {
	tests := []struct {
		name          string
		misconfigs    bool
		saslRequired  bool
		wantAnon      bool
		wantFindings  int
		wantFindingID string
		wantSeverity  plugins.Severity
	}{
		{
			name:          "misconfigs=true no SASL",
			misconfigs:    true,
			saslRequired:  false,
			wantAnon:      true,
			wantFindings:  1,
			wantFindingID: "kafka-no-sasl",
			wantSeverity:  plugins.SeverityHigh,
		},
		{
			name:         "misconfigs=true SASL required",
			misconfigs:   true,
			saslRequired: true,
			wantAnon:     false,
			wantFindings: 0,
		},
		{
			name:         "misconfigs=false",
			misconfigs:   false,
			saslRequired: false,
			wantAnon:     false,
			wantFindings: 0,
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
				serverConn, err := listener.Accept()
				if err != nil {
					return
				}
				handleMockKafkaNew(serverConn, tt.saslRequired)
			}()

			conn, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatalf("Failed to connect to mock server: %v", err)
			}
			defer conn.Close()

			addrStr := net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort))
			addrPort := netip.MustParseAddrPort(addrStr)
			target := plugins.Target{
				Host:       "127.0.0.1",
				Address:    addrPort,
				Misconfigs: tt.misconfigs,
			}

			service, err := Run(conn, false, 5*time.Second, target)
			if err != nil {
				t.Fatalf("Run() returned unexpected error: %v", err)
			}
			if service == nil {
				t.Fatal("Run() returned nil, want non-nil service")
			}

			if service.AnonymousAccess != tt.wantAnon {
				t.Errorf("AnonymousAccess = %v, want %v", service.AnonymousAccess, tt.wantAnon)
			}
			if len(service.SecurityFindings) != tt.wantFindings {
				t.Fatalf("len(SecurityFindings) = %d, want %d", len(service.SecurityFindings), tt.wantFindings)
			}
			if tt.wantFindings > 0 {
				if service.SecurityFindings[0].ID != tt.wantFindingID {
					t.Errorf("SecurityFindings[0].ID = %q, want %q", service.SecurityFindings[0].ID, tt.wantFindingID)
				}
				if service.SecurityFindings[0].Severity != tt.wantSeverity {
					t.Errorf("SecurityFindings[0].Severity = %q, want %q", service.SecurityFindings[0].Severity, tt.wantSeverity)
				}
			}
		})
	}
}

// TestKafkaNewSecurityFindingsLive spins up a real bitnami/kafka container and
// verifies that the kafka-no-sasl finding is detected (or suppressed) correctly.
func TestKafkaNewSecurityFindingsLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	tests := []struct {
		name         string
		misconfigs   bool
		wantAnon     bool
		wantFindings int
	}{
		{
			name:         "no SASL - finding detected",
			misconfigs:   true,
			wantAnon:     true,
			wantFindings: 1,
		},
		{
			name:         "no SASL but misconfigs disabled",
			misconfigs:   false,
			wantAnon:     false,
			wantFindings: 0,
		},
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %s", err)
	}

	// spotify/kafka runs Kafka 0.10.1.0 on port 9092 with no authentication,
	// which is the no-SASL configuration we want to test against.
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "spotify/kafka",
		Tag:        "latest",
	})
	if err != nil {
		t.Fatalf("could not start kafka container: %s", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	rawAddr := resource.GetHostPort("9092/tcp")
	host, port, err := net.SplitHostPort(rawAddr)
	if err != nil {
		t.Fatalf("could not parse host:port %q: %v", rawAddr, err)
	}
	if host == "localhost" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	targetAddr := net.JoinHostPort(host, port)

	// Wait until Kafka is ready by sending an ApiVersions request and expecting
	// a valid length-prefixed response.
	err = pool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", targetAddr, 5*time.Second)
		if dialErr != nil {
			return dialErr
		}
		defer conn.Close()

		cid := genCorrelationID()
		apiVersionsRequest := []byte{
			0x00, 0x00, 0x00, 0x43,
			0x00, 0x12,
			0x00, 0x00,
			cid[0], cid[1], cid[2], cid[3],
			0x00, 0x1f, 0x63, 0x6f, 0x6e, 0x73, 0x75, 0x6d,
			0x65, 0x72, 0x2d, 0x4f, 0x66, 0x66, 0x73, 0x65,
			0x74, 0x20, 0x45, 0x78, 0x70, 0x6c, 0x6f, 0x72,
			0x65, 0x72, 0x20, 0x32, 0x2e, 0x32, 0x2d, 0x31,
			0x38,
			0x00,
			0x12, 0x61, 0x70, 0x61, 0x63, 0x68, 0x65, 0x2d,
			0x6b, 0x61, 0x66, 0x6b, 0x61, 0x2d, 0x6a, 0x61,
			0x76, 0x61,
			0x06, 0x32, 0x2e, 0x34, 0x2e, 0x30,
			0x00,
		}
		if _, writeErr := conn.Write(apiVersionsRequest); writeErr != nil {
			return writeErr
		}
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, readErr := conn.Read(buf)
		if readErr != nil || n < 4 {
			return fmt.Errorf("kafka not ready: read %d bytes, err: %v", n, readErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed waiting for kafka container: %s", err)
	}

	addrPort := netip.MustParseAddrPort(targetAddr)

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			conn, dialErr := net.DialTimeout("tcp", targetAddr, 5*time.Second)
			if dialErr != nil {
				t.Fatalf("failed to connect to kafka container: %v", dialErr)
			}
			defer conn.Close()

			target := plugins.Target{
				Host:       host,
				Address:    addrPort,
				Misconfigs: tt.misconfigs,
			}

			service, runErr := Run(conn, false, 5*time.Second, target)
			if runErr != nil {
				t.Fatalf("Run() returned unexpected error: %v", runErr)
			}
			if service == nil {
				t.Fatal("Run() returned nil, want non-nil service")
			}

			if service.AnonymousAccess != tt.wantAnon {
				t.Errorf("AnonymousAccess = %v, want %v", service.AnonymousAccess, tt.wantAnon)
			}
			if len(service.SecurityFindings) != tt.wantFindings {
				t.Fatalf("len(SecurityFindings) = %d, want %d", len(service.SecurityFindings), tt.wantFindings)
			}
			if tt.wantFindings > 0 {
				if service.SecurityFindings[0].ID != "kafka-no-sasl" {
					t.Errorf("SecurityFindings[0].ID = %q, want %q", service.SecurityFindings[0].ID, "kafka-no-sasl")
				}
				if service.SecurityFindings[0].Severity != plugins.SeverityHigh {
					t.Errorf("SecurityFindings[0].Severity = %q, want %q", service.SecurityFindings[0].Severity, plugins.SeverityHigh)
				}
			}
		})
	}
}

func TestKafkaNew(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "kafkanew",
			Port:        9092,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "spotify/kafka",
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

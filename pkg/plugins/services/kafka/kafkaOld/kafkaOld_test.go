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

package kafkaold

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// readFullOld reads exactly len(buf) bytes from conn.
func readFullOld(conn net.Conn, buf []byte) error {
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

// handleMockKafkaOld serves one client connection for the mock kafkaOld server.
// It reads the Metadata v0 request, extracts the random topic name from the
// payload, and sends back a valid Metadata v0 response containing that topic.
func handleMockKafkaOld(conn net.Conn) {
	defer conn.Close()

	lenBuf := make([]byte, 4)
	if err := readFullOld(conn, lenBuf); err != nil {
		return
	}
	reqLen := binary.BigEndian.Uint32(lenBuf)
	reqBody := make([]byte, reqLen)
	if err := readFullOld(conn, reqBody); err != nil {
		return
	}

	// Extract correlation_id from bytes 4-7 of the body (offset 8-11 overall)
	var cid [4]byte
	if len(reqBody) >= 8 {
		copy(cid[:], reqBody[4:8])
	}

	// Extract topic name: in the request body the layout after the header is:
	//   api_key(2) + api_version(2) + correlation_id(4) + client_id_len(2) + client_id(13)
	//   = 2+2+4+2+13 = 23 bytes of header fields
	//   then topic_count(4) + topic_name_len(2) + topic_name(6)
	// Topic name starts at body offset 23+4+2 = 29
	var topicName [6]byte
	if len(reqBody) >= 35 {
		copy(topicName[:], reqBody[29:35])
	}

	// Build Metadata v0 response with the echoed topic name:
	//   length(4) + correlation_id(4) + broker_count(4) + topic_count(4) +
	//   error_code(2) + topic_name_length(2) + topic_name(6) + partition_count(2)
	payload := make([]byte, 4+4+4+4+2+2+6+2) // 28 bytes total
	binary.BigEndian.PutUint32(payload[0:4], uint32(len(payload)-4))
	copy(payload[4:8], cid[:])
	binary.BigEndian.PutUint32(payload[8:12], 0)  // broker_count = 0
	binary.BigEndian.PutUint32(payload[12:16], 1) // topic_count = 1
	binary.BigEndian.PutUint16(payload[16:18], 0) // error_code = 0
	binary.BigEndian.PutUint16(payload[18:20], 6) // topic_name_length = 6
	copy(payload[20:26], topicName[:])
	binary.BigEndian.PutUint16(payload[26:28], 0) // partition_count = 0

	conn.Write(payload) //nolint:errcheck
}

// TestKafkaOldSecurityFindings verifies SASL misconfiguration detection for the
// kafkaOld plugin via a mock TCP server.
func TestKafkaOldSecurityFindings(t *testing.T) {
	tests := []struct {
		name          string
		misconfigs    bool
		wantAnon      bool
		wantFindings  int
		wantFindingID string
		wantSeverity  plugins.Severity
	}{
		{
			name:          "misconfigs=true",
			misconfigs:    true,
			wantAnon:      true,
			wantFindings:  1,
			wantFindingID: "kafka-no-sasl",
			wantSeverity:  plugins.SeverityHigh,
		},
		{
			name:         "misconfigs=false",
			misconfigs:   false,
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
				handleMockKafkaOld(serverConn)
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

func TestKafkaOld(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "kafkaold",
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

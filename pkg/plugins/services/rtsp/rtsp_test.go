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
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"

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

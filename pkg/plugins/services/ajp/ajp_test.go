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

package ajp

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// ---------------------------------------------------------------------------
// T4: Probe builder test
// ---------------------------------------------------------------------------

// TestBuildCPingProbe verifies the package-level cpingProbe constant is the
// correct 5-byte AJPv13 CPing frame.
func TestBuildCPingProbe(t *testing.T) {
	expected := []byte{0x12, 0x34, 0x00, 0x01, 0x0a}

	if len(cpingProbe) != 5 {
		t.Fatalf("cpingProbe length: got %d, want 5", len(cpingProbe))
	}
	if !bytes.Equal(cpingProbe, expected) {
		t.Errorf("cpingProbe = %x, want %x", cpingProbe, expected)
	}
}

// ---------------------------------------------------------------------------
// T4: Response validator tests (table-driven)
// ---------------------------------------------------------------------------

// isValidCPong is a thin helper that mirrors DetectAJP's validation logic so
// that tests can exercise the byte-level checks without a real connection.
func isValidCPong(resp []byte) bool {
	if len(resp) == 0 {
		return false
	}
	if len(resp) < 5 {
		return false
	}
	return bytes.Equal(resp[:5], cpongExpected)
}

// TestIsValidCPong verifies the CPong byte-level validator against all
// adversarial vectors enumerated in architecture.md section 5.2 and
// security-review.md item 14.
func TestIsValidCPong(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			name:     "valid CPong exact 5 bytes",
			input:    []byte{0x41, 0x42, 0x00, 0x01, 0x09},
			expected: true,
		},
		{
			name:     "empty (nil) response",
			input:    nil,
			expected: false,
		},
		{
			name:     "short truncated 3 bytes",
			input:    []byte{0x41, 0x42, 0x00},
			expected: false,
		},
		{
			name:     "wrong magic byte 0 (ab instead of 41)",
			input:    []byte{0xab, 0xcd, 0x00, 0x01, 0x09},
			expected: false,
		},
		{
			name:     "wrong magic byte 1 (00 instead of 42)",
			input:    []byte{0x41, 0x00, 0x00, 0x01, 0x09},
			expected: false,
		},
		{
			name:     "wrong length field (00 02 instead of 00 01)",
			input:    []byte{0x41, 0x42, 0x00, 0x02, 0x09},
			expected: false,
		},
		{
			name:     "wrong code byte (08 instead of 09)",
			input:    []byte{0x41, 0x42, 0x00, 0x01, 0x08},
			expected: false,
		},
		{
			// HTTP/1.1 400 Bad Request — the kind of response an HTTP server on
			// port 8009 would emit. Starts with 'H' (0x48). Must be rejected.
			name:     "HTTP 400 response prefix",
			input:    []byte{0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x34},
			expected: false,
		},
		{
			// Valid CPong magic followed by extra bytes — trailing bytes are ignored;
			// validation is a prefix check, not a length-equality check.
			name:     "valid CPong with trailing bytes (prefix match accepted)",
			input:    []byte{0x41, 0x42, 0x00, 0x01, 0x09, 0xff, 0xff},
			expected: true,
		},
		{
			name:     "4096 byte garbage response (rejected)",
			input:    bytes.Repeat([]byte{0xff}, 4096),
			expected: false,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			result := isValidCPong(tt.input)
			if result != tt.expected {
				t.Errorf("isValidCPong(%x) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// T5: Mock-server tests via net.Pipe
// ---------------------------------------------------------------------------

// TestPluginRun_MockServer_Success verifies that Plugin.Run correctly detects
// AJP when the server sends a valid CPong response.
func TestPluginRun_MockServer_Success(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	goroutineErr := make(chan error, 1)
	go func() {
		defer close(goroutineErr)
		defer server.Close()

		// Read the 5-byte CPing probe.
		buf := make([]byte, 5)
		if _, err := server.Read(buf); err != nil {
			goroutineErr <- fmt.Errorf("server read failed: %w", err)
			return
		}
		if !bytes.Equal(buf, cpingProbe) {
			goroutineErr <- fmt.Errorf("server received %x, want CPing %x", buf, cpingProbe)
			return
		}
		// Respond with valid CPong.
		if _, err := server.Write(cpongExpected); err != nil {
			goroutineErr <- fmt.Errorf("server write failed: %w", err)
			return
		}
	}()

	result, err := (&Plugin{}).Run(client, 2*time.Second, plugins.Target{})
	if err := <-goroutineErr; err != nil {
		t.Errorf("%v", err)
	}
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if result == nil {
		t.Fatal("Run() result is nil, want non-nil Service")
	}
	if result.Protocol != plugins.ProtoAJP {
		t.Errorf("result.Protocol = %q, want %q", result.Protocol, plugins.ProtoAJP)
	}

	// Verify CPE is present in the raw payload via the Metadata() helper.
	meta := result.Metadata()
	ajp, ok := meta.(plugins.ServiceAJP)
	if !ok {
		t.Fatalf("Metadata() type = %T, want plugins.ServiceAJP", meta)
	}
	if ajp.ProtocolVersion != "1.3" {
		t.Errorf("ProtocolVersion = %q, want %q", ajp.ProtocolVersion, "1.3")
	}
	if !ajp.CPingEnabled {
		t.Errorf("CPingEnabled = false, want true")
	}
	if len(ajp.CPEs) == 0 || ajp.CPEs[0] != AJPCPEMatch {
		t.Errorf("CPEs = %v, want [%q]", ajp.CPEs, AJPCPEMatch)
	}
	if result.Version != "1.3" {
		t.Errorf("result.Version = %q, want %q", result.Version, "1.3")
	}
}

// TestPluginRun_MockServer_HTTP400 verifies that Plugin.Run returns nil/nil
// when the server sends an HTTP 400 response instead of CPong.
func TestPluginRun_MockServer_HTTP400(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		// Read whatever the client sends (swallow it).
		buf := make([]byte, 64)
		_, _ = server.Read(buf)
		// Respond with HTTP/1.1 400 Bad Request.
		_, _ = server.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}()

	result, err := (&Plugin{}).Run(client, 2*time.Second, plugins.Target{})
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if result != nil {
		t.Errorf("Run() result = %v, want nil", result)
	}
}

// TestPluginRun_MockServer_EmptyRead verifies that Plugin.Run returns nil/nil
// when the server reads the probe but closes without writing any data.
// The server must read the CPing probe first so the client write succeeds
// (net.Pipe is synchronous). Then it closes without writing — simulating a
// non-AJP service that accepts the connection and then drops it.
func TestPluginRun_MockServer_EmptyRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		// Read the CPing probe (so the client write doesn't block/error), then
		// close without writing — produces an EOF/empty-read on the client side.
		buf := make([]byte, 5)
		_, _ = server.Read(buf)
		// Close without writing any response.
	}()

	result, err := (&Plugin{}).Run(client, 2*time.Second, plugins.Target{})
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if result != nil {
		t.Errorf("Run() result = %v, want nil", result)
	}
}

// ---------------------------------------------------------------------------
// T6: Docker integration test (keep-container-alive variant)
//
// NOTE: This test intentionally does NOT call test.RunTest because that helper
// unconditionally calls defer dockerPool.Purge(resource), destroying the
// container before the user can inspect it. This inline runner wraps the purge
// behind NERVA_KEEP_CONTAINER so the default behavior is identical but the
// user can opt in to container persistence for manual follow-up.
//
// To keep the container after the test:
//   NERVA_KEEP_CONTAINER=1 go test -v -run TestDockerAJP ./pkg/plugins/services/ajp/...
//
// Bind address note: tomcat:9.0.30 is the last pre-Ghostcat-patch release
// with AJP enabled on 0.0.0.0:8009 out-of-the-box. tomcat:9.0.31+ disables
// AJP by default and restricts the bind address to 127.0.0.1.
// ---------------------------------------------------------------------------

// TestDockerAJP performs a live integration test against a real Tomcat 9.0.30
// container to confirm that AJP CPing/CPong detection works end-to-end.
func TestDockerAJP(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker integration test in short mode")
	}

	// 1. Connect to Docker daemon.
	dockerPool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %s", err)
	}

	// 2. Start the Tomcat 9.0.30 container (AJP enabled on 0.0.0.0:8009 by default).
	resource, err := dockerPool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "tomcat",
		Tag:          "9.0.30",
		ExposedPorts: []string{"8009/tcp"},
	})
	if err != nil {
		t.Fatalf("could not start tomcat container: %s", err)
	}

	// 3. Conditionally defer container cleanup — default is always purge.
	if os.Getenv("NERVA_KEEP_CONTAINER") == "" {
		defer dockerPool.Purge(resource) //nolint:errcheck
	}

	// 4. Resolve host:port from the container's port mapping.
	hostPort := resource.GetHostPort("8009/tcp")

	// 5. Poll until Tomcat's AJP connector actually responds to CPing, not just accepts TCP.
	var result *plugins.Service
	if retryErr := dockerPool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", hostPort, 5*time.Second)
		if dialErr != nil {
			return dialErr
		}
		defer conn.Close()
		svc, runErr := (&Plugin{}).Run(conn, 5*time.Second, plugins.Target{})
		if runErr != nil {
			return runErr
		}
		if svc == nil {
			return fmt.Errorf("AJP not detected yet (Tomcat still starting)")
		}
		result = svc
		return nil
	}); retryErr != nil {
		t.Fatalf("AJP plugin never detected Tomcat: %s", retryErr)
	}

	// 7. If the user wants to keep the container, print the coordinates.
	if os.Getenv("NERVA_KEEP_CONTAINER") != "" {
		t.Logf("Container name: %s", resource.Container.Name)
		t.Logf("AJP host:port:  %s", hostPort)
		t.Logf("To probe manually: printf '\\x12\\x34\\x00\\x01\\x0a' | nc -w1 %s | xxd", hostPort)
	}

	// 8. Assert results.
	if err != nil {
		t.Fatalf("Plugin.Run() error = %v, want nil", err)
	}
	if result == nil {
		t.Fatal("Plugin.Run() result is nil, want non-nil Service")
	}
	if result.Protocol != plugins.ProtoAJP {
		t.Errorf("result.Protocol = %q, want %q", result.Protocol, plugins.ProtoAJP)
	}

	meta := result.Metadata()
	ajp, ok := meta.(plugins.ServiceAJP)
	if !ok {
		t.Fatalf("Metadata() type = %T, want plugins.ServiceAJP", meta)
	}
	if ajp.ProtocolVersion != "1.3" {
		t.Errorf("ProtocolVersion = %q, want %q", ajp.ProtocolVersion, "1.3")
	}
	if !ajp.CPingEnabled {
		t.Errorf("CPingEnabled = false, want true")
	}
	if len(ajp.CPEs) == 0 || ajp.CPEs[0] != AJPCPEMatch {
		t.Errorf("CPEs = %v, want [%q]", ajp.CPEs, AJPCPEMatch)
	}
	if result.Version != "1.3" {
		t.Errorf("result.Version = %q, want %q", result.Version, "1.3")
	}
}

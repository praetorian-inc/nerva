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

package git

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// helper builds a valid pkt-line encoded line (used to construct test responses).
func makePktLine(data string) []byte {
	return encodePktLine(data + "\n")
}

// flushPkt is the 4-byte flush packet.
var flushPkt = []byte("0000")

// TestEncodePktLine tests pkt-line encoding.
func TestEncodePktLine(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantLen  int
		wantData string
	}{
		{
			name:     "empty string",
			input:    "",
			wantLen:  4,
			wantData: "0004",
		},
		{
			name:     "simple string",
			input:    "hello",
			wantLen:  9,
			wantData: "0009hello",
		},
		{
			name:     "git-upload-pack request",
			input:    "git-upload-pack /test.git\x00host=127.0.0.1\x00",
			wantLen:  4 + len("git-upload-pack /test.git\x00host=127.0.0.1\x00"),
			wantData: "002dgit-upload-pack /test.git\x00host=127.0.0.1\x00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encodePktLine(tt.input)
			assert.Equal(t, tt.wantLen, len(result), "encoded length mismatch")
			assert.Equal(t, tt.wantData, string(result), "encoded content mismatch")
		})
	}
}

// TestDecodePktLine tests pkt-line decoding.
func TestDecodePktLine(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		wantLine      string
		wantConsumed  int
		wantErrSubstr string
	}{
		{
			name:         "normal line",
			input:        []byte("0009hello"),
			wantLine:     "hello",
			wantConsumed: 9,
		},
		{
			name:         "flush packet",
			input:        []byte("0000"),
			wantLine:     "",
			wantConsumed: 4,
		},
		{
			name:         "flush packet with trailing data",
			input:        []byte("0000extra"),
			wantLine:     "",
			wantConsumed: 4,
		},
		{
			name:          "too short",
			input:         []byte("001"),
			wantErrSubstr: "too short",
		},
		{
			name:          "invalid hex",
			input:         []byte("ZZZZ"),
			wantErrSubstr: "invalid pkt-line length hex",
		},
		{
			name:         "ref line with newline",
			input:        []byte("0032" + "da39a3ee5e6b4b0d3255bfef95601890afd80709 HEAD\n"),
			wantLine:     "da39a3ee5e6b4b0d3255bfef95601890afd80709 HEAD\n",
			wantConsumed: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line, consumed, err := decodePktLine(tt.input)
			if tt.wantErrSubstr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrSubstr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantLine, line)
			assert.Equal(t, tt.wantConsumed, consumed)
		})
	}
}

// sha1 is a valid 40-char hex SHA-1 hash used in tests.
const sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

// sha2 is a second valid 40-char hex SHA-1 hash.
const sha2 = "aabbccdd11223344556677889900aabbccddeeff"

// buildRefLine builds a pkt-line encoded ref advertisement line.
func buildRefLine(hash, refName string) []byte {
	return makePktLine(hash + " " + refName)
}

// buildFirstRefLine builds the first ref line with capabilities after NUL.
func buildFirstRefLine(hash, refName, caps string) []byte {
	return encodePktLine(hash + " " + refName + "\x00" + caps + "\n")
}

// TestParseRefAdvertisement tests full ref advertisement parsing.
func TestParseRefAdvertisement(t *testing.T) {
	tests := []struct {
		name            string
		input           []byte
		wantRefs        int
		wantCaps        []string
		wantVersion     int
		wantHeadHash    string
		wantNilRefs     bool
		wantBranchRef   string
		wantTagPresent  bool
	}{
		{
			name: "valid ref advertisement with HEAD, branch, and tag",
			input: append(append(append(append(
				buildFirstRefLine(sha1, "HEAD", "multi_ack side-band-64k ofs-delta"),
				buildRefLine(sha1, "refs/heads/main")...),
				buildRefLine(sha2, "refs/tags/v1.0")...),
				buildRefLine(sha2, "refs/tags/v1.0^{}")...),
				flushPkt...),
			wantRefs:       4, // HEAD + main + v1.0 + v1.0^{} (peeled tag is a separate pkt-line)
			wantCaps:       []string{"multi_ack", "side-band-64k", "ofs-delta"},
			wantVersion:    0,
			wantHeadHash:   sha1,
			wantBranchRef:  "refs/heads/main",
			wantTagPresent: true,
		},
		{
			name: "protocol v1 response",
			input: append(append(append(
				encodePktLine("version 1\n"),
				buildFirstRefLine(sha1, "HEAD", "side-band-64k")...),
				buildRefLine(sha1, "refs/heads/main")...),
				flushPkt...),
			wantRefs:     2,
			wantCaps:     []string{"side-band-64k"},
			wantVersion:  1,
			wantHeadHash: sha1,
		},
		{
			name:        "empty repository - flush only",
			input:       flushPkt,
			wantNilRefs: true,
		},
		{
			name:        "ERR response - access denied",
			input:       encodePktLine("ERR access denied\n"),
			wantNilRefs: true,
		},
		{
			name: "single ref with capabilities",
			input: append(
				buildFirstRefLine(sha1, "HEAD", "delete-refs ofs-delta"),
				flushPkt...),
			wantRefs:     1,
			wantCaps:     []string{"delete-refs", "ofs-delta"},
			wantVersion:  0,
			wantHeadHash: sha1,
		},
		{
			name: "multiple branches and tags",
			input: append(append(append(append(
				buildFirstRefLine(sha1, "HEAD", "multi_ack"),
				buildRefLine(sha1, "refs/heads/main")...),
				buildRefLine(sha2, "refs/heads/develop")...),
				buildRefLine(sha2, "refs/tags/v1.0")...),
				flushPkt...),
			wantRefs:    4,
			wantVersion: 0,
		},
		{
			name: "response with peeled tags",
			input: append(append(append(
				buildFirstRefLine(sha1, "HEAD", "ofs-delta"),
				buildRefLine(sha2, "refs/tags/v1.0")...),
				buildRefLine(sha1, "refs/tags/v1.0^{}")...),
				flushPkt...),
			wantRefs:       3,
			wantTagPresent: true,
		},
		{
			name:        "truncated malformed response",
			input:       []byte("001"),
			wantNilRefs: true,
		},
		{
			name:        "non-git response random bytes",
			input:       []byte("SSH-2.0-OpenSSH_8.2\r\n"),
			wantNilRefs: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			refs, caps, version, err := parseRefAdvertisement(tt.input)

			require.NoError(t, err)

			if tt.wantNilRefs {
				assert.Nil(t, refs, "expected nil refs for non-git response")
				return
			}

			require.NotNil(t, refs, "expected non-nil refs")
			assert.Equal(t, tt.wantRefs, len(refs), "ref count mismatch")
			assert.Equal(t, tt.wantVersion, version, "protocol version mismatch")

			if tt.wantCaps != nil {
				assert.Equal(t, tt.wantCaps, caps, "capabilities mismatch")
			}

			if tt.wantHeadHash != "" {
				found := false
				for _, r := range refs {
					if r.Name == "HEAD" && r.Hash == tt.wantHeadHash {
						found = true
						break
					}
				}
				assert.True(t, found, "HEAD ref with expected hash not found")
			}
		})
	}
}

// TestBuildUploadPackRequest tests the request builder.
func TestBuildUploadPackRequest(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantPfx string
	}{
		{
			name:    "IPv4 host",
			host:    "192.168.1.1",
			wantPfx: "002f",
		},
		{
			name:    "hostname",
			host:    "git.example.com",
			wantPfx: "0033",
		},
		{
			name:    "localhost",
			host:    "localhost",
			wantPfx: "002d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := buildUploadPackRequest(tt.host)
			require.Greater(t, len(req), 4, "request must be longer than 4 bytes")

			// The request must be a valid pkt-line.
			line, consumed, err := decodePktLine(req)
			require.NoError(t, err)
			assert.Equal(t, len(req), consumed, "request should be a single pkt-line")
			assert.Contains(t, line, "git-upload-pack /test.git", "request must contain git-upload-pack path")
			assert.Contains(t, line, "host="+tt.host, "request must contain host")

			// Verify the 4-byte hex prefix.
			assert.Equal(t, tt.wantPfx, string(req[:4]), "pkt-line length prefix mismatch")
		})
	}
}

// TestPluginInterface tests the plugin's interface method implementations.
func TestPluginInterface(t *testing.T) {
	plugin := &TCPPlugin{}

	t.Run("Name", func(t *testing.T) {
		assert.Equal(t, "git", plugin.Name())
	})

	t.Run("Type", func(t *testing.T) {
		assert.Equal(t, plugins.TCP, plugin.Type())
	})

	t.Run("Priority", func(t *testing.T) {
		assert.Equal(t, 2, plugin.Priority())
	})

	t.Run("PortPriority default port", func(t *testing.T) {
		assert.True(t, plugin.PortPriority(9418))
	})

	t.Run("PortPriority non-default ports", func(t *testing.T) {
		for _, port := range []uint16{22, 80, 443, 3690, 8080} {
			assert.False(t, plugin.PortPriority(port), "port %d should not be priority", port)
		}
	})
}

// TestRun tests the Run() method using net.Pipe() for mock connections.
func TestRun(t *testing.T) {
	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:9418"),
		Host:    "127.0.0.1",
	}

	t.Run("valid ref advertisement", func(t *testing.T) {
		// Build a mock git daemon response.
		mockResponse := append(append(append(
			buildFirstRefLine(sha1, "HEAD", "multi_ack side-band-64k ofs-delta"),
			buildRefLine(sha1, "refs/heads/main")...),
			buildRefLine(sha2, "refs/tags/v1.0")...),
			flushPkt...)

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		// Server goroutine: read request, send response.
		go func() {
			buf := make([]byte, 512)
			serverConn.SetDeadline(time.Now().Add(2 * time.Second))
			n, _ := serverConn.Read(buf)
			_ = n // consume the client request
			serverConn.Write(mockResponse)
			serverConn.Close()
		}()

		plugin := &TCPPlugin{}
		service, err := plugin.Run(clientConn, 2*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service, "expected service result for valid git response")
		assert.Equal(t, "git", service.Protocol)
		assert.Equal(t, "127.0.0.1", service.IP)
		assert.Equal(t, 9418, service.Port)

		// Verify metadata.
		metadata := service.Metadata()
		gitMeta, ok := metadata.(plugins.ServiceGit)
		require.True(t, ok, "metadata should be ServiceGit")
		assert.Equal(t, sha1, gitMeta.HeadRef, "HEAD ref hash mismatch")
		assert.Contains(t, gitMeta.Branches, "main")
		assert.Contains(t, gitMeta.Tags, "v1.0")
		assert.Contains(t, gitMeta.Capabilities, "multi_ack")
	})

	t.Run("connection closed without data returns nil service", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		// Server reads request then closes connection without sending a response.
		// This produces an EOF in Recv(), which the plugin propagates as an error.
		// This is expected behavior — not a git daemon.
		go func() {
			buf := make([]byte, 512)
			serverConn.SetDeadline(time.Now().Add(2 * time.Second))
			serverConn.Read(buf)
			serverConn.Close()
		}()

		plugin := &TCPPlugin{}
		service, err := plugin.Run(clientConn, 2*time.Second, target)

		// An EOF on immediate close is a ReadError from pluginutils.Recv.
		// The service should always be nil for non-git connections.
		assert.Nil(t, service, "closed connection should yield nil service")
		_ = err // May be nil or ReadError depending on timing; service must be nil.
	})

	t.Run("flush-only response returns nil", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		go func() {
			buf := make([]byte, 512)
			serverConn.SetDeadline(time.Now().Add(2 * time.Second))
			serverConn.Read(buf)
			serverConn.Write(flushPkt)
			serverConn.Close()
		}()

		plugin := &TCPPlugin{}
		service, err := plugin.Run(clientConn, 2*time.Second, target)

		require.NoError(t, err)
		assert.Nil(t, service, "flush-only response should yield nil service")
	})

	t.Run("ERR response returns nil", func(t *testing.T) {
		errResponse := encodePktLine("ERR Repository not found\n")

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		go func() {
			buf := make([]byte, 512)
			serverConn.SetDeadline(time.Now().Add(2 * time.Second))
			serverConn.Read(buf)
			serverConn.Write(errResponse)
			serverConn.Close()
		}()

		plugin := &TCPPlugin{}
		service, err := plugin.Run(clientConn, 2*time.Second, target)

		require.NoError(t, err)
		assert.Nil(t, service, "ERR response should yield nil service")
	})

	t.Run("non-git response returns nil", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		go func() {
			buf := make([]byte, 512)
			serverConn.SetDeadline(time.Now().Add(2 * time.Second))
			serverConn.Read(buf)
			serverConn.Write([]byte("SSH-2.0-OpenSSH_8.2\r\n"))
			serverConn.Close()
		}()

		plugin := &TCPPlugin{}
		service, err := plugin.Run(clientConn, 2*time.Second, target)

		require.NoError(t, err)
		assert.Nil(t, service, "non-git response should yield nil service")
	})
}

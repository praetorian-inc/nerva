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

package qdrant

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestExtractVersionFromString(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantVersion string
	}{
		{
			name:        "standard version",
			body:        `{"title":"qdrant","version":"1.7.4"}`,
			wantVersion: "1.7.4",
		},
		{
			name:        "version with v prefix",
			body:        `{"title":"qdrant","version":"v1.7.4"}`,
			wantVersion: "1.7.4",
		},
		{
			name:        "version with pre-release",
			body:        `{"title":"qdrant","version":"1.7.4-beta"}`,
			wantVersion: "1.7.4-beta",
		},
		{
			name:        "no version",
			body:        `{"title":"qdrant"}`,
			wantVersion: "",
		},
		{
			name:        "empty body",
			body:        "",
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractVersionFromString(tt.body)
			if result != tt.wantVersion {
				t.Errorf("extractVersionFromString() = %q, want %q", result, tt.wantVersion)
			}
		})
	}
}

func TestBuildQdrantCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantCPE string
	}{
		{
			name:    "standard version",
			version: "1.7.4",
			wantCPE: "cpe:2.3:a:qdrant:qdrant:1.7.4:*:*:*:*:*:*:*",
		},
		{
			name:    "unknown version",
			version: "",
			wantCPE: "cpe:2.3:a:qdrant:qdrant:*:*:*:*:*:*:*:*",
		},
		{
			name:    "version with pre-release",
			version: "1.7.4-beta",
			wantCPE: "cpe:2.3:a:qdrant:qdrant:1.7.4-beta:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildQdrantCPE(tt.version)
			if result != tt.wantCPE {
				t.Errorf("buildQdrantCPE() = %q, want %q", result, tt.wantCPE)
			}
		})
	}
}

func TestQdrantPluginInterface(t *testing.T) {
	plugin := &QdrantPlugin{}

	t.Run("Name", func(t *testing.T) {
		if name := plugin.Name(); name != QDRANT {
			t.Errorf("Name() = %q, want %q", name, QDRANT)
		}
	})

	t.Run("Type", func(t *testing.T) {
		if pluginType := plugin.Type(); pluginType != plugins.TCP {
			t.Errorf("Type() = %v, want TCP", pluginType)
		}
	})

	t.Run("Priority", func(t *testing.T) {
		if priority := plugin.Priority(); priority != 50 {
			t.Errorf("Priority() = %d, want 50", priority)
		}
	})

	t.Run("PortPriority default port 6333", func(t *testing.T) {
		if !plugin.PortPriority(6333) {
			t.Error("PortPriority(6333) = false, want true")
		}
	})

	t.Run("PortPriority non-default port", func(t *testing.T) {
		if plugin.PortPriority(8080) {
			t.Error("PortPriority(8080) = true, want false")
		}
	})
}

// TestDetectQdrant_Integration tests the full DetectQdrant function with mock HTTP server
func TestDetectQdrant_Integration(t *testing.T) {
	tests := []struct {
		name         string
		response     string
		statusCode   int
		wantDetected bool
		wantVersion  string
	}{
		{
			name:         "valid qdrant JSON response",
			response:     `{"title":"qdrant - vector search engine","version":"1.7.4"}`,
			statusCode:   http.StatusOK,
			wantDetected: true,
			wantVersion:  "1.7.4",
		},
		{
			name:         "qdrant without version",
			response:     `{"title":"qdrant - vector search engine"}`,
			statusCode:   http.StatusOK,
			wantDetected: true,
			wantVersion:  "",
		},
		{
			name:         "non-qdrant JSON response",
			response:     `{"title":"other service","version":"1.0.0"}`,
			statusCode:   http.StatusOK,
			wantDetected: false,
			wantVersion:  "",
		},
		{
			name:         "non-qdrant service",
			response:     `{"status":"ok"}`,
			statusCode:   http.StatusOK,
			wantDetected: false,
			wantVersion:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			// Parse server address
			addr := strings.TrimPrefix(server.URL, "http://")
			host, portStr, _ := net.SplitHostPort(addr)
			port, _ := strconv.Atoi(portStr)

			// Create connection to test server
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Fatalf("Failed to connect to test server: %v", err)
			}
			defer conn.Close()

			// Create target
			ip := net.ParseIP(host)
			if ip == nil {
				ip = net.ParseIP("127.0.0.1")
			}
			netAddr, _ := netip.AddrFromSlice(ip.To4())
			target := plugins.Target{
				Address: netip.AddrPortFrom(netAddr, uint16(port)),
			}

			// Call DetectQdrant
			version, detected, _ := DetectQdrant(conn, 5*time.Second, target)

			if detected != tt.wantDetected {
				t.Errorf("DetectQdrant() detected = %v, want %v", detected, tt.wantDetected)
			}
			if version != tt.wantVersion {
				t.Errorf("DetectQdrant() version = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

// TestDetectQdrant_FallbackStringMatch tests the fallback detection when JSON parsing fails
func TestDetectQdrant_FallbackStringMatch(t *testing.T) {
	tests := []struct {
		name         string
		response     string
		wantDetected bool
		wantVersion  string
	}{
		{
			name:         "non-JSON response containing qdrant",
			response:     `<html><body>Welcome to Qdrant vector database</body></html>`,
			wantDetected: true,
			wantVersion:  "",
		},
		{
			name:         "non-JSON with version in text",
			response:     `Qdrant server "version":"1.8.0" running`,
			wantDetected: true,
			wantVersion:  "1.8.0",
		},
		{
			name:         "non-JSON without qdrant mention",
			response:     `<html><body>Welcome to our service</body></html>`,
			wantDetected: false,
			wantVersion:  "",
		},
		{
			name:         "malformed JSON with qdrant",
			response:     `{"title": "qdrant", invalid json here`,
			wantDetected: true,
			wantVersion:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			// Parse server address
			addr := strings.TrimPrefix(server.URL, "http://")
			host, portStr, _ := net.SplitHostPort(addr)
			port, _ := strconv.Atoi(portStr)

			// Create connection to test server
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Fatalf("Failed to connect to test server: %v", err)
			}
			defer conn.Close()

			// Create target
			ip := net.ParseIP(host)
			if ip == nil {
				ip = net.ParseIP("127.0.0.1")
			}
			netAddr, _ := netip.AddrFromSlice(ip.To4())
			target := plugins.Target{
				Address: netip.AddrPortFrom(netAddr, uint16(port)),
			}

			// Call DetectQdrant
			version, detected, _ := DetectQdrant(conn, 5*time.Second, target)

			if detected != tt.wantDetected {
				t.Errorf("DetectQdrant() detected = %v, want %v", detected, tt.wantDetected)
			}
			if version != tt.wantVersion {
				t.Errorf("DetectQdrant() version = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

func TestDetectQdrant_CPEInjection(t *testing.T) {
	tests := []struct {
		name        string
		response    string
		wantVersion string // empty means version should be rejected
	}{
		{
			name:        "CPE injection attempt with colon",
			response:    `{"title":"qdrant - vector search engine","version":"1.0.0:*:*:malicious"}`,
			wantVersion: "",
		},
		{
			name:        "CPE injection with special characters",
			response:    `{"title":"qdrant - vector search engine","version":"1.0.0;rm -rf /"}`,
			wantVersion: "",
		},
		{
			name:        "command injection attempt",
			response:    `{"title":"qdrant - vector search engine","version":"1.0.0$(whoami)"}`,
			wantVersion: "",
		},
		{
			name:        "path traversal attempt",
			response:    `{"title":"qdrant - vector search engine","version":"../../etc/passwd"}`,
			wantVersion: "",
		},
		{
			name:        "valid version with pre-release",
			response:    `{"title":"qdrant - vector search engine","version":"1.7.4-beta"}`,
			wantVersion: "1.7.4-beta",
		},
		{
			name:        "valid standard version",
			response:    `{"title":"qdrant - vector search engine","version":"1.7.4"}`,
			wantVersion: "1.7.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			addr := strings.TrimPrefix(server.URL, "http://")
			host, portStr, _ := net.SplitHostPort(addr)
			port, _ := strconv.Atoi(portStr)

			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Fatalf("Failed to connect to test server: %v", err)
			}
			defer conn.Close()

			ip := net.ParseIP(host)
			if ip == nil {
				ip = net.ParseIP("127.0.0.1")
			}
			netAddr, _ := netip.AddrFromSlice(ip.To4())
			target := plugins.Target{
				Address: netip.AddrPortFrom(netAddr, uint16(port)),
			}

			version, detected, _ := DetectQdrant(conn, 5*time.Second, target)

			// Should always detect qdrant (title matches)
			if !detected {
				t.Error("DetectQdrant() should detect qdrant even with invalid version")
			}

			if version != tt.wantVersion {
				t.Errorf("DetectQdrant() version = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

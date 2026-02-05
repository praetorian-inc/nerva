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

package zookeeper

import (
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

func TestZooKeeper(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "zookeeper with version extraction",
			Port:        2181,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				if res == nil {
					t.Error("expected Service, got nil")
					return false
				}

				// After fix: DetectZooKeeper now sends "srvr" first (instead of "ruok")
				// This avoids the connection-closing issue and extracts version in one request
				// Version should be successfully extracted from the srvr response
				if res.Version == "" {
					t.Error("expected version to be extracted, got empty string")
					return false
				}

				t.Logf("Successfully detected ZooKeeper version: %s", res.Version)
				return true
			},
			RunConfig: dockertest.RunOptions{
				Repository: "zookeeper",
			},
		},
	}

	p := &ZooKeeperPlugin{}

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

// TestDetectZooKeeper tests ruok -> imok detection
func TestDetectZooKeeper(t *testing.T) {
	tests := []struct {
		name       string
		response   []byte
		shouldFail bool
	}{
		{
			name:       "valid imok response",
			response:   []byte("imok"),
			shouldFail: false,
		},
		{
			name:       "empty response",
			response:   []byte{},
			shouldFail: true,
		},
		{
			name:       "invalid response",
			response:   []byte("invalid"),
			shouldFail: true,
		},
		{
			name:       "whitelist restriction",
			response:   []byte("ruok is not in the whitelist"),
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkZooKeeper(tt.response)
			if tt.shouldFail && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.shouldFail && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestExtractZooKeeperVersion tests version extraction from srvr response
func TestExtractZooKeeperVersion(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     string
	}{
		{
			name: "standard srvr response with version",
			response: "Zookeeper version: 3.8.0-5a02a05eddb59aee6ac762f7ea82e92a68eb9c0f, built on 2022-02-25 08:49 UTC\n" +
				"Latency min/avg/max: 0/0/0\n" +
				"Received: 100\n" +
				"Sent: 99\n" +
				"Connections: 1\n" +
				"Outstanding: 0\n" +
				"Zxid: 0x100\n" +
				"Mode: standalone\n" +
				"Node count: 5\n",
			want: "3.8.0",
		},
		{
			name: "version 3.7.x",
			response: "Zookeeper version: 3.7.1-1, built on 01/01/2024 00:00 GMT\n" +
				"Mode: follower\n",
			want: "3.7.1",
		},
		{
			name: "version 3.6.x",
			response: "Zookeeper version: 3.6.3\n" +
				"Mode: leader\n",
			want: "3.6.3",
		},
		{
			name:     "empty response",
			response: "",
			want:     "",
		},
		{
			name: "missing version field",
			response: "Mode: standalone\n" +
				"Node count: 5\n",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractZooKeeperVersion(tt.response)
			if got != tt.want {
				t.Errorf("extractZooKeeperVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestExtractZooKeeperMode tests mode extraction from srvr response
func TestExtractZooKeeperMode(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     string
	}{
		{
			name: "standalone mode",
			response: "Zookeeper version: 3.8.0\n" +
				"Mode: standalone\n",
			want: "standalone",
		},
		{
			name: "leader mode",
			response: "Mode: leader\n" +
				"Connections: 5\n",
			want: "leader",
		},
		{
			name: "follower mode",
			response: "Mode: follower\n",
			want: "follower",
		},
		{
			name: "observer mode",
			response: "Mode: observer\n",
			want: "observer",
		},
		{
			name:     "empty response",
			response: "",
			want:     "",
		},
		{
			name: "missing mode field",
			response: "Zookeeper version: 3.8.0\n" +
				"Connections: 1\n",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractZooKeeperMode(tt.response)
			if got != tt.want {
				t.Errorf("extractZooKeeperMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestExtractZooKeeperConnections tests connections extraction from srvr response
func TestExtractZooKeeperConnections(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     int
	}{
		{
			name: "with connections",
			response: "Zookeeper version: 3.8.0\n" +
				"Connections: 5\n",
			want: 5,
		},
		{
			name: "zero connections",
			response: "Connections: 0\n" +
				"Mode: standalone\n",
			want: 0,
		},
		{
			name: "single connection",
			response: "Connections: 1\n",
			want: 1,
		},
		{
			name:     "empty response",
			response: "",
			want:     0,
		},
		{
			name: "missing connections field",
			response: "Mode: standalone\n" +
				"Node count: 5\n",
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractZooKeeperConnections(tt.response)
			if got != tt.want {
				t.Errorf("extractZooKeeperConnections() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestExtractZooKeeperNodeCount tests node count extraction from srvr response
func TestExtractZooKeeperNodeCount(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     int
	}{
		{
			name: "with node count",
			response: "Zookeeper version: 3.8.0\n" +
				"Node count: 42\n",
			want: 42,
		},
		{
			name: "zero nodes",
			response: "Node count: 0\n" +
				"Mode: standalone\n",
			want: 0,
		},
		{
			name: "single node",
			response: "Node count: 1\n",
			want: 1,
		},
		{
			name:     "empty response",
			response: "",
			want:     0,
		},
		{
			name: "missing node count field",
			response: "Mode: standalone\n" +
				"Connections: 5\n",
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractZooKeeperNodeCount(tt.response)
			if got != tt.want {
				t.Errorf("extractZooKeeperNodeCount() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestBuildZooKeeperCPE tests CPE generation for ZooKeeper servers
func TestBuildZooKeeperCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "specific version",
			version: "3.8.0",
			want:    "cpe:2.3:a:apache:zookeeper:3.8.0:*:*:*:*:*:*:*",
		},
		{
			name:    "version 3.7.x",
			version: "3.7.1",
			want:    "cpe:2.3:a:apache:zookeeper:3.7.1:*:*:*:*:*:*:*",
		},
		{
			name:    "version 3.6.x",
			version: "3.6.3",
			want:    "cpe:2.3:a:apache:zookeeper:3.6.3:*:*:*:*:*:*:*",
		},
		{
			name:    "unknown version (wildcard)",
			version: "",
			want:    "cpe:2.3:a:apache:zookeeper:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildZooKeeperCPE(tt.version)
			if got != tt.want {
				t.Errorf("buildZooKeeperCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestCheckWhitelistRestriction tests detection of whitelist restrictions
func TestCheckWhitelistRestriction(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		restricted bool
	}{
		{
			name:       "not executed message",
			response:   "ruok is not executed because it is not in the whitelist",
			restricted: true,
		},
		{
			name:       "not in whitelist message",
			response:   "ruok is not in the whitelist",
			restricted: true,
		},
		{
			name:       "normal response",
			response:   "Zookeeper version: 3.8.0",
			restricted: false,
		},
		{
			name:       "empty response",
			response:   "",
			restricted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkWhitelistRestriction(tt.response)
			if got != tt.restricted {
				t.Errorf("checkWhitelistRestriction() = %v, want %v", got, tt.restricted)
			}
		})
	}
}

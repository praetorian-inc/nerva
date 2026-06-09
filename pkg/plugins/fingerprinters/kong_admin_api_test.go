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

package fingerprinters

import (
	"net/http"
	"testing"
)

func TestKongAdminAPIFingerprinter_Name(t *testing.T) {
	fp := &KongAdminAPIFingerprinter{}
	if got := fp.Name(); got != "kong" {
		t.Errorf("Name() = %q, want %q", got, "kong")
	}
}

func TestKongAdminAPIFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "application/json returns true",
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "application/json; charset=utf-8 returns true",
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "text/html returns false",
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "no Content-Type returns false",
			contentType: "",
			want:        false,
		},
		{
			name:        "Application/JSON mixed case returns true",
			contentType: "Application/JSON",
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &KongAdminAPIFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Trimmed fixture from the live Kong 3.6.1 DB-less container capture.
// Preserves the structurally significant fields; irrelevant nginx/ssl
// configuration is omitted to keep the fixture readable.
var kongRoot361DBless = []byte(`{
	"node_id": "182137f6-2f37-4a2c-b8fa-632c5b20895a",
	"version": "3.6.1",
	"tagline": "Welcome to kong",
	"hostname": "31a52776da56",
	"lua_version": "LuaJIT 2.1.0-20231117",
	"configuration": {
		"database": "off"
	},
	"plugins": {
		"available_on_server": {
			"request-transformer": {"version": "3.6.1", "priority": 801},
			"rate-limiting":       {"version": "3.6.1", "priority": 910},
			"jwt":                 {"version": "3.6.1", "priority": 1450},
			"acl":                 {"version": "3.6.1", "priority": 950},
			"cors":                {"version": "3.6.1", "priority": 2000},
			"basic-auth":          {"version": "3.6.1", "priority": 1100}
		},
		"enabled_in_cluster": []
	}
}`)

var kongRoot361Postgres = []byte(`{
	"node_id": "aaaabbbb-cccc-dddd-eeee-ffffffffffff",
	"version": "3.6.1",
	"tagline": "Welcome to kong",
	"hostname": "kong-db-host",
	"lua_version": "LuaJIT 2.1.0-20231117",
	"configuration": {
		"database": "postgres"
	},
	"plugins": {
		"available_on_server": {
			"key-auth":   {"version": "3.6.1", "priority": 1250},
			"rate-limiting": {"version": "3.6.1", "priority": 910}
		},
		"enabled_in_cluster": []
	}
}`)

var kongEnterpriseVersion = []byte(`{
	"node_id": "deadbeef-0000-1111-2222-333333333333",
	"version": "3.4.3.2",
	"tagline": "Welcome to kong",
	"hostname": "kong-enterprise",
	"lua_version": "LuaJIT 2.1.0-20231117",
	"configuration": {
		"database": "postgres"
	},
	"plugins": {
		"available_on_server": {
			"oauth2": {"version": "3.4.3.2", "priority": 1400}
		},
		"enabled_in_cluster": []
	}
}`)

func TestKongAdminAPIFingerprinter_Fingerprint_Positive(t *testing.T) {
	tests := []struct {
		name            string
		body            []byte
		wantVersion     string
		wantCPE         string
		wantDatabase    string
		wantPluginCount int
		wantSortedFirst string // first plugin name alphabetically
	}{
		{
			name:            "Kong 3.6.1 DB-less",
			body:            kongRoot361DBless,
			wantVersion:     "3.6.1",
			wantCPE:         "cpe:2.3:a:konghq:kong:3.6.1:*:*:*:*:*:*:*",
			wantDatabase:    "off",
			wantPluginCount: 6,
			wantSortedFirst: "acl",
		},
		{
			name:            "Kong 3.6.1 postgres DB mode",
			body:            kongRoot361Postgres,
			wantVersion:     "3.6.1",
			wantCPE:         "cpe:2.3:a:konghq:kong:3.6.1:*:*:*:*:*:*:*",
			wantDatabase:    "postgres",
			wantPluginCount: 2,
			wantSortedFirst: "key-auth",
		},
		{
			name:            "Kong enterprise 4-part version 3.4.3.2",
			body:            kongEnterpriseVersion,
			wantVersion:     "3.4.3.2",
			wantCPE:         "cpe:2.3:a:konghq:kong:3.4.3.2:*:*:*:*:*:*:*",
			wantDatabase:    "postgres",
			wantPluginCount: 1,
			wantSortedFirst: "oauth2",
		},
		{
			name: "Kong 2-part version 3.6",
			body: []byte(`{
				"version": "3.6",
				"tagline": "Welcome to kong",
				"hostname": "host",
				"configuration": {"database": "off"},
				"plugins": {"available_on_server": {}}
			}`),
			wantVersion:     "3.6",
			wantCPE:         "cpe:2.3:a:konghq:kong:3.6:*:*:*:*:*:*:*",
			wantDatabase:    "off",
			wantPluginCount: 0,
		},
		{
			name: "Valid Kong tagline+version but malformed version string",
			body: []byte(`{
				"version": "v3.6abc",
				"tagline": "Welcome to kong",
				"hostname": "host",
				"configuration": {"database": "off"},
				"plugins": {"available_on_server": {}}
			}`),
			wantVersion:     "*",
			wantCPE:         "cpe:2.3:a:konghq:kong:*:*:*:*:*:*:*:*",
			wantDatabase:    "off",
			wantPluginCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &KongAdminAPIFingerprinter{}
			resp := &http.Response{}

			result, err := fp.Fingerprint(resp, tt.body)
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want result")
			}

			if result.Technology != "kong" {
				t.Errorf("Technology = %q, want %q", result.Technology, "kong")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if len(result.CPEs) != 1 {
				t.Fatalf("CPEs count = %d, want 1", len(result.CPEs))
			}
			if result.CPEs[0] != tt.wantCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], tt.wantCPE)
			}

			// Metadata checks
			if db, ok := result.Metadata["database"].(string); !ok || db != tt.wantDatabase {
				t.Errorf("Metadata database = %q, want %q", db, tt.wantDatabase)
			}

			if tt.wantPluginCount > 0 {
				pluginCount, ok := result.Metadata["plugin_count"].(int)
				if !ok {
					t.Errorf("Metadata plugin_count not present or wrong type")
				} else if pluginCount != tt.wantPluginCount {
					t.Errorf("Metadata plugin_count = %d, want %d", pluginCount, tt.wantPluginCount)
				}

				plugins, ok := result.Metadata["plugins"].([]string)
				if !ok {
					t.Errorf("Metadata plugins not present or wrong type")
				} else {
					if len(plugins) != tt.wantPluginCount {
						t.Errorf("plugins slice length = %d, want %d", len(plugins), tt.wantPluginCount)
					}
					// Verify sorted: first element must match expected
					if tt.wantSortedFirst != "" && len(plugins) > 0 && plugins[0] != tt.wantSortedFirst {
						t.Errorf("plugins[0] = %q, want %q (expected sorted ascending)", plugins[0], tt.wantSortedFirst)
					}
					// Verify ascending sort across whole slice
					for i := 1; i < len(plugins); i++ {
						if plugins[i] < plugins[i-1] {
							t.Errorf("plugins not sorted: plugins[%d]=%q < plugins[%d]=%q", i, plugins[i], i-1, plugins[i-1])
						}
					}
				}
			} else {
				// Empty plugin map: keys must not be present
				if _, ok := result.Metadata["plugins"]; ok {
					t.Errorf("plugins key present when plugin map was empty, should be absent")
				}
				if _, ok := result.Metadata["plugin_count"]; ok {
					t.Errorf("plugin_count key present when plugin map was empty, should be absent")
				}
			}

			if len(result.SecurityFindings) != 0 {
				t.Errorf("SecurityFindings = %v, want empty", result.SecurityFindings)
			}
		})
	}
}

func TestKongAdminAPIFingerprinter_Fingerprint_Negative(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{
			name: "generic JSON API without tagline",
			body: []byte(`{"name":"some-api","version":"1.0.0","status":"ok"}`),
		},
		{
			name: "tagline present but wrong service",
			body: []byte(`{"tagline":"Welcome to nginx","version":"1.24.0"}`),
		},
		{
			name: "Kong tagline present but version empty",
			body: []byte(`{"tagline":"Welcome to kong","version":"","configuration":{"database":"off"}}`),
		},
		{
			name: "Kong tagline present but version missing",
			body: []byte(`{"tagline":"Welcome to kong","configuration":{"database":"off"}}`),
		},
		{
			name: "malformed JSON body",
			body: []byte(`{this is not valid json`),
		},
		{
			name: "empty body",
			body: []byte(``),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &KongAdminAPIFingerprinter{}
			resp := &http.Response{}

			result, err := fp.Fingerprint(resp, tt.body)
			if err != nil {
				t.Fatalf("Fingerprint() error = %v, want nil", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil for non-Kong input", result)
			}
		})
	}
}

func TestKongAdminAPIFingerprinter_PluginSorting(t *testing.T) {
	// Feed keys in a non-alphabetical JSON order; expect sorted output.
	body := []byte(`{
		"version": "3.6.1",
		"tagline": "Welcome to kong",
		"hostname": "host",
		"configuration": {"database": "off"},
		"plugins": {
			"available_on_server": {
				"zipkin":       {"version": "3.6.1", "priority": 100000},
				"acl":          {"version": "3.6.1", "priority": 950},
				"rate-limiting":{"version": "3.6.1", "priority": 910},
				"basic-auth":   {"version": "3.6.1", "priority": 1100},
				"cors":         {"version": "3.6.1", "priority": 2000}
			}
		}
	}`)

	fp := &KongAdminAPIFingerprinter{}
	result, err := fp.Fingerprint(&http.Response{}, body)
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}

	plugins, ok := result.Metadata["plugins"].([]string)
	if !ok {
		t.Fatal("plugins metadata not present or wrong type")
	}

	want := []string{"acl", "basic-auth", "cors", "rate-limiting", "zipkin"}
	if len(plugins) != len(want) {
		t.Fatalf("plugins length = %d, want %d", len(plugins), len(want))
	}
	for i, p := range want {
		if plugins[i] != p {
			t.Errorf("plugins[%d] = %q, want %q", i, plugins[i], p)
		}
	}
}

func TestBuildKongCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "OSS 3-part version",
			version: "3.6.1",
			want:    "cpe:2.3:a:konghq:kong:3.6.1:*:*:*:*:*:*:*",
		},
		{
			name:    "Enterprise 4-part version",
			version: "3.4.3.2",
			want:    "cpe:2.3:a:konghq:kong:3.4.3.2:*:*:*:*:*:*:*",
		},
		{
			name:    "wildcard version",
			version: "*",
			want:    "cpe:2.3:a:konghq:kong:*:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version",
			version: "",
			want:    "cpe:2.3:a:konghq:kong:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildKongCPE(tt.version); got != tt.want {
				t.Errorf("buildKongCPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

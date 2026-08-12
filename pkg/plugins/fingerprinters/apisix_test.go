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

func TestAPISIXFingerprinter_Name(t *testing.T) {
	fp := &APISIXFingerprinter{}
	if got := fp.Name(); got != "apisix" {
		t.Errorf("Name() = %q, want %q", got, "apisix")
	}
}

func TestAPISIXFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name         string
		serverHeader string
		setHeader    bool
		want         bool
	}{
		{
			name:         "APISIX/3.9.0 returns true",
			serverHeader: "APISIX/3.9.0",
			setHeader:    true,
			want:         true,
		},
		{
			name:         "APISIX with no version returns true",
			serverHeader: "APISIX",
			setHeader:    true,
			want:         true,
		},
		{
			name:         "apisix/2.0.0 lowercase returns true",
			serverHeader: "apisix/2.0.0",
			setHeader:    true,
			want:         true,
		},
		{
			name:         "nginx returns false",
			serverHeader: "nginx",
			setHeader:    true,
			want:         false,
		},
		{
			name:         "kong/3.6.1 returns false",
			serverHeader: "kong/3.6.1",
			setHeader:    true,
			want:         false,
		},
		{
			name:         "empty Server header returns false",
			serverHeader: "",
			setHeader:    true,
			want:         false,
		},
		{
			name:      "no Server header returns false",
			setHeader: false,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &APISIXFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			if tt.setHeader {
				resp.Header.Set("Server", tt.serverHeader)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAPISIXFingerprinter_Fingerprint_Positive(t *testing.T) {
	tests := []struct {
		name         string
		serverHeader string
		wantVersion  string
		wantCPE      string
	}{
		{
			name:         "APISIX 3.9.0",
			serverHeader: "APISIX/3.9.0",
			wantVersion:  "3.9.0",
			wantCPE:      "cpe:2.3:a:apache:apisix:3.9.0:*:*:*:*:*:*:*",
		},
		{
			name:         "APISIX 2.15.3",
			serverHeader: "APISIX/2.15.3",
			wantVersion:  "2.15.3",
			wantCPE:      "cpe:2.3:a:apache:apisix:2.15.3:*:*:*:*:*:*:*",
		},
		{
			name:         "APISIX with no version",
			serverHeader: "APISIX",
			wantVersion:  "*",
			wantCPE:      "cpe:2.3:a:apache:apisix:*:*:*:*:*:*:*:*",
		},
		{
			name:         "APISIX with invalid version",
			serverHeader: "APISIX/abc",
			wantVersion:  "*",
			wantCPE:      "cpe:2.3:a:apache:apisix:*:*:*:*:*:*:*:*",
		},
		{
			name:         "lowercase apisix/2.0.0",
			serverHeader: "apisix/2.0.0",
			wantVersion:  "2.0.0",
			wantCPE:      "cpe:2.3:a:apache:apisix:2.0.0:*:*:*:*:*:*:*",
		},
		{
			name:         "APISIX with pre-release version suffix",
			serverHeader: "APISIX/3.9.0-rc1",
			wantVersion:  "*",
			wantCPE:      "cpe:2.3:a:apache:apisix:*:*:*:*:*:*:*:*",
		},
		{
			name:         "APISIX with leading/trailing whitespace",
			serverHeader: "  APISIX/3.9.0  ",
			wantVersion:  "3.9.0",
			wantCPE:      "cpe:2.3:a:apache:apisix:3.9.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &APISIXFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			resp.Header.Set("Server", tt.serverHeader)

			result, err := fp.Fingerprint(resp, nil)
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want result")
			}

			if result.Technology != "apisix" {
				t.Errorf("Technology = %q, want %q", result.Technology, "apisix")
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
			if got, ok := result.Metadata["server_header"].(string); !ok || got != tt.serverHeader {
				t.Errorf("Metadata server_header = %q, want %q", got, tt.serverHeader)
			}
			if len(result.SecurityFindings) != 0 {
				t.Errorf("SecurityFindings = %v, want empty", result.SecurityFindings)
			}
			if result.Severity != "" {
				t.Errorf("Severity = %q, want empty (detection-only fingerprinter emits no security finding)", result.Severity)
			}
		})
	}
}

func TestAPISIXFingerprinter_Fingerprint_Negative(t *testing.T) {
	tests := []struct {
		name         string
		serverHeader string
		setHeader    bool
	}{
		{
			name:         "nginx",
			serverHeader: "nginx/1.24.0",
			setHeader:    true,
		},
		{
			name:         "openresty",
			serverHeader: "openresty",
			setHeader:    true,
		},
		{
			name:         "kong",
			serverHeader: "kong/3.6.1",
			setHeader:    true,
		},
		{
			name:         "empty Server header",
			serverHeader: "",
			setHeader:    true,
		},
		{
			name:      "no Server header at all",
			setHeader: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &APISIXFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			if tt.setHeader {
				resp.Header.Set("Server", tt.serverHeader)
			}

			result, err := fp.Fingerprint(resp, nil)
			if err != nil {
				t.Fatalf("Fingerprint() error = %v, want nil", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil for non-APISIX input", result)
			}
		})
	}
}

func TestBuildAPISIXCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "3-part version",
			version: "3.9.0",
			want:    "cpe:2.3:a:apache:apisix:3.9.0:*:*:*:*:*:*:*",
		},
		{
			name:    "wildcard version",
			version: "*",
			want:    "cpe:2.3:a:apache:apisix:*:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version",
			version: "",
			want:    "cpe:2.3:a:apache:apisix:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildAPISIXCPE(tt.version); got != tt.want {
				t.Errorf("buildAPISIXCPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

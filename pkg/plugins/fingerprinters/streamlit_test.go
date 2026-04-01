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

func TestStreamlitFingerprinter_Name(t *testing.T) {
	fp := &StreamlitFingerprinter{}
	if got := fp.Name(); got != "streamlit" {
		t.Errorf("Name() = %q, want %q", got, "streamlit")
	}
}

func TestStreamlitFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &StreamlitFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/_stcore/health" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/_stcore/health")
	}
}

func TestStreamlitFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "Content-Type: text/html returns true",
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "Content-Type: text/html; charset=UTF-8 returns true",
			contentType: "text/html; charset=UTF-8",
			want:        true,
		},
		{
			name:        "Content-Type: application/json returns false",
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "No Content-Type header returns false",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &StreamlitFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}

			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStreamlitFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		serverHeader   string
		wantServerMeta string
	}{
		{
			name:           "Exact ok body without Server header",
			body:           "ok",
			serverHeader:   "",
			wantServerMeta: "",
		},
		{
			name:           "ok body with TornadoServer header",
			body:           "ok",
			serverHeader:   "TornadoServer/6.4.1",
			wantServerMeta: "TornadoServer/6.4.1",
		},
		{
			name:           "ok body with trailing newline",
			body:           "ok\n",
			serverHeader:   "",
			wantServerMeta: "",
		},
		{
			name:           "ok body with surrounding whitespace",
			body:           "  ok  ",
			serverHeader:   "",
			wantServerMeta: "",
		},
		{
			name:           "ok body with nginx as reverse proxy (no TornadoServer)",
			body:           "ok",
			serverHeader:   "nginx/1.24.0",
			wantServerMeta: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &StreamlitFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html; charset=UTF-8")
			if tt.serverHeader != "" {
				resp.Header.Set("Server", tt.serverHeader)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "streamlit" {
				t.Errorf("Technology = %q, want %q", result.Technology, "streamlit")
			}
			if result.Version != "" {
				t.Errorf("Version = %q, want empty string (Streamlit does not expose version via health endpoint)", result.Version)
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := "cpe:2.3:a:streamlit:streamlit:*:*:*:*:*:*:*:*"
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}

			// Check server metadata
			if tt.wantServerMeta != "" {
				if server, ok := result.Metadata["server"].(string); !ok || server != tt.wantServerMeta {
					t.Errorf("Metadata[server] = %v, want %q", result.Metadata["server"], tt.wantServerMeta)
				}
			} else {
				if _, ok := result.Metadata["server"]; ok {
					t.Errorf("Metadata[server] should not be set, got %v", result.Metadata["server"])
				}
			}
		})
	}
}

func TestStreamlitFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Non-ok body",
			body: "not ok",
		},
		{
			name: "Empty body",
			body: "",
		},
		{
			name: "JSON body",
			body: `{"status": "ok"}`,
		},
		{
			name: "HTML body",
			body: "<html><body>ok</body></html>",
		},
		{
			name: "unavailable response",
			body: "unavailable",
		},
		{
			name: "ok with extra text",
			body: "ok extra",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &StreamlitFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html; charset=UTF-8")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil", result)
			}
		})
	}
}

func TestBuildStreamlitCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "1.29.0",
			want:    "cpe:2.3:a:streamlit:streamlit:1.29.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:streamlit:streamlit:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildStreamlitCPE(tt.version); got != tt.want {
				t.Errorf("buildStreamlitCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStreamlitFingerprinter_Integration(t *testing.T) {
	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &StreamlitFingerprinter{}
	Register(fp)

	// Create a valid Streamlit health response
	body := []byte("ok")

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html; charset=UTF-8")
	resp.Header.Set("Server", "TornadoServer/6.4.1")

	results := RunFingerprinters(resp, body)

	// Should find at least the Streamlit fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "streamlit" {
			found = true
			if result.Version != "" {
				t.Errorf("Version = %q, want empty string", result.Version)
			}
			expectedCPE := "cpe:2.3:a:streamlit:streamlit:*:*:*:*:*:*:*:*"
			if len(result.CPEs) == 0 || result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %v, want %q", result.CPEs, expectedCPE)
			}
		}
	}

	if !found {
		t.Error("StreamlitFingerprinter not found in results")
	}
}

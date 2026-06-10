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
	"strings"
	"testing"
)

// Interface compliance assertion
var _ ActiveHTTPFingerprinter = (*DLinkFingerprinter)(nil)

func TestDLinkFingerprinter_Name(t *testing.T) {
	f := &DLinkFingerprinter{}
	if name := f.Name(); name != "d-link-router" {
		t.Errorf("Name() = %q, expected %q", name, "d-link-router")
	}
}

func TestDLinkFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &DLinkFingerprinter{}
	if ep := f.ProbeEndpoint(); ep != "" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", ep, "")
	}
}

func TestDLinkFingerprinter_Match(t *testing.T) {
	f := &DLinkFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "accepts D-Link model in Server header",
			statusCode: 200,
			headers: http.Header{
				"Server":       []string{"DIR-825"},
				"Content-Type": []string{"text/html"},
			},
			want: true,
		},
		{
			name:       "accepts DAP model in Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"DAP-1520"},
			},
			want: true,
		},
		{
			name:       "accepts text/html content-type",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html; charset=UTF-8"},
			},
			want: true,
		},
		{
			name:       "rejects 500 server error",
			statusCode: 500,
			headers: http.Header{
				"Server":       []string{"DIR-825"},
				"Content-Type": []string{"text/html"},
			},
			want: false,
		},
		{
			name:       "rejects application/json without D-Link Server header",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			want: false,
		},
		{
			name:       "rejects unrelated Server header",
			statusCode: 200,
			headers: http.Header{
				"Server":       []string{"Apache/2.4.51"},
				"Content-Type": []string{"application/json"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     tt.headers,
			}
			if got := f.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDLinkFingerprinter_Fingerprint(t *testing.T) {
	f := &DLinkFingerprinter{}

	tests := []struct {
		name          string
		statusCode    int
		headers       http.Header
		body          string
		wantResult    bool
		wantTech      string
		wantVersion   string
		wantCPEPrefix string
		wantModel     string
	}{
		{
			name:       "detects via Server header with D-Link model (standalone)",
			statusCode: 200,
			headers: http.Header{
				"Server":       []string{"DIR-825"},
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body>Login</body></html>`,
			wantResult:    true,
			wantTech:      "d-link-router",
			wantCPEPrefix: "cpe:2.3:o:dlink:dir-825_firmware:",
			wantModel:     "DIR-825",
		},
		{
			name:       "detects brand + model in body (corroborated)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body><h1>D-Link DIR-615</h1></body></html>`,
			wantResult:    true,
			wantTech:      "d-link-router",
			wantCPEPrefix: "cpe:2.3:o:dlink:dir-615_firmware:",
			wantModel:     "DIR-615",
		},
		{
			name:       "does NOT detect brand + /login.htm path (/login.htm removed from path pattern)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body><a href="/login.htm">D-Link Login</a></body></html>`,
			wantResult: false,
		},
		{
			name:       "detects brand + dlinkrouter.local path (corroborated)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body>Visit dlinkrouter.local for D-Link setup</body></html>`,
			wantResult:    true,
			wantTech:      "d-link-router",
		},
		{
			name:       "extracts firmware version from body",
			statusCode: 200,
			headers: http.Header{
				"Server":       []string{"DIR-825"},
				"Content-Type": []string{"text/html"},
			},
			body:          "firmware: 2.06\n",
			wantResult:    true,
			wantVersion:   "2.06",
			wantCPEPrefix: "cpe:2.3:o:dlink:dir-825_firmware:2.06:",
		},
		{
			name:       "does NOT detect D-Link path alone without brand (FP prevention)",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><a href="/info/Login.html">Login</a></body></html>`,
			wantResult: false,
		},
		{
			name:       "does NOT detect D-Link brand alone without model or path (FP prevention)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body>D-Link routers are vulnerable to this attack.</body></html>`,
			wantResult: false,
		},
		{
			name:       "does NOT detect model pattern in unrelated context without brand",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body>The DIR-825 was patched last year.</body></html>`,
			wantResult: false,
		},
		{
			name:       "rejects 500 server error",
			statusCode: 500,
			headers: http.Header{
				"Server":       []string{"DIR-825"},
				"Content-Type": []string{"text/html"},
			},
			body:       `D-Link error`,
			wantResult: false,
		},
		{
			name:       "uses router_firmware CPE for unknown model",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body>D-Link router login<a href="/info/Login.html">Login</a></body></html>`,
			wantResult:    true,
			wantCPEPrefix: "cpe:2.3:o:dlink:router_firmware:",
		},
		{
			name:       "CPE vendor is dlink without hyphen",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"DSL-2640B"},
			},
			body:          ``,
			wantResult:    true,
			wantCPEPrefix: "cpe:2.3:o:dlink:",
		},
		{
			name:       "severity is unset",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"DIR-825"},
			},
			body:       ``,
			wantResult: true,
		},
		{
			name:       "detects DWR series",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"DWR-932"},
			},
			body:          ``,
			wantResult:    true,
			wantTech:      "d-link-router",
			wantCPEPrefix: "cpe:2.3:o:dlink:dwr-932_firmware:",
			wantModel:     "DWR-932",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     tt.headers,
			}
			result, err := f.Fingerprint(resp, []byte(tt.body))

			if err != nil {
				t.Errorf("Fingerprint() error = %v", err)
				return
			}

			if tt.wantResult && result == nil {
				t.Error("Fingerprint() returned nil, expected result")
				return
			}

			if !tt.wantResult && result != nil {
				t.Errorf("Fingerprint() returned result, expected nil; got Technology=%q", result.Technology)
				return
			}

			if result == nil {
				return
			}

			// Severity must always be unset for fingerprinter-only scope
			if result.Severity != "" {
				t.Errorf("Severity = %q, want empty (unset)", result.Severity)
			}

			if tt.wantTech != "" && result.Technology != tt.wantTech {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
			}

			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			if tt.wantCPEPrefix != "" {
				if len(result.CPEs) == 0 {
					t.Fatalf("CPEs is empty, want prefix %q", tt.wantCPEPrefix)
				}
				if !strings.HasPrefix(result.CPEs[0], tt.wantCPEPrefix) {
					t.Errorf("CPE[0] = %q, want prefix %q", result.CPEs[0], tt.wantCPEPrefix)
				}
			}

			if tt.wantModel != "" {
				if m, ok := result.Metadata["product_model"]; ok {
					if m != tt.wantModel {
						t.Errorf("product_model = %q, want %q", m, tt.wantModel)
					}
				} else {
					t.Errorf("product_model not in metadata, wanted %q", tt.wantModel)
				}
			}
		})
	}
}

func TestExtractDLinkVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "firmware keyword context",
			input: `firmware: 2.06`,
			want:  "2.06",
		},
		{
			name:  "firmwareVersion field",
			input: `{"firmwareVersion":"1.0.0"}`,
			want:  "1.0.0",
		},
		{
			name:  "fw_ver key-value",
			input: `fw_ver=2.4.0`,
			want:  "2.4.0",
		},
		{
			name:  "returns empty when no version present",
			input: `<html><body>Login</body></html>`,
			want:  "",
		},
		{
			name:  "rejects version with trailing letters",
			input: `firmware: 2.06abc`,
			want:  "",
		},
		{
			name:  "rejects version exceeding length cap",
			input: `firmware: 12345678901234567890.1`,
			want:  "",
		},
		{
			name:  "returns empty for empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractDLinkVersion(tt.input); got != tt.want {
				t.Errorf("extractDLinkVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractDLinkModel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "DIR-825",
			input: "Welcome to DIR-825",
			want:  "DIR-825",
		},
		{
			name:  "DAP-1520",
			input: "DAP-1520 Management",
			want:  "DAP-1520",
		},
		{
			name:  "DSL-2640B",
			input: "DSL-2640B Setup",
			want:  "DSL-2640B",
		},
		{
			name:  "DWR-932",
			input: "DWR-932 Router",
			want:  "DWR-932",
		},
		{
			name:  "DHP-1565",
			input: "DHP-1565 Powerline",
			want:  "DHP-1565",
		},
		{
			name:  "returns empty when no model found",
			input: "<html><body>Login Page</body></html>",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractDLinkModel(tt.input); got != tt.want {
				t.Errorf("extractDLinkModel(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildDLinkCPEs(t *testing.T) {
	tests := []struct {
		name    string
		product string
		version string
		wantCPE string
	}{
		{
			name:    "DIR-825 with version",
			product: "dir-825_firmware",
			version: "2.06",
			wantCPE: "cpe:2.3:o:dlink:dir-825_firmware:2.06:*:*:*:*:*:*:*",
		},
		{
			name:    "router firmware without version uses wildcard",
			product: "router_firmware",
			version: "",
			wantCPE: "cpe:2.3:o:dlink:router_firmware:*:*:*:*:*:*:*:*",
		},
		{
			name:    "CPE vendor has no hyphen",
			product: "dir-615_firmware",
			version: "1.0",
			wantCPE: "cpe:2.3:o:dlink:dir-615_firmware:1.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpes := buildDLinkCPEs(tt.product, tt.version)
			if len(cpes) != 1 {
				t.Errorf("buildDLinkCPEs() returned %d CPEs, want 1", len(cpes))
				return
			}
			if cpes[0] != tt.wantCPE {
				t.Errorf("buildDLinkCPEs() = %q, want %q", cpes[0], tt.wantCPE)
			}
		})
	}
}

func TestDLinkCPEProduct(t *testing.T) {
	tests := []struct {
		name  string
		model string
		want  string
	}{
		{name: "empty model defaults to router_firmware", model: "", want: "router_firmware"},
		{name: "DIR-825", model: "DIR-825", want: "dir-825_firmware"},
		{name: "DAP-1520", model: "DAP-1520", want: "dap-1520_firmware"},
		{name: "DSL-2640B", model: "DSL-2640B", want: "dsl-2640b_firmware"},
		{name: "DWR-932", model: "DWR-932", want: "dwr-932_firmware"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dlinkCPEProduct(tt.model); got != tt.want {
				t.Errorf("dlinkCPEProduct(%q) = %q, want %q", tt.model, got, tt.want)
			}
		})
	}
}

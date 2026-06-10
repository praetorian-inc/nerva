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
var _ ActiveHTTPFingerprinter = (*TPLinkFingerprinter)(nil)

func TestTPLinkFingerprinter_Name(t *testing.T) {
	f := &TPLinkFingerprinter{}
	if name := f.Name(); name != "tp-link-router" {
		t.Errorf("Name() = %q, expected %q", name, "tp-link-router")
	}
}

func TestTPLinkFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &TPLinkFingerprinter{}
	if ep := f.ProbeEndpoint(); ep != "/webpages/login.html" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", ep, "/webpages/login.html")
	}
}

func TestTPLinkFingerprinter_Match(t *testing.T) {
	f := &TPLinkFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "accepts WWW-Authenticate with TP-LINK",
			statusCode: 401,
			headers: http.Header{
				"WWW-Authenticate": []string{`Basic realm="TP-LINK Router"`},
			},
			want: true,
		},
		{
			name:       "accepts WWW-Authenticate with tp-link lowercase",
			statusCode: 401,
			headers: http.Header{
				"WWW-Authenticate": []string{`Basic realm="tp-link"`},
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
				"Content-Type":     []string{"text/html"},
				"WWW-Authenticate": []string{`Basic realm="TP-LINK Router"`},
			},
			want: false,
		},
		{
			name:       "rejects application/json without TP-Link header",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			want: false,
		},
		{
			name:       "rejects unrelated WWW-Authenticate",
			statusCode: 401,
			headers: http.Header{
				"WWW-Authenticate": []string{`Basic realm="Router"`},
				"Content-Type":     []string{"application/json"},
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

func TestTPLinkFingerprinter_Fingerprint(t *testing.T) {
	f := &TPLinkFingerprinter{}

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
			name:       "detects via WWW-Authenticate TP-LINK realm (standalone)",
			statusCode: 401,
			headers: http.Header{
				"WWW-Authenticate": []string{`Basic realm="TP-LINK Router"`},
			},
			body:          ``,
			wantResult:    true,
			wantTech:      "tp-link-router",
			wantCPEPrefix: "cpe:2.3:o:tp-link:",
		},
		{
			name:       "detects brand + model in body (corroborated)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body><title>TP-Link Archer C7</title></body></html>`,
			wantResult:    true,
			wantTech:      "tp-link-router",
			wantCPEPrefix: "cpe:2.3:o:tp-link:archer_c7_firmware:",
			wantModel:     "Archer C7",
		},
		{
			name:       "detects brand + /webpages/ path (corroborated)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><script src="/webpages/main.js"></script><p>TP-Link Router</p></html>`,
			wantResult:    true,
			wantTech:      "tp-link-router",
			wantCPEPrefix: "cpe:2.3:o:tp-link:",
		},
		{
			name:       "detects brand + /cgi/getParm path (corroborated)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body>TPLINK router<script>fetch('/cgi/getParm')</script></body></html>`,
			wantResult:    true,
			wantTech:      "tp-link-router",
		},
		{
			name:       "extracts firmware version from body",
			statusCode: 401,
			headers: http.Header{
				"WWW-Authenticate": []string{`Basic realm="TP-LINK Router"`},
			},
			body:          `{"firmwareVersion":"3.16.0","model":"TL-WR841N"}`,
			wantResult:    true,
			wantTech:      "tp-link-router",
			wantVersion:   "3.16.0",
			wantCPEPrefix: "cpe:2.3:o:tp-link:tl-wr841n_firmware:3.16.0:",
			wantModel:     "TL-WR841N",
		},
		{
			name:       "extracts TL-series model",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body><h1>TP-Link TL-WR940N</h1><script src="/webpages/login.js"></script></body></html>`,
			wantResult:    true,
			wantTech:      "tp-link-router",
			wantCPEPrefix: "cpe:2.3:o:tp-link:tl-wr940n_firmware:",
			wantModel:     "TL-WR940N",
		},
		{
			name:       "does NOT detect TP-Link path alone without brand (FP prevention)",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><script src="/webpages/main.js"></script><body>Router Login</body></html>`,
			wantResult: false,
		},
		{
			name:       "does NOT detect TP-Link brand alone without model or path (FP prevention)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body>TP-Link routers are popular home networking devices.</body></html>`,
			wantResult: false,
		},
		{
			name:       "does NOT detect model pattern in unrelated context without brand",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body>Configure your Archer C7 device settings.</body></html>`,
			wantResult: false,
		},
		{
			name:       "rejects 500 server error",
			statusCode: 500,
			headers: http.Header{
				"Content-Type":     []string{"text/html"},
				"WWW-Authenticate": []string{`Basic realm="TP-LINK Router"`},
			},
			body:       `TP-Link error`,
			wantResult: false,
		},
		{
			name:       "uses router_firmware CPE for unknown model",
			statusCode: 401,
			headers: http.Header{
				"WWW-Authenticate": []string{`Basic realm="TP-LINK"`},
			},
			body:          ``,
			wantResult:    true,
			wantCPEPrefix: "cpe:2.3:o:tp-link:router_firmware:",
		},
		{
			name:       "severity is unset",
			statusCode: 401,
			headers: http.Header{
				"WWW-Authenticate": []string{`Basic realm="TP-LINK Router"`},
			},
			body:       ``,
			wantResult: true,
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

func TestExtractTPLinkVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "JSON firmwareVersion field",
			input: `{"firmwareVersion":"3.16.0","hardware":"1.0"}`,
			want:  "3.16.0",
		},
		{
			name:  "fw_ver key-value",
			input: `fw_ver=1.0.0`,
			want:  "1.0.0",
		},
		{
			name:  "fw_ver with space separator",
			input: `fw_ver 2.4.3`,
			want:  "2.4.3",
		},
		{
			name:  "modelVersion JS variable",
			input: `var modelVersion = "3.16.1"`,
			want:  "3.16.1",
		},
		{
			name:  "firmware keyword context",
			input: `firmware: 1.2.3`,
			want:  "1.2.3",
		},
		{
			name:  "returns empty when no version present",
			input: `<html><body>Welcome</body></html>`,
			want:  "",
		},
		{
			name:  "rejects version with trailing letters",
			input: `firmwareVersion=1.0.0abc`,
			want:  "",
		},
		{
			name:  "rejects version exceeding length cap",
			input: `firmwareVersion=12345678901234567890.1`,
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
			if got := extractTPLinkVersion(tt.input); got != tt.want {
				t.Errorf("extractTPLinkVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractTPLinkModel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "TL-WR841N",
			input: "Welcome to TL-WR841N",
			want:  "TL-WR841N",
		},
		{
			name:  "Archer C7",
			input: "Archer C7 Administration",
			want:  "Archer C7",
		},
		{
			name:  "Archer AX3000",
			input: "Archer AX3000 Setup",
			want:  "Archer AX3000",
		},
		{
			name:  "TL-SG1005P",
			input: "TL-SG1005P Switch",
			want:  "TL-SG1005P",
		},
		{
			name:  "returns empty when no model found",
			input: "<html><body>Login Page</body></html>",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractTPLinkModel(tt.input); got != tt.want {
				t.Errorf("extractTPLinkModel(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildTPLinkCPEs(t *testing.T) {
	tests := []struct {
		name    string
		product string
		version string
		wantCPE string
	}{
		{
			name:    "Archer C7 with version",
			product: "archer_c7_firmware",
			version: "3.16.0",
			wantCPE: "cpe:2.3:o:tp-link:archer_c7_firmware:3.16.0:*:*:*:*:*:*:*",
		},
		{
			name:    "TL-WR841N with version",
			product: "tl-wr841n_firmware",
			version: "1.0.0",
			wantCPE: "cpe:2.3:o:tp-link:tl-wr841n_firmware:1.0.0:*:*:*:*:*:*:*",
		},
		{
			name:    "router firmware without version uses wildcard",
			product: "router_firmware",
			version: "",
			wantCPE: "cpe:2.3:o:tp-link:router_firmware:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpes := buildTPLinkCPEs(tt.product, tt.version)
			if len(cpes) != 1 {
				t.Errorf("buildTPLinkCPEs() returned %d CPEs, want 1", len(cpes))
				return
			}
			if cpes[0] != tt.wantCPE {
				t.Errorf("buildTPLinkCPEs() = %q, want %q", cpes[0], tt.wantCPE)
			}
		})
	}
}

func TestTPLinkCPEProduct(t *testing.T) {
	tests := []struct {
		name  string
		model string
		want  string
	}{
		{name: "empty model defaults to router_firmware", model: "", want: "router_firmware"},
		{name: "Archer C7", model: "Archer C7", want: "archer_c7_firmware"},
		{name: "TL-WR841N", model: "TL-WR841N", want: "tl-wr841n_firmware"},
		{name: "Archer AX3000", model: "Archer AX3000", want: "archer_ax3000_firmware"},
		{name: "TL-SG1005P", model: "TL-SG1005P", want: "tl-sg1005p_firmware"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tplinkCPEProduct(tt.model); got != tt.want {
				t.Errorf("tplinkCPEProduct(%q) = %q, want %q", tt.model, got, tt.want)
			}
		})
	}
}

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
var _ ActiveHTTPFingerprinter = (*NetgearFingerprinter)(nil)

func TestNetgearFingerprinter_Name(t *testing.T) {
	f := &NetgearFingerprinter{}
	if name := f.Name(); name != "netgear-router" {
		t.Errorf("Name() = %q, expected %q", name, "netgear-router")
	}
}

func TestNetgearFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &NetgearFingerprinter{}
	if ep := f.ProbeEndpoint(); ep != "/currentsetting.htm" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", ep, "/currentsetting.htm")
	}
}

func TestNetgearFingerprinter_Match(t *testing.T) {
	f := &NetgearFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "accepts WWW-Authenticate with NETGEAR",
			statusCode: 401,
			headers: http.Header{
				"WWW-Authenticate": []string{`Basic realm="NETGEAR R7000P"`},
			},
			want: true,
		},
		{
			name:       "accepts WWW-Authenticate with netgear lowercase",
			statusCode: 401,
			headers: http.Header{
				"WWW-Authenticate": []string{`Basic realm="netgear"`},
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
				"WWW-Authenticate": []string{`Basic realm="NETGEAR"`},
			},
			want: false,
		},
		{
			name:       "rejects application/json without NETGEAR header",
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
		{
			name:       "accepts text/plain content-type",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/plain"},
			},
			want: true,
		},
		{
			name:       "accepts response with no Content-Type",
			statusCode: 200,
			headers:    http.Header{},
			want:       true,
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

func TestNetgearFingerprinter_Fingerprint(t *testing.T) {
	f := &NetgearFingerprinter{}

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
			name:       "detects via WWW-Authenticate NETGEAR realm (standalone)",
			statusCode: 401,
			headers: http.Header{
				"WWW-Authenticate": []string{`Basic realm="NETGEAR R7000P"`},
			},
			body:          ``,
			wantResult:    true,
			wantTech:      "netgear-router",
			wantCPEPrefix: "cpe:2.3:o:netgear:",
		},
		{
			name:       "detects via currentsetting.htm Model= and Firmware= (standalone)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          "Model=R7000P\nFirmware=V1.3.2.134\nRegion=1",
			wantResult:    true,
			wantTech:      "netgear-router",
			wantVersion:   "1.3.2.134",
			wantCPEPrefix: "cpe:2.3:o:netgear:r7000p_firmware:1.3.2.134:",
			wantModel:     "R7000P",
		},
		{
			name:       "detects brand + R-series model in body (corroborated)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body><h1>NETGEAR R8000</h1></body></html>`,
			wantResult:    true,
			wantTech:      "netgear-router",
			wantCPEPrefix: "cpe:2.3:o:netgear:r8000_firmware:",
			wantModel:     "R8000",
		},
		{
			name:       "detects brand + routerlogin.net path (corroborated)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body>Visit routerlogin.net for NETGEAR setup</body></html>`,
			wantResult:    true,
			wantTech:      "netgear-router",
		},
		{
			name:       "detects brand + NETGEAR_ UI element (corroborated)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body class="NETGEAR_style"><p>NETGEAR router</p></body></html>`,
			wantResult:    true,
			wantTech:      "netgear-router",
		},
		{
			name:       "extracts RAX-series model",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body><h1>NETGEAR RAX50</h1></body></html>`,
			wantResult:    true,
			wantCPEPrefix: "cpe:2.3:o:netgear:rax50_firmware:",
			wantModel:     "RAX50",
		},
		{
			name:       "does NOT detect Netgear path alone without brand (FP prevention)",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html>Visit routerlogin.net for setup</html>`,
			wantResult: false,
		},
		{
			name:       "does NOT detect NETGEAR brand alone without model or path (FP prevention)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body>NETGEAR routers are vulnerable to this CVE.</body></html>`,
			wantResult: false,
		},
		{
			name:       "does NOT detect R-series model in unrelated context without brand (FP prevention)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body>Configure R7000P settings manually.</body></html>`,
			wantResult: false,
		},
		{
			name:       "rejects 500 server error",
			statusCode: 500,
			headers: http.Header{
				"Content-Type":     []string{"text/html"},
				"WWW-Authenticate": []string{`Basic realm="NETGEAR"`},
			},
			body:       `NETGEAR error`,
			wantResult: false,
		},
		{
			name:       "uses router_firmware CPE for unknown model",
			statusCode: 401,
			headers: http.Header{
				"WWW-Authenticate": []string{`Basic realm="NETGEAR"`},
			},
			body:          ``,
			wantResult:    true,
			wantCPEPrefix: "cpe:2.3:o:netgear:router_firmware:",
		},
		{
			name:       "severity is unset",
			statusCode: 401,
			headers: http.Header{
				"WWW-Authenticate": []string{`Basic realm="NETGEAR R7000P"`},
			},
			body:       ``,
			wantResult: true,
		},
		{
			name:       "Model= only without Firmware= does not trigger currentsetting signal",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `Model=SomeDevice\nSomethingElse=value`,
			wantResult: false,
		},
		{
			name:       "does NOT detect Firmware= alone without Model= (FP prevention)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       "Firmware=V1.3.2.134\nRegion=1",
			wantResult: false,
		},
		{
			name:       "does NOT detect Model= in middle of line (FP prevention)",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html>Set Model=R7000P in the config. Firmware=latest</html>`,
			wantResult: false,
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

func TestExtractNetgearVersionFromSettings(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Firmware=V1.3.2.134",
			input: "Model=R7000P\nFirmware=V1.3.2.134\nRegion=1",
			want:  "1.3.2.134",
		},
		{
			name:  "Firmware without V prefix",
			input: "Firmware=1.0.9.88",
			want:  "1.0.9.88",
		},
		{
			name:  "returns empty when no Firmware field",
			input: "Model=R7000P\nRegion=1",
			want:  "",
		},
		{
			name:  "rejects version exceeding length cap",
			input: "Firmware=V12345678901234567890.1",
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
			if got := extractNetgearVersionFromSettings(tt.input); got != tt.want {
				t.Errorf("extractNetgearVersionFromSettings(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractNetgearVersionFromBody(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "firmware keyword context",
			input: `firmware: 1.2.3`,
			want:  "1.2.3",
		},
		{
			name:  "firmwareVersion field",
			input: `{"firmwareVersion":"2.0.0"}`,
			want:  "2.0.0",
		},
		{
			name:  "returns empty when no version present",
			input: `<html><body>Login</body></html>`,
			want:  "",
		},
		{
			name:  "rejects version with trailing letters",
			input: `firmware: 1.0.0abc`,
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
			if got := extractNetgearVersionFromBody(tt.input); got != tt.want {
				t.Errorf("extractNetgearVersionFromBody(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractNetgearModel(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantModel string
		fromBody  bool // true = use extractNetgearModelFromBody
	}{
		{
			name:      "R7000P from currentsetting.htm",
			input:     "Model=R7000P\nFirmware=V1.3.2.134",
			wantModel: "R7000P",
			fromBody:  false,
		},
		{
			name:      "RAX50 from currentsetting.htm",
			input:     "Model=RAX50\nFirmware=V1.0.0",
			wantModel: "RAX50",
			fromBody:  false,
		},
		{
			name:      "R8000 from body",
			input:     "NETGEAR R8000 router",
			wantModel: "R8000",
			fromBody:  true,
		},
		{
			name:      "RAX50 from body",
			input:     "RAX50 Nighthawk AX6 6-Stream WiFi 6 Router",
			wantModel: "RAX50",
			fromBody:  true,
		},
		{
			name:      "returns empty when no model in settings",
			input:     "Firmware=V1.0.0\nRegion=1",
			wantModel: "",
			fromBody:  false,
		},
		{
			name:      "returns empty when no model in body",
			input:     "<html><body>Login Page</body></html>",
			wantModel: "",
			fromBody:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			if tt.fromBody {
				got = extractNetgearModelFromBody(tt.input)
			} else {
				got = extractNetgearModelFromSettings(tt.input)
			}
			if got != tt.wantModel {
				t.Errorf("extractNetgearModel(%q) = %q, want %q", tt.input, got, tt.wantModel)
			}
		})
	}
}

func TestBuildNetgearCPEs(t *testing.T) {
	tests := []struct {
		name    string
		product string
		version string
		wantCPE string
	}{
		{
			name:    "R7000P with version",
			product: "r7000p_firmware",
			version: "1.3.2.134",
			wantCPE: "cpe:2.3:o:netgear:r7000p_firmware:1.3.2.134:*:*:*:*:*:*:*",
		},
		{
			name:    "RAX50 with version",
			product: "rax50_firmware",
			version: "1.0.0",
			wantCPE: "cpe:2.3:o:netgear:rax50_firmware:1.0.0:*:*:*:*:*:*:*",
		},
		{
			name:    "router firmware without version uses wildcard",
			product: "router_firmware",
			version: "",
			wantCPE: "cpe:2.3:o:netgear:router_firmware:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpes := buildNetgearCPEs(tt.product, tt.version)
			if len(cpes) != 1 {
				t.Errorf("buildNetgearCPEs() returned %d CPEs, want 1", len(cpes))
				return
			}
			if cpes[0] != tt.wantCPE {
				t.Errorf("buildNetgearCPEs() = %q, want %q", cpes[0], tt.wantCPE)
			}
		})
	}
}

func TestNetgearCPEProduct(t *testing.T) {
	tests := []struct {
		name  string
		model string
		want  string
	}{
		{name: "empty model defaults to router_firmware", model: "", want: "router_firmware"},
		{name: "R7000P", model: "R7000P", want: "r7000p_firmware"},
		{name: "R8000", model: "R8000", want: "r8000_firmware"},
		{name: "RAX50", model: "RAX50", want: "rax50_firmware"},
		{name: "Nighthawk", model: "Nighthawk", want: "nighthawk_firmware"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := netgearCPEProduct(tt.model); got != tt.want {
				t.Errorf("netgearCPEProduct(%q) = %q, want %q", tt.model, got, tt.want)
			}
		})
	}
}

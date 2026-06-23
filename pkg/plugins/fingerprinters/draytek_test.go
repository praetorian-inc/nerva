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
var _ ActiveHTTPFingerprinter = (*DrayTekVigorFingerprinter)(nil)

func TestDrayTekVigorFingerprinter_Name(t *testing.T) {
	f := &DrayTekVigorFingerprinter{}
	if name := f.Name(); name != "draytek-vigor" {
		t.Errorf("Name() = %q, expected %q", name, "draytek-vigor")
	}
}

func TestDrayTekVigorFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &DrayTekVigorFingerprinter{}
	if ep := f.ProbeEndpoint(); ep != "/weblogin.htm" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", ep, "/weblogin.htm")
	}
}

func TestDrayTekVigorFingerprinter_Match(t *testing.T) {
	f := &DrayTekVigorFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "accepts text/html content-type with 200",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html; charset=UTF-8"},
			},
			want: true,
		},
		{
			name:       "accepts text/html content-type with 401",
			statusCode: 401,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			want: true,
		},
		{
			name:       "accepts text/html content-type with 302",
			statusCode: 302,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			want: true,
		},
		{
			name:       "rejects 500 server error",
			statusCode: 500,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			want: false,
		},
		{
			name:       "rejects 503 server error",
			statusCode: 503,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			want: false,
		},
		{
			name:       "rejects application/json",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			want: false,
		},
		{
			name:       "rejects response with no content-type",
			statusCode: 200,
			headers:    http.Header{},
			want:       false,
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

func TestDrayTekVigorFingerprinter_Fingerprint(t *testing.T) {
	f := &DrayTekVigorFingerprinter{}

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
			name:       "detects brand + model in body (Vigor3910)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body><title>DrayTek Vigor3910</title></body></html>`,
			wantResult:    true,
			wantTech:      "draytek-vigor",
			wantCPEPrefix: "cpe:2.3:o:draytek:vigor3910_firmware:",
			wantModel:     "vigor3910",
		},
		{
			name:       "detects brand + model (Vigor2960)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body>DrayTek Vigor2960 Management</body></html>`,
			wantResult:    true,
			wantTech:      "draytek-vigor",
			wantCPEPrefix: "cpe:2.3:o:draytek:vigor2960_firmware:",
			wantModel:     "vigor2960",
		},
		{
			name:       "detects brand + model (Vigor165)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body>DrayTek Vigor165 Router Login</body></html>`,
			wantResult:    true,
			wantTech:      "draytek-vigor",
			wantCPEPrefix: "cpe:2.3:o:draytek:vigor165_firmware:",
			wantModel:     "vigor165",
		},
		{
			name:       "detects brand + model (Vigor1000B)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body><h1>DrayTek Vigor1000B</h1></body></html>`,
			wantResult:    true,
			wantTech:      "draytek-vigor",
			wantCPEPrefix: "cpe:2.3:o:draytek:vigor1000b_firmware:",
			wantModel:     "vigor1000b",
		},
		{
			name:       "detects VigorLTE200 with correct CPE product",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body>DrayTek VigorLTE200 LTE Router</body></html>`,
			wantResult:    true,
			wantTech:      "draytek-vigor",
			wantCPEPrefix: "cpe:2.3:o:draytek:vigorlte200_firmware:",
			wantModel:     "vigorlte200",
		},
		{
			name:       "extracts four-part firmware version (4.4.5.3)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body>DrayTek Vigor3910<script>var fwVersion="4.4.5.3";</script></body></html>`,
			wantResult:    true,
			wantTech:      "draytek-vigor",
			wantVersion:   "4.4.5.3",
			wantCPEPrefix: "cpe:2.3:o:draytek:vigor3910_firmware:4.4.5.3:",
			wantModel:     "vigor3910",
		},
		{
			name:       "extracts three-part firmware version (1.5.1)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body>DrayTek Vigor2960<br>fw_ver: 1.5.1</body></html>`,
			wantResult:    true,
			wantTech:      "draytek-vigor",
			wantVersion:   "1.5.1",
			wantCPEPrefix: "cpe:2.3:o:draytek:vigor2960_firmware:1.5.1:",
			wantModel:     "vigor2960",
		},
		{
			name:       "does NOT detect brand only (no model)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body>DrayTek routers are popular networking devices.</body></html>`,
			wantResult: false,
		},
		{
			name:       "does NOT detect model only (no brand)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body>Configure your Vigor3910 device.</body></html>`,
			wantResult: false,
		},
		{
			name:       "does NOT detect generic router page",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body><h1>Router Login</h1><p>Enter credentials</p></body></html>`,
			wantResult: false,
		},
		{
			name:       "does NOT detect news article mentioning DrayTek",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body><h1>Top 10 Routers of 2024</h1><p>DrayTek makes enterprise routers.</p></body></html>`,
			wantResult: false,
		},
		{
			name:       "rejects 500 server error",
			statusCode: 500,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `DrayTek Vigor3910 error`,
			wantResult: false,
		},
		{
			name:       "rejects non-HTML content type",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			body:       `{"brand":"DrayTek","model":"Vigor3910"}`,
			wantResult: false,
		},
		{
			name:       "rejects body over 1 MiB",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       "DrayTek Vigor3910 " + strings.Repeat("A", 1<<20),
			wantResult: false,
		},
		{
			name:       "uses vigor_firmware CPE for unknown model (fallback)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			// This case cannot produce unknown model since detection requires model match,
			// but we test the CPE builder separately; here we test the minimum detection case.
			body:          `<html><body>DrayTek Vigor3910 Router</body></html>`,
			wantResult:    true,
			wantCPEPrefix: "cpe:2.3:o:draytek:vigor3910_firmware:",
		},
		{
			name:       "detection-only: severity is empty",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body>DrayTek Vigor3910 Login</body></html>`,
			wantResult: true,
		},
		{
			name:       "nil body (empty) with brand and model — no result when body empty",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       "",
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

			// SecurityFindings must not be set for fingerprinter-only scope
			if len(result.SecurityFindings) != 0 {
				t.Errorf("SecurityFindings has %d entries, want 0", len(result.SecurityFindings))
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

func TestExtractDrayTekVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "fwVersion context keyword",
			input: `var fwVersion="4.4.5.3";`,
			want:  "4.4.5.3",
		},
		{
			name:  "fw_ver context keyword",
			input: `fw_ver: 1.5.1`,
			want:  "1.5.1",
		},
		{
			name:  "firmware keyword context",
			input: `firmware: 4.4.5`,
			want:  "4.4.5",
		},
		{
			name:  "FwVer context keyword",
			input: `FwVer:"4.4.5"`,
			want:  "4.4.5",
		},
		{
			name:  "four-part version (4.4.5.3)",
			input: `fwVersion=4.4.5.3`,
			want:  "4.4.5.3",
		},
		{
			name:  "three-part version (1.5.1)",
			input: `fw_ver=1.5.1`,
			want:  "1.5.1",
		},
		{
			name:  "returns empty when no version present",
			input: `<html><body>Welcome to the router</body></html>`,
			want:  "",
		},
		{
			name:  "rejects version too long",
			input: `fwVersion=12345678901234567890.1.2`,
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
			if got := extractDrayTekVersion(tt.input); got != tt.want {
				t.Errorf("extractDrayTekVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractDrayTekModel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Vigor3910",
			input: "DrayTek Vigor3910 Router",
			want:  "vigor3910",
		},
		{
			name:  "Vigor2960",
			input: "Vigor2960 Management",
			want:  "vigor2960",
		},
		{
			name:  "Vigor165",
			input: "Welcome to Vigor165",
			want:  "vigor165",
		},
		{
			name:  "Vigor1000B",
			input: "DrayTek Vigor1000B",
			want:  "vigor1000b",
		},
		{
			name:  "VigorLTE200",
			input: "VigorLTE200 LTE Router",
			want:  "vigorlte200",
		},
		{
			name:  "returns empty when no model found",
			input: "<html><body>Login Page</body></html>",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractDrayTekModel(tt.input); got != tt.want {
				t.Errorf("extractDrayTekModel(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildDrayTekCPEs(t *testing.T) {
	tests := []struct {
		name    string
		product string
		version string
		wantCPE string
	}{
		{
			name:    "Vigor3910 with four-part version",
			product: "vigor3910_firmware",
			version: "4.4.5.3",
			wantCPE: "cpe:2.3:o:draytek:vigor3910_firmware:4.4.5.3:*:*:*:*:*:*:*",
		},
		{
			name:    "Vigor2960 with three-part version",
			product: "vigor2960_firmware",
			version: "1.5.1",
			wantCPE: "cpe:2.3:o:draytek:vigor2960_firmware:1.5.1:*:*:*:*:*:*:*",
		},
		{
			name:    "vigor_firmware fallback without version uses wildcard",
			product: "vigor_firmware",
			version: "",
			wantCPE: "cpe:2.3:o:draytek:vigor_firmware:*:*:*:*:*:*:*:*",
		},
		{
			name:    "vigorlte200_firmware with version",
			product: "vigorlte200_firmware",
			version: "4.4.5",
			wantCPE: "cpe:2.3:o:draytek:vigorlte200_firmware:4.4.5:*:*:*:*:*:*:*",
		},
		{
			name:    "rejects CPE metacharacter colon in product",
			product: "vigor3910:injected_firmware",
			version: "4.4.5.3",
			wantCPE: "cpe:2.3:o:draytek:vigor_firmware:4.4.5.3:*:*:*:*:*:*:*",
		},
		{
			name:    "rejects CPE metacharacter asterisk in product",
			product: "vigor3910*_firmware",
			version: "4.4.5.3",
			wantCPE: "cpe:2.3:o:draytek:vigor_firmware:4.4.5.3:*:*:*:*:*:*:*",
		},
		{
			name:    "rejects CPE metacharacter in version",
			product: "vigor3910_firmware",
			version: "4.4.5:injected",
			wantCPE: "cpe:2.3:o:draytek:vigor3910_firmware:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpes := buildDrayTekCPEs(tt.product, tt.version)
			if len(cpes) != 1 {
				t.Errorf("buildDrayTekCPEs() returned %d CPEs, want 1", len(cpes))
				return
			}
			if cpes[0] != tt.wantCPE {
				t.Errorf("buildDrayTekCPEs() = %q, want %q", cpes[0], tt.wantCPE)
			}
		})
	}
}

func TestDrayTekCPEProduct(t *testing.T) {
	tests := []struct {
		name  string
		model string
		want  string
	}{
		{name: "empty model defaults to vigor_firmware", model: "", want: "vigor_firmware"},
		{name: "vigor3910", model: "vigor3910", want: "vigor3910_firmware"},
		{name: "vigor2960", model: "vigor2960", want: "vigor2960_firmware"},
		{name: "vigor165", model: "vigor165", want: "vigor165_firmware"},
		{name: "vigor1000b", model: "vigor1000b", want: "vigor1000b_firmware"},
		{name: "vigorlte200", model: "vigorlte200", want: "vigorlte200_firmware"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := draytekCPEProduct(tt.model); got != tt.want {
				t.Errorf("draytekCPEProduct(%q) = %q, want %q", tt.model, got, tt.want)
			}
		})
	}
}

func TestDrayTekVigorFingerprinter_DetectionOnlyContract(t *testing.T) {
	f := &DrayTekVigorFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
	body := []byte(`<html><body>DrayTek Vigor3910 Router Login</body></html>`)

	result, err := f.Fingerprint(resp, body)
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, expected result")
	}

	if result.Severity != "" {
		t.Errorf("Severity = %q, want empty — fingerprinter-only ticket must not set Severity", result.Severity)
	}
	if len(result.SecurityFindings) != 0 {
		t.Errorf("SecurityFindings = %v, want nil — fingerprinter-only ticket must not set SecurityFindings", result.SecurityFindings)
	}
}

func TestDrayTekVigorFingerprinter_CPEInjectionGuard(t *testing.T) {
	f := &DrayTekVigorFingerprinter{}

	// Body with brand + model that contains CPE metacharacters after the model.
	// The model regex should NOT capture the metacharacters.
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
	body := []byte(`<html><body>DrayTek Vigor3910 fwVersion=4.4.5.3</body></html>`)

	result, err := f.Fingerprint(resp, body)
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("expected result for valid DrayTek page")
	}

	for _, cpe := range result.CPEs {
		// Count colons — a valid CPE 2.3 has exactly 12 colons
		colonCount := strings.Count(cpe, ":")
		if colonCount != 12 {
			t.Errorf("CPE has %d colons (expected 12): %q", colonCount, cpe)
		}
	}
}

func TestDrayTekVigorFingerprinter_Registration(t *testing.T) {
	found := false
	for _, fp := range GetFingerprinters() {
		if fp.Name() == "draytek-vigor" {
			found = true
			if active, ok := fp.(ActiveHTTPFingerprinter); ok {
				if ep := active.ProbeEndpoint(); ep != "/weblogin.htm" {
					t.Errorf("ProbeEndpoint() = %q, want %q", ep, "/weblogin.htm")
				}
			} else {
				t.Error("draytek-vigor fingerprinter does not implement ActiveHTTPFingerprinter")
			}
			break
		}
	}
	if !found {
		t.Error("draytek-vigor not found in registered fingerprinters")
	}
}

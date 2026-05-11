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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// --- Name ---

func TestBarracudaESGFingerprinter_Name(t *testing.T) {
	f := &BarracudaESGFingerprinter{}
	if got := f.Name(); got != "barracuda-esg" {
		t.Errorf("Name() = %q, want %q", got, "barracuda-esg")
	}
}

// --- Match ---

func TestBarracudaESGFingerprinter_Match(t *testing.T) {
	f := &BarracudaESGFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "accepts X-Barracuda-Spam-Score header",
			statusCode: 200,
			headers: http.Header{
				"X-Barracuda-Spam-Score": []string{"0.00"},
			},
			want: true,
		},
		{
			name:       "accepts X-Barracuda-Spam-Status header",
			statusCode: 200,
			headers: http.Header{
				"X-Barracuda-Spam-Status": []string{"No"},
			},
			want: true,
		},
		{
			name:       "accepts Server: Barracuda/6.8 header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Barracuda/6.8"},
			},
			want: true,
		},
		{
			name:       "accepts text/html content-type for body detection",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html; charset=UTF-8"},
			},
			want: true,
		},
		{
			name:       "accepts 302 redirect with X-Barracuda header",
			statusCode: 302,
			headers: http.Header{
				"X-Barracuda-Connect": []string{"mail.example.com[1.2.3.4]"},
				"Location":            []string{"/login"},
			},
			want: true,
		},
		{
			name:       "rejects 500 server error even with X-Barracuda header",
			statusCode: 500,
			headers: http.Header{
				"X-Barracuda-Spam-Score": []string{"0.00"},
				"Content-Type":           []string{"text/html"},
			},
			want: false,
		},
		{
			name:       "rejects application/json with no Barracuda signals",
			statusCode: 200,
			headers: http.Header{
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

// --- Fingerprint: Valid detections ---

func TestBarracudaESGFingerprinter_Fingerprint_Valid(t *testing.T) {
	f := &BarracudaESGFingerprinter{}

	// Realistic Barracuda ESG response headers.
	barracudaHeaders := http.Header{
		"X-Barracuda-Spam-Score":  []string{"0.00"},
		"X-Barracuda-Spam-Status": []string{"No"},
		"X-Barracuda-Connect":     []string{"mail.example.com[1.2.3.4]"},
		"Server":                  []string{"Barracuda/6.8"},
		"Content-Type":            []string{"text/html"},
	}

	barracudaBody := `<html><head><title>Barracuda Email Security Gateway</title></head>
<body><h1>Barracuda Email Security Gateway</h1>
<p>Powered by Barracuda Networks</p></body></html>`

	tests := []struct {
		name             string
		statusCode       int
		headers          http.Header
		body             string
		wantTech         string
		wantCPEPrefix    string
		wantDetectMethod string
		wantVersion      string
	}{
		{
			name:             "detects via X-Barracuda header (definitive signal)",
			statusCode:       200,
			headers:          barracudaHeaders,
			body:             `<html><body>Login</body></html>`,
			wantTech:         "barracuda-esg",
			wantCPEPrefix:    "cpe:2.3:o:barracuda:email_security_gateway_firmware:",
			wantDetectMethod: "header",
		},
		{
			name:       "detects via Server: Barracuda header",
			statusCode: 200,
			headers: http.Header{
				"Server":       []string{"Barracuda/6.8"},
				"Content-Type": []string{"text/html"},
			},
			body:             `<html><body>Welcome</body></html>`,
			wantTech:         "barracuda-esg",
			wantCPEPrefix:    "cpe:2.3:o:barracuda:email_security_gateway_firmware:",
			wantDetectMethod: "header",
		},
		{
			name:       "detects via body brand signals",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:             barracudaBody,
			wantTech:         "barracuda-esg",
			wantCPEPrefix:    "cpe:2.3:o:barracuda:email_security_gateway_firmware:",
			wantDetectMethod: "body",
		},
		{
			name:       "detects with multiple X-Barracuda headers",
			statusCode: 200,
			headers: http.Header{
				"X-Barracuda-Spam-Score":  []string{"0.00"},
				"X-Barracuda-Spam-Status": []string{"No"},
				"X-Barracuda-Connect":     []string{"mail.example.com[1.2.3.4]"},
			},
			body:             ``,
			wantTech:         "barracuda-esg",
			wantCPEPrefix:    "cpe:2.3:o:barracuda:email_security_gateway_firmware:",
			wantDetectMethod: "header",
		},
		{
			name:       "extracts version from X-Barracuda-Version header",
			statusCode: 200,
			headers: http.Header{
				"X-Barracuda-Spam-Score": []string{"0.00"},
				"X-Barracuda-Version":    []string{"9.2.0.001"},
			},
			body:             ``,
			wantTech:         "barracuda-esg",
			wantCPEPrefix:    "cpe:2.3:o:barracuda:email_security_gateway_firmware:9.2.0.001:",
			wantDetectMethod: "header",
			wantVersion:      "9.2.0.001",
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
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, expected result")
			}

			if result.Technology != tt.wantTech {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
			}

			if tt.wantCPEPrefix != "" {
				if len(result.CPEs) == 0 {
					t.Fatalf("CPEs is empty, want prefix %q", tt.wantCPEPrefix)
				}
				if !strings.HasPrefix(result.CPEs[0], tt.wantCPEPrefix) {
					t.Errorf("CPE[0] = %q, want prefix %q", result.CPEs[0], tt.wantCPEPrefix)
				}
			}

			if tt.wantDetectMethod != "" {
				if m, ok := result.Metadata["detection_method"]; !ok {
					t.Error("Metadata missing detection_method")
				} else if m != tt.wantDetectMethod {
					t.Errorf("detection_method = %q, want %q", m, tt.wantDetectMethod)
				}
			}

			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Severity must be SeverityCritical for all valid detections
			if result.Severity != plugins.SeverityCritical {
				t.Errorf("Severity = %q, want %q", result.Severity, plugins.SeverityCritical)
			}
		})
	}
}

// --- Fingerprint: Invalid / non-detections ---

func TestBarracudaESGFingerprinter_Fingerprint_Invalid(t *testing.T) {
	f := &BarracudaESGFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		body       string
	}{
		{
			name:       "empty body with no signals",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: ``,
		},
		{
			name:       "non-Barracuda page with html content",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: `<html><head><title>Corporate Login</title></head><body>Welcome</body></html>`,
		},
		{
			name:       "body exceeding 2MiB is truncated and checked — no signals",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: strings.Repeat("x", barracudaMaxBodySize+1),
		},
		{
			name:       "body containing CPE injection sequence :*:",
			statusCode: 200,
			headers: http.Header{
				"Content-Type":           []string{"text/html"},
				"X-Barracuda-Spam-Score": []string{"0.00"},
			},
			// The CPE injection check gates on the body, not headers — but
			// we test that bodies with :*: are rejected even when headers match.
			// NOTE: headers still match, but body gate rejects.
			body: `<html><body>cpe:2.3:o:barracuda:*:*:*:*:*:*:*:*</body></html>`,
		},
		{
			name:       "5xx error rejected",
			statusCode: 503,
			headers: http.Header{
				"X-Barracuda-Spam-Score": []string{"0.00"},
				"Content-Type":           []string{"text/html"},
			},
			body: `<html><body>Service Unavailable</body></html>`,
		},
		{
			name:       "generic email page without Barracuda signals",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: `<html><body><h1>Email Security Gateway</h1><p>Powered by Acme Networks</p></body></html>`,
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
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil", result)
			}
		})
	}
}

// --- hasBarracudaHeaders ---

func TestHasBarracudaHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    bool
	}{
		{
			name: "X-Barracuda-Spam-Score present",
			headers: http.Header{
				"X-Barracuda-Spam-Score": []string{"0.00"},
			},
			want: true,
		},
		{
			name: "X-Barracuda-Connect present",
			headers: http.Header{
				"X-Barracuda-Connect": []string{"mail.example.com[1.2.3.4]"},
			},
			want: true,
		},
		{
			name: "multiple X-Barracuda headers",
			headers: http.Header{
				"X-Barracuda-Spam-Score":  []string{"0.00"},
				"X-Barracuda-Spam-Status": []string{"No"},
			},
			want: true,
		},
		{
			name: "no X-Barracuda headers",
			headers: http.Header{
				"Server":       []string{"Apache"},
				"Content-Type": []string{"text/html"},
			},
			want: false,
		},
		{
			name:    "empty header set",
			headers: http.Header{},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: tt.headers}
			if got := hasBarracudaHeaders(resp); got != tt.want {
				t.Errorf("hasBarracudaHeaders() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- buildBarracudaCPE ---

func TestBuildBarracudaCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantCPE string
	}{
		{
			name:    "with version",
			version: "9.2.0.001",
			wantCPE: "cpe:2.3:o:barracuda:email_security_gateway_firmware:9.2.0.001:*:*:*:*:*:*:*",
		},
		{
			name:    "without version uses wildcard",
			version: "",
			wantCPE: "cpe:2.3:o:barracuda:email_security_gateway_firmware:*:*:*:*:*:*:*:*",
		},
		{
			name:    "two-part version",
			version: "9.2",
			wantCPE: "cpe:2.3:o:barracuda:email_security_gateway_firmware:9.2:*:*:*:*:*:*:*",
		},
		{
			name:    "five-part version",
			version: "12.0.1.123.4",
			wantCPE: "cpe:2.3:o:barracuda:email_security_gateway_firmware:12.0.1.123.4:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildBarracudaCPE(tt.version)
			if got != tt.wantCPE {
				t.Errorf("buildBarracudaCPE(%q) = %q, want %q", tt.version, got, tt.wantCPE)
			}
		})
	}
}

// --- sanitizeBarracudaHeaderValue ---

func TestSanitizeBarracudaHeaderValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "clean printable ASCII passthrough",
			input: "0.00",
			want:  "0.00",
		},
		{
			name:  "strips control character",
			input: "value\x00with\x01null",
			want:  "valuewithnull",
		},
		{
			name:  "strips non-printable rune",
			input: "test\x1bvalue",
			want:  "testvalue",
		},
		{
			name:  "preserves printable special chars",
			input: "mail.example.com[1.2.3.4]",
			want:  "mail.example.com[1.2.3.4]",
		},
		{
			name:  "truncates at 512 bytes",
			input: strings.Repeat("A", 600),
			want:  strings.Repeat("A", 512),
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeBarracudaHeaderValue(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeBarracudaHeaderValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- Version validation ---

func TestValidateBarracudaVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "valid two-part", input: "9.2", want: "9.2"},
		{name: "valid three-part", input: "9.2.0", want: "9.2.0"},
		{name: "valid four-part", input: "9.2.0.001", want: "9.2.0.001"},
		{name: "valid five-part", input: "12.0.1.123.4", want: "12.0.1.123.4"},
		{name: "rejects letters", input: "9.2a", want: ""},
		{name: "rejects injection with semicolon", input: "9.2;DROP TABLE", want: ""},
		{name: "rejects CPE metachar colon", input: "9.2:*", want: ""},
		{name: "rejects oversized", input: strings.Repeat("9", 33) + ".1", want: ""},
		{name: "rejects empty", input: "", want: ""},
		{name: "rejects single part", input: "9", want: ""},
		{name: "strips and validates", input: "  9.2.0  ", want: "9.2.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateBarracudaVersion(tt.input)
			if got != tt.want {
				t.Errorf("validateBarracudaVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- Integration test using httptest ---

func TestBarracudaESGFingerprinter_Integration(t *testing.T) {
	mux := http.NewServeMux()

	// Simulate a Barracuda ESG response with realistic headers
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Header().Set("X-Barracuda-Spam-Score", "0.00")
		w.Header().Set("X-Barracuda-Spam-Status", "No")
		w.Header().Set("X-Barracuda-Connect", "mail.example.com[1.2.3.4]")
		w.Header().Set("Server", "Barracuda/6.8")
		w.Header().Set("X-Barracuda-Version", "9.2.0.001")
		fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>Barracuda Email Security Gateway</title></head>
<body>
<h1>Barracuda Email Security Gateway</h1>
<p>Powered by Barracuda Networks</p>
<p>Version: 9.2.0.001</p>
</body>
</html>`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	fp := &BarracudaESGFingerprinter{}

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()

	// Read body manually for test (simulating nerva's HTTP client)
	bodyBuf := make([]byte, barracudaMaxBodySize)
	n, _ := resp.Body.Read(bodyBuf)
	body := bodyBuf[:n]

	if !fp.Match(resp) {
		t.Fatal("Match() returned false for Barracuda ESG response")
	}

	result, err := fp.Fingerprint(resp, body)
	if err != nil {
		t.Fatalf("Fingerprint() error: %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil for Barracuda ESG")
	}

	if result.Technology != "barracuda-esg" {
		t.Errorf("Technology = %q, want barracuda-esg", result.Technology)
	}

	if result.Version != "9.2.0.001" {
		t.Errorf("Version = %q, want 9.2.0.001", result.Version)
	}

	if result.Severity != plugins.SeverityCritical {
		t.Errorf("Severity = %q, want critical", result.Severity)
	}

	if len(result.CPEs) == 0 {
		t.Fatal("CPEs is empty")
	}
	wantCPE := "cpe:2.3:o:barracuda:email_security_gateway_firmware:9.2.0.001:*:*:*:*:*:*:*"
	if result.CPEs[0] != wantCPE {
		t.Errorf("CPE[0] = %q, want %q", result.CPEs[0], wantCPE)
	}

	// Verify barracuda_headers metadata collected
	if bh, ok := result.Metadata["barracuda_headers"]; !ok {
		t.Error("Metadata missing barracuda_headers")
	} else {
		headers, ok := bh.(map[string]string)
		if !ok {
			t.Errorf("barracuda_headers is not map[string]string, got %T", bh)
		} else if len(headers) == 0 {
			t.Error("barracuda_headers map is empty")
		}
	}

	if dm, ok := result.Metadata["detection_method"]; !ok {
		t.Error("Metadata missing detection_method")
	} else if dm != "header" {
		t.Errorf("detection_method = %q, want header", dm)
	}
}

// TestBarracudaESGFingerprinter_PassiveInterface verifies that BarracudaESGFingerprinter
// implements HTTPFingerprinter but NOT ActiveHTTPFingerprinter (passive only).
func TestBarracudaESGFingerprinter_PassiveInterface(t *testing.T) {
	var _ HTTPFingerprinter = (*BarracudaESGFingerprinter)(nil)

	// Must NOT implement ActiveHTTPFingerprinter (no ProbeEndpoint)
	_, isActive := interface{}(&BarracudaESGFingerprinter{}).(ActiveHTTPFingerprinter)
	if isActive {
		t.Error("BarracudaESGFingerprinter must not implement ActiveHTTPFingerprinter")
	}
}

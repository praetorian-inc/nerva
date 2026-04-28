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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestZyxelFingerprinter_Name(t *testing.T) {
	f := &ZyxelFingerprinter{}
	if name := f.Name(); name != "zyxel-firewall" {
		t.Errorf("Name() = %q, expected %q", name, "zyxel-firewall")
	}
}

func TestZyxelFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &ZyxelFingerprinter{}
	if ep := f.ProbeEndpoint(); ep != "/weblogin.cgi" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", ep, "/weblogin.cgi")
	}
}

func TestZyxelFingerprinter_Match(t *testing.T) {
	f := &ZyxelFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "accepts redirect to /ztp/cgi-bin/",
			statusCode: 302,
			headers: http.Header{
				"Location": []string{"/ztp/cgi-bin/handler"},
			},
			want: true,
		},
		{
			name:       "accepts redirect to /weblogin.cgi",
			statusCode: 302,
			headers: http.Header{
				"Location": []string{"/weblogin.cgi"},
			},
			want: true,
		},
		{
			name:       "accepts text/html response",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html; charset=UTF-8"},
			},
			want: true,
		},
		{
			name:       "accepts 404 text/html (pre-filter only)",
			statusCode: 404,
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
				"Location":     []string{"/ztp/cgi-bin/"},
			},
			want: false,
		},
		{
			name:       "rejects application/json without Zyxel redirect",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			want: false,
		},
		{
			name:       "rejects unrelated redirect",
			statusCode: 302,
			headers: http.Header{
				"Location": []string{"/login"},
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

func TestZyxelFingerprinter_Fingerprint(t *testing.T) {
	f := &ZyxelFingerprinter{}

	tests := []struct {
		name           string
		statusCode     int
		headers        http.Header
		body           string
		wantResult     bool
		wantTech       string
		wantVersion    string
		wantCPEPrefix  string
		wantModel      string
	}{
		{
			name:       "detects ZTP handler in body (standalone signal)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body><form action="/ztp/cgi-bin/handler">Login</form></body></html>`,
			wantResult:    true,
			wantTech:      "zyxel-firewall",
			wantCPEPrefix: "cpe:2.3:o:zyxel:",
		},
		{
			name:       "detects from redirect to /ztp/cgi-bin/handler",
			statusCode: 302,
			headers: http.Header{
				"Location": []string{"/ztp/cgi-bin/handler"},
			},
			body:          ``,
			wantResult:    true,
			wantTech:      "zyxel-firewall",
			wantCPEPrefix: "cpe:2.3:o:zyxel:",
		},
		{
			name:       "detects from redirect to /weblogin.cgi",
			statusCode: 302,
			headers: http.Header{
				"Location": []string{"/weblogin.cgi"},
			},
			body:          ``,
			wantResult:    true,
			wantTech:      "zyxel-firewall",
			wantCPEPrefix: "cpe:2.3:o:zyxel:",
		},
		{
			name:       "detects Zyxel brand + model in body (corroborated)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><head><title>Zyxel ATP200</title></head><body>Welcome to Zyxel ATP200</body></html>`,
			wantResult:    true,
			wantTech:      "zyxel-firewall",
			wantCPEPrefix: "cpe:2.3:o:zyxel:atp_firmware:",
			wantModel:     "ATP200",
		},
		{
			name:       "detects weblogin.cgi + Zyxel brand in body (corroborated)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body><form action="/weblogin.cgi"><p>Zyxel Network</p></form></body></html>`,
			wantResult:    true,
			wantTech:      "zyxel-firewall",
			wantCPEPrefix: "cpe:2.3:o:zyxel:",
		},
		{
			name:       "does NOT detect from Zyxel brand alone (false positive prevention)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body>Zyxel routers were affected by a critical vulnerability.</body></html>`,
			wantResult: false,
		},
		{
			name:       "does NOT detect from unrelated HTML",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><head><title>Company Login</title></head><body><form action="/login">Login</form></body></html>`,
			wantResult: false,
		},
		{
			name:       "does NOT detect 500 error",
			statusCode: 500,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body>/ztp/cgi-bin/handler error</body></html>`,
			wantResult: false,
		},
		{
			name:       "extracts firmware version from body",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body><form action="/ztp/cgi-bin/handler">Version: V5.38(ABZH.0)</form></body></html>`,
			wantResult:    true,
			wantTech:      "zyxel-firewall",
			wantVersion:   "5.38",
			wantCPEPrefix: "cpe:2.3:o:zyxel:zld_firmware:5.38:",
		},
		{
			name:       "extracts model name and uses model-specific CPE",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: `<html><body>
<form action="/ztp/cgi-bin/handler">
<p>USG FLEX 200</p>
</form></body></html>`,
			wantResult:    true,
			wantTech:      "zyxel-firewall",
			wantCPEPrefix: "cpe:2.3:o:zyxel:usg_flex_firmware:",
			wantModel:     "USG FLEX 200",
		},
		{
			name:       "generates correct CPE for ATP model",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: `<html><body>
<form action="/ztp/cgi-bin/handler">
<p>Zyxel ATP500</p>
</form></body></html>`,
			wantResult:    true,
			wantTech:      "zyxel-firewall",
			wantCPEPrefix: "cpe:2.3:o:zyxel:atp_firmware:",
			wantModel:     "ATP500",
		},
		{
			name:       "generates correct CPE for VPN model",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: `<html><body>
<form action="/ztp/cgi-bin/handler">
<p>VPN300</p>
</form></body></html>`,
			wantResult:    true,
			wantTech:      "zyxel-firewall",
			wantCPEPrefix: "cpe:2.3:o:zyxel:vpn_firmware:",
			wantModel:     "VPN300",
		},
		{
			name:       "detects ZYXEL in all caps with model (case-insensitive brand)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><head><title>ZYXEL ATP200</title></head><body>ZYXEL ATP200 Login</body></html>`,
			wantResult:    true,
			wantTech:      "zyxel-firewall",
			wantModel:     "ATP200",
		},
		// Empty body with ZTP redirect — should detect from redirect alone
		{
			name:       "detects from redirect with empty body",
			statusCode: 302,
			headers: http.Header{
				"Location": []string{"/ztp/cgi-bin/handler"},
			},
			body:          "",
			wantResult:    true,
			wantTech:      "zyxel-firewall",
			wantCPEPrefix: "cpe:2.3:o:zyxel:zld_firmware:",
		},
		// Brand alone without model — should NOT detect
		{
			name:       "does NOT detect model keyword without Zyxel brand",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body>Configure your ATP200 device</body></html>`,
			wantResult: false,
		},
		// 404 response with Zyxel ZTP content — should still detect (4xx is accepted)
		{
			name:       "detects on 404 response with ZTP handler in body",
			statusCode: 404,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body>Error: /ztp/cgi-bin/handler not found</body></html>`,
			wantResult:    true,
			wantTech:      "zyxel-firewall",
		},
		// USG model (not FLEX, not ATP, not VPN) — tests the USG CPE branch
		{
			name:       "generates USG CPE for USG model",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:          `<html><body><form action="/ztp/cgi-bin/handler"><p>Zyxel USG40</p></form></body></html>`,
			wantResult:    true,
			wantTech:      "zyxel-firewall",
			wantCPEPrefix: "cpe:2.3:o:zyxel:usg_firmware:",
			wantModel:     "USG40",
		},
		// Redirect-only detection with no model — uses generic ZLD CPE
		{
			name:       "redirect-only detection uses generic ZLD CPE (no model available)",
			statusCode: 302,
			headers: http.Header{
				"Location": []string{"/ztp/cgi-bin/handler"},
			},
			body:          "",
			wantResult:    true,
			wantTech:      "zyxel-firewall",
			wantCPEPrefix: "cpe:2.3:o:zyxel:zld_firmware:",
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

func TestExtractZyxelVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "bare numeric version",
			input: "Firmware 5.38",
			want:  "5.38",
		},
		{
			name:  "V-prefix with build qualifier in parens",
			input: "Version: V5.38(ABZH.0)",
			want:  "5.38",
		},
		{
			name:  "bare version with build qualifier in parens",
			input: "5.38(ABZH.0)",
			want:  "", // no firmware context or V-prefix; avoids matching JS/CSS library versions
		},
		{
			name:  "V-prefix bare numeric",
			input: "V5.38",
			want:  "5.38",
		},
		{
			name:  "three-part version",
			input: "5.38.1",
			want:  "", // bare number with no firmware context or V-prefix
		},
		{
			name:  "returns empty when no version present",
			input: "<html><body>Welcome</body></html>",
			want:  "",
		},
		{
			name:  "rejects version trailed by letters",
			input: "version=5.38abc",
			want:  "",
		},
		{
			name:  "does not extract jQuery version from script path",
			input: `<script src="/js/jquery-3.7.1.min.js"></script><span>V5.38(ABZH.0)</span>`,
			want:  "5.38",
		},
		// Version exceeding length cap
		{
			name:  "rejects version exceeding length cap",
			input: "Firmware Version 12345678901234567890.1",
			want:  "",
		},
		// Multiple version strings — firmware context takes priority over bare numbers
		{
			name:  "extracts firmware version not jQuery version",
			input: `<script src="/js/jquery-3.7.1.min.js"></script>Firmware Version V5.38(ABZH.0)`,
			want:  "5.38",
		},
		// Version with only V prefix, no context keyword
		{
			name:  "extracts V-prefixed version as fallback",
			input: `<div>V4.60</div>`,
			want:  "4.60",
		},
		// No version at all in empty string
		{
			name:  "returns empty for empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractZyxelVersion(tt.input); got != tt.want {
				t.Errorf("extractZyxelVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractZyxelModel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "ATP200",
			input: "Welcome to ATP200",
			want:  "ATP200",
		},
		{
			name:  "USG FLEX 100",
			input: "USG FLEX 100 Administration",
			want:  "USG FLEX 100",
		},
		{
			name:  "USG FLEX 200H",
			input: "USG FLEX 200H Login",
			want:  "USG FLEX 200H",
		},
		{
			name:  "VPN300",
			input: "VPN300 Firewall",
			want:  "VPN300",
		},
		{
			name:  "USG40",
			input: "USG40 Administration",
			want:  "USG40",
		},
		{
			name:  "ATP100W",
			input: "Welcome to ATP100W",
			want:  "ATP100W",
		},
		{
			name:  "USG FLEX 50AX",
			input: "USG FLEX 50AX Login",
			want:  "USG FLEX 50AX",
		},
		{
			name:  "returns empty when no model found",
			input: "<html><body>Login Page</body></html>",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractZyxelModel(tt.input); got != tt.want {
				t.Errorf("extractZyxelModel(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildZyxelCPEs(t *testing.T) {
	tests := []struct {
		name    string
		product string
		version string
		wantCPE string
	}{
		{
			name:    "ATP with version",
			product: "atp_firmware",
			version: "5.38",
			wantCPE: "cpe:2.3:o:zyxel:atp_firmware:5.38:*:*:*:*:*:*:*",
		},
		{
			name:    "USG FLEX with version",
			product: "usg_flex_firmware",
			version: "5.38",
			wantCPE: "cpe:2.3:o:zyxel:usg_flex_firmware:5.38:*:*:*:*:*:*:*",
		},
		{
			name:    "USG FLEX H with version",
			product: "usg_flex_h_firmware",
			version: "5.38",
			wantCPE: "cpe:2.3:o:zyxel:usg_flex_h_firmware:5.38:*:*:*:*:*:*:*",
		},
		{
			name:    "VPN with version",
			product: "vpn_firmware",
			version: "5.38",
			wantCPE: "cpe:2.3:o:zyxel:vpn_firmware:5.38:*:*:*:*:*:*:*",
		},
		{
			name:    "ATP without version uses wildcard",
			product: "atp_firmware",
			version: "",
			wantCPE: "cpe:2.3:o:zyxel:atp_firmware:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpes := buildZyxelCPEs(tt.product, tt.version)
			if len(cpes) != 1 {
				t.Errorf("buildZyxelCPEs() returned %d CPEs, want 1", len(cpes))
				return
			}
			if cpes[0] != tt.wantCPE {
				t.Errorf("buildZyxelCPEs() = %q, want %q", cpes[0], tt.wantCPE)
			}
		})
	}
}

func TestZyxelFingerprinter_VersionRegexValidation(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "accepts valid 2-part version",
			input: "V5.38",
			want:  "5.38",
		},
		{
			name:  "accepts valid 3-part version",
			input: "5.38.1",
			want:  "", // bare number with no firmware context or V-prefix
		},
		{
			name:  "rejects injection attempt with semicolon",
			input: "5.38;DROP TABLE",
			want:  "", // bare number with no firmware context or V-prefix
		},
		{
			name:  "rejects oversized version (length cap)",
			input: "12345678901234567890.1",
			want:  "", // exceeds zyxelMaxVersionLen after capture
		},
		{
			name:  "rejects version with only letters",
			input: "abc.def",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractZyxelVersion(tt.input)
			if got != tt.want {
				t.Errorf("extractZyxelVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestZyxelFingerprinter_ActiveInterface verifies that ZyxelFingerprinter
// implements the ActiveHTTPFingerprinter interface.
func TestZyxelFingerprinter_ActiveInterface(t *testing.T) {
	var _ ActiveHTTPFingerprinter = (*ZyxelFingerprinter)(nil)
}

func TestZyxelCPEProduct(t *testing.T) {
	tests := []struct {
		name  string
		model string
		want  string
	}{
		{name: "empty model defaults to zld_firmware", model: "", want: "zld_firmware"},
		{name: "ATP model", model: "ATP200", want: "atp_firmware"},
		{name: "USG FLEX model", model: "USG FLEX 100", want: "usg_flex_firmware"},
		{name: "USG FLEX H model via suffix", model: "USG FLEX 200H", want: "usg_flex_h_firmware"},
		{name: "USG FLEX AX model", model: "USG FLEX 50AX", want: "usg_flex_firmware"},
		{name: "VPN model", model: "VPN300", want: "vpn_firmware"},
		{name: "USG model", model: "USG40", want: "usg_firmware"},
		{name: "USG-VPN model", model: "USG20-VPN", want: "usg_firmware"},
		{name: "ATP W variant", model: "ATP100W", want: "atp_firmware"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := zyxelCPEProduct(tt.model); got != tt.want {
				t.Errorf("zyxelCPEProduct(%q) = %q, want %q", tt.model, got, tt.want)
			}
		})
	}
}

func TestZyxelFingerprinter_HTTPTest(t *testing.T) {
	mux := http.NewServeMux()

	// Route 1: Root redirects to ZTP handler (like real Zyxel)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ztp/cgi-bin/handler", http.StatusFound)
	})

	// Route 2: ZTP handler serves login page
	mux.HandleFunc("/ztp/cgi-bin/handler", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Zyxel ATP200</title></head>
<body>
<div id="login-header">Zyxel ATP200</div>
<form id="loginForm" action="/ztp/cgi-bin/handler" method="post">
<input type="text" name="username" />
<input type="password" name="password" />
<span class="firmware">Firmware Version V5.38(ABZH.0)</span>
</form>
</body></html>`)
	})

	// Route 3: Legacy weblogin.cgi
	mux.HandleFunc("/weblogin.cgi", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><h1>Zyxel USG FLEX 100</h1>
<form action="/weblogin.cgi" method="post">Login</form></body></html>`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	fp := &ZyxelFingerprinter{}

	// Test 1: Root redirect
	t.Run("root_redirect_detected", func(t *testing.T) {
		client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		}}
		resp, err := client.Get(srv.URL + "/")
		if err != nil {
			t.Fatalf("GET / failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if !fp.Match(resp) {
			t.Fatal("Match() returned false for redirect to ZTP")
		}
		result, err := fp.Fingerprint(resp, body)
		if err != nil {
			t.Fatalf("Fingerprint() error: %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil for ZTP redirect")
		}
		if result.Technology != "zyxel-firewall" {
			t.Errorf("Technology = %q, want zyxel-firewall", result.Technology)
		}
	})

	// Test 2: ZTP handler login page
	t.Run("ztp_login_page_detected", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/ztp/cgi-bin/handler")
		if err != nil {
			t.Fatalf("GET /ztp/cgi-bin/handler failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if !fp.Match(resp) {
			t.Fatal("Match() returned false for ZTP login page")
		}
		result, err := fp.Fingerprint(resp, body)
		if err != nil {
			t.Fatalf("Fingerprint() error: %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil for ZTP login page")
		}
		if result.Technology != "zyxel-firewall" {
			t.Errorf("Technology = %q, want zyxel-firewall", result.Technology)
		}
		if result.Version != "5.38" {
			t.Errorf("Version = %q, want 5.38", result.Version)
		}
		if m, ok := result.Metadata["product_model"]; ok {
			if m != "ATP200" {
				t.Errorf("product_model = %q, want ATP200", m)
			}
		} else {
			t.Error("product_model not in metadata")
		}
	})

	// Test 3: Legacy weblogin.cgi
	t.Run("weblogin_page_detected", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/weblogin.cgi")
		if err != nil {
			t.Fatalf("GET /weblogin.cgi failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if !fp.Match(resp) {
			t.Fatal("Match() returned false for weblogin.cgi")
		}
		result, err := fp.Fingerprint(resp, body)
		if err != nil {
			t.Fatalf("Fingerprint() error: %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil for weblogin.cgi page")
		}
		if result.Technology != "zyxel-firewall" {
			t.Errorf("Technology = %q, want zyxel-firewall", result.Technology)
		}
	})
}

// TestZyxelFingerprinter_ShodanVectors tests detection against realistic
// Zyxel ZLD management interface response patterns.
func TestZyxelFingerprinter_ShodanVectors(t *testing.T) {
	f := &ZyxelFingerprinter{}

	tests := []struct {
		name        string
		description string
		statusCode  int
		headers     http.Header
		body        string
		wantTech    string
		wantVersion string
	}{
		{
			name:        "Shodan Vector 1: Zyxel ATP200 login page (port 443)",
			description: "Admin login page with ZTP handler in action and model branding",
			statusCode:  200,
			headers: http.Header{
				"Content-Type":    []string{"text/html; charset=UTF-8"},
				"X-Frame-Options": []string{"SAMEORIGIN"},
			},
			body: `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Zyxel ATP200</title>
</head>
<body>
<div id="login-header">Zyxel ATP200</div>
<form id="loginForm" action="/ztp/cgi-bin/handler" method="post">
<input type="text" name="username" />
<input type="password" name="password" />
<span class="firmware">V5.38(ABZH.0)</span>
</form>
</body>
</html>`,
			wantTech:    "zyxel-firewall",
			wantVersion: "5.38",
		},
		{
			name:        "Shodan Vector 2: Zyxel USG FLEX 200 redirect (port 443)",
			description: "Root path redirects to /ztp/cgi-bin/ before login page",
			statusCode:  302,
			headers: http.Header{
				"Location":     []string{"/ztp/cgi-bin/handler"},
				"Content-Type": []string{"text/html"},
			},
			body:        ``,
			wantTech:    "zyxel-firewall",
			wantVersion: "",
		},
		{
			name:        "Shodan Vector 3: Zyxel USG FLEX 100 weblogin redirect",
			description: "Older ZLD firmware redirect pattern to /weblogin.cgi",
			statusCode:  302,
			headers: http.Header{
				"Location": []string{"/weblogin.cgi"},
			},
			body:        ``,
			wantTech:    "zyxel-firewall",
			wantVersion: "",
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

			if result == nil {
				t.Errorf("Fingerprint() returned nil for Shodan vector: %s", tt.description)
				return
			}

			if result.Technology != tt.wantTech {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
			}

			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			if len(result.CPEs) != 1 {
				t.Errorf("CPEs length = %d, want 1", len(result.CPEs))
			}

			if len(result.CPEs) > 0 {
				if !strings.HasPrefix(result.CPEs[0], "cpe:2.3:o:zyxel:") {
					t.Errorf("CPE[0] = %q, want prefix cpe:2.3:o:zyxel:", result.CPEs[0])
				}
			}
		})
	}
}

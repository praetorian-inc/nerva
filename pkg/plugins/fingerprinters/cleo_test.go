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

// ── Name / ProbeEndpoint ───────────────────────────────────────────────────────

func TestCleoFingerprinter_Name(t *testing.T) {
	fp := &CleoFingerprinter{}
	if got := fp.Name(); got != "cleo" {
		t.Errorf("Name() = %q, want %q", got, "cleo")
	}
}

func TestCleoFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &CleoFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/Synchronization" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/Synchronization")
	}
}

// ── Match ──────────────────────────────────────────────────────────────────────

func TestCleoFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		server     string
		want       bool
	}{
		{name: "200 OK passes", statusCode: 200, want: true},
		{name: "302 redirect passes", statusCode: 302, want: true},
		{name: "404 Not Found passes", statusCode: 404, want: true},
		{name: "499 passes (upper boundary)", statusCode: 499, want: true},
		{name: "100 Informational rejected", statusCode: 100, want: false},
		{name: "500 Internal Server Error rejected", statusCode: 500, want: false},
		{name: "503 Service Unavailable rejected", statusCode: 503, want: false},
		{name: "Server: Cleo Harmony header passes", statusCode: 200, server: "Cleo Harmony/5.8.0.21", want: true},
		{name: "Server: nginx still passes on status", statusCode: 200, server: "nginx/1.24.0", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CleoFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ── Fingerprint: positive (valid) ─────────────────────────────────────────────

func TestCleoFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		server        string
		wwwAuth       string
		body          string
		wantVariant   string
		wantVersion   string
		wantCPE       string
		wantDetection string
	}{
		{
			name:          "Harmony server header with four-part version",
			statusCode:    200, server: "Cleo Harmony/5.8.0.21",
			wantVariant: "Harmony", wantVersion: "5.8.0.21",
			wantCPE: "cpe:2.3:a:cleo:harmony:5.8.0.21:*:*:*:*:*:*:*", wantDetection: "server_header",
		},
		{
			name:          "VLTrader server header with version",
			statusCode:    200, server: "Cleo VLTrader/5.8.0.24",
			wantVariant: "VLTrader", wantVersion: "5.8.0.24",
			wantCPE: "cpe:2.3:a:cleo:vltrader:5.8.0.24:*:*:*:*:*:*:*", wantDetection: "server_header",
		},
		{
			name:          "LexiCom server header with version",
			statusCode:    200, server: "Cleo LexiCom/5.7.0.1",
			wantVariant: "LexiCom", wantVersion: "5.7.0.1",
			wantCPE: "cpe:2.3:a:cleo:lexicom:5.7.0.1:*:*:*:*:*:*:*", wantDetection: "server_header",
		},
		{
			name:          "Server header with Linux OS suffix tolerated",
			statusCode:    200, server: "Cleo Harmony/5.8.0.21 (Linux)",
			wantVariant: "Harmony", wantVersion: "5.8.0.21",
			wantCPE: "cpe:2.3:a:cleo:harmony:5.8.0.21:*:*:*:*:*:*:*", wantDetection: "server_header",
		},
		{
			name:          "Server header with Windows OS suffix tolerated",
			statusCode:    200, server: "Cleo VLTrader/5.8.0.24 (Windows Server 2019)",
			wantVariant: "VLTrader", wantVersion: "5.8.0.24",
			wantCPE: "cpe:2.3:a:cleo:vltrader:5.8.0.24:*:*:*:*:*:*:*", wantDetection: "server_header",
		},
		{
			name:       "Server header + versalex web portal marker → body+server_header",
			statusCode: 200, server: "Cleo Harmony/5.8.0.21",
			body:          "<html><body>VersaLex Web Portal</body></html>",
			wantVariant: "Harmony", wantVersion: "5.8.0.21",
			wantCPE: "cpe:2.3:a:cleo:harmony:5.8.0.21:*:*:*:*:*:*:*", wantDetection: "body+server_header",
		},
		{
			name:       "Server header + mftportal marker → body+server_header",
			statusCode: 200, server: "Cleo VLTrader/5.8.0.24",
			body:          "<html><body><div class=\"mftportal\">x</div></body></html>",
			wantVariant: "VLTrader", wantVersion: "5.8.0.24",
			wantCPE: "cpe:2.3:a:cleo:vltrader:5.8.0.24:*:*:*:*:*:*:*", wantDetection: "body+server_header",
		},
		{
			name:       "Server header + vlportal marker → body+server_header",
			statusCode: 200, server: "Cleo LexiCom/5.7.0.1",
			body:          "<html><body><div id=\"VLPortal\">x</div></body></html>",
			wantVariant: "LexiCom", wantVersion: "5.7.0.1",
			wantCPE: "cpe:2.3:a:cleo:lexicom:5.7.0.1:*:*:*:*:*:*:*", wantDetection: "body+server_header",
		},
		{
			name:          "WWW-Authenticate Basic realm Cleo Harmony → www_authenticate",
			statusCode:    401, wwwAuth: `Basic realm="Cleo Harmony"`,
			wantVariant: "Harmony", wantVersion: "",
			wantCPE: "cpe:2.3:a:cleo:harmony:*:*:*:*:*:*:*:*", wantDetection: "www_authenticate",
		},
		{
			name:          "WWW-Authenticate Basic realm Cleo VLTrader → www_authenticate",
			statusCode:    401, wwwAuth: `Basic realm="Cleo VLTrader"`,
			wantVariant: "VLTrader", wantVersion: "",
			wantCPE: "cpe:2.3:a:cleo:vltrader:*:*:*:*:*:*:*:*", wantDetection: "www_authenticate",
		},
		{
			name:          "WWW-Authenticate Basic realm Cleo LexiCom → www_authenticate",
			statusCode:    401, wwwAuth: `Basic realm="Cleo LexiCom"`,
			wantVariant: "LexiCom", wantVersion: "",
			wantCPE: "cpe:2.3:a:cleo:lexicom:*:*:*:*:*:*:*:*", wantDetection: "www_authenticate",
		},
		{
			name:       "Harmony body title detection (no server header)",
			statusCode: 200,
			body:       "<html><head><title>Cleo Harmony</title></head><body><h1>Cleo Harmony</h1></body></html>",
			wantVariant: "Harmony", wantVersion: "",
			wantCPE: "cpe:2.3:a:cleo:harmony:*:*:*:*:*:*:*:*", wantDetection: "body",
		},
		{
			name:       "VLTrader body detection",
			statusCode: 200,
			body:       "<html><head><title>Cleo VLTrader</title></head><body>Welcome to Cleo VLTrader</body></html>",
			wantVariant: "VLTrader", wantVersion: "",
			wantCPE: "cpe:2.3:a:cleo:vltrader:*:*:*:*:*:*:*:*", wantDetection: "body",
		},
		{
			name:       "LexiCom body detection",
			statusCode: 200,
			body:       "<html><head><title>Cleo LexiCom</title></head><body>Cleo LexiCom sign-in</body></html>",
			wantVariant: "LexiCom", wantVersion: "",
			wantCPE: "cpe:2.3:a:cleo:lexicom:*:*:*:*:*:*:*:*", wantDetection: "body",
		},
		{
			name:       "Server header takes priority over body",
			statusCode: 200, server: "Cleo Harmony/5.8.0.21",
			body:          "<html><head><title>Cleo Harmony</title></head><body><h1>Cleo Harmony</h1></body></html>",
			wantVariant: "Harmony", wantVersion: "5.8.0.21",
			wantCPE: "cpe:2.3:a:cleo:harmony:5.8.0.21:*:*:*:*:*:*:*", wantDetection: "server_header",
		},
		{
			name:          "302 redirect with Harmony header passes",
			statusCode:    302, server: "Cleo Harmony/5.8.0.21",
			wantVariant: "Harmony", wantVersion: "5.8.0.21",
			wantCPE: "cpe:2.3:a:cleo:harmony:5.8.0.21:*:*:*:*:*:*:*", wantDetection: "server_header",
		},
		{
			name:          "Two-component version (major.minor) is valid",
			statusCode:    200, server: "Cleo Harmony/5.8",
			wantVariant: "Harmony", wantVersion: "5.8",
			wantCPE: "cpe:2.3:a:cleo:harmony:5.8:*:*:*:*:*:*:*", wantDetection: "server_header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CleoFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.wwwAuth != "" {
				resp.Header.Set("WWW-Authenticate", tt.wwwAuth)
			}
			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want non-nil result")
			}
			if result.Technology != "cleo" {
				t.Errorf("Technology = %q, want cleo", result.Technology)
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			} else if result.CPEs[0] != tt.wantCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], tt.wantCPE)
			}
			if result.Metadata == nil {
				t.Fatal("Metadata is nil")
			}
			if prod, ok := result.Metadata["product"].(string); !ok || prod != tt.wantVariant {
				t.Errorf("Metadata[product] = %v, want %q", result.Metadata["product"], tt.wantVariant)
			}
			if dm, ok := result.Metadata["detection_method"].(string); !ok || dm != tt.wantDetection {
				t.Errorf("Metadata[detection_method] = %v, want %q", result.Metadata["detection_method"], tt.wantDetection)
			}
		})
	}
}

// ── Fingerprint: negative (must return nil) ────────────────────────────────────

func TestCleoFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		server     string
		wwwAuth    string
		body       string
	}{
		{name: "Generic nginx page", statusCode: 200, server: "nginx/1.24.0", body: "<html><head><title>Welcome to nginx</title></head></html>"},
		{name: "Microsoft IIS default page", statusCode: 200, server: "Microsoft-IIS/10.0", body: "<html><head><title>IIS Windows Server</title></head></html>"},
		{name: "Brand substring false positive: Harmony without Cleo prefix", statusCode: 200, body: "<html><head><title>Harmony Portal</title></head><body>Harmony admin</body></html>"},
		{name: "Brand substring false positive: VLTrader without Cleo", statusCode: 200, body: "<html><body>VLTrader info no cleo</body></html>"},
		{name: "Single weak body marker alone is insufficient (versalex web portal)", statusCode: 200, body: "<html><body>VersaLex Web Portal</body></html>"},
		{name: "Single weak body marker alone is insufficient (mftportal)", statusCode: 200, body: "<html><body><div class=\"mftportal\">x</div></body></html>"},
		{name: "Single weak body marker alone is insufficient (vlportal)", statusCode: 200, body: "<html><body><div id=\"VLPortal\">x</div></body></html>"},
		{name: "WWW-Authenticate non-Cleo realm", statusCode: 401, wwwAuth: `Basic realm="My Application"`},
		{name: "CPE-injection attempt", statusCode: 200, body: "<html><title>Cleo Harmony</title><body>version:*:malicious</body></html>"},
		{name: "Body length > 2 MiB rejected", statusCode: 200, body: "cleo harmony" + string(make([]byte, 2*1024*1024+1))},
		{name: "Status 500 rejected", statusCode: 500, server: "Cleo Harmony/5.8.0.21", body: "<html><title>Cleo Harmony</title></html>"},
		{name: "Status 503 rejected", statusCode: 503, body: "<html><title>Cleo Harmony</title></html>"},
		{name: "Empty body and no Cleo server header", statusCode: 200},
		{name: "Cleo in body but no recognized variant", statusCode: 200, body: "<html><title>Cleo Admin</title><body>Cleo admin panel</body></html>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CleoFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.wwwAuth != "" {
				resp.Header.Set("WWW-Authenticate", tt.wwwAuth)
			}
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

// ── Header-only matching ───────────────────────────────────────────────────────

func TestCleoFingerprinter_HeaderOnlyMatch(t *testing.T) {
	fp := &CleoFingerprinter{}

	t.Run("Cleo Harmony server header with empty body produces result", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
		resp.Header.Set("Server", "Cleo Harmony/5.8.0.21")
		result, err := fp.Fingerprint(resp, []byte(""))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil, want non-nil")
		}
		if dm, ok := result.Metadata["detection_method"].(string); !ok || dm != "server_header" {
			t.Errorf("detection_method = %v, want server_header", result.Metadata["detection_method"])
		}
		if prod, ok := result.Metadata["product"].(string); !ok || prod != "Harmony" {
			t.Errorf("product = %v, want Harmony", result.Metadata["product"])
		}
	})

	t.Run("Cleo VLTrader server header with empty body produces result", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
		resp.Header.Set("Server", "Cleo VLTrader/5.8.0.24")
		result, err := fp.Fingerprint(resp, []byte(""))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil, want non-nil")
		}
		if prod, ok := result.Metadata["product"].(string); !ok || prod != "VLTrader" {
			t.Errorf("product = %v, want VLTrader", result.Metadata["product"])
		}
	})

	t.Run("Generic nginx server header with empty body returns nil", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
		resp.Header.Set("Server", "nginx/1.24.0")
		result, err := fp.Fingerprint(resp, []byte(""))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result != nil {
			t.Errorf("Fingerprint() = %+v, want nil for nginx", result)
		}
	})

	t.Run("server_header metadata key present", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
		resp.Header.Set("Server", "Cleo LexiCom/5.7.0.1")
		result, err := fp.Fingerprint(resp, []byte(""))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil")
		}
		if sh, ok := result.Metadata["server_header"].(string); !ok || sh == "" {
			t.Errorf("Metadata[server_header] = %v, want non-empty", result.Metadata["server_header"])
		}
	})
}

// ── WWW-Authenticate unit tests ────────────────────────────────────────────────

func TestExtractCleoFromWWWAuthenticate(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		wantVariant string
		wantMethod  string
	}{
		{name: "Basic realm Cleo Harmony", headerValue: `Basic realm="Cleo Harmony"`, wantVariant: "Harmony", wantMethod: "www_authenticate"},
		{name: "Basic realm Cleo VLTrader", headerValue: `Basic realm="Cleo VLTrader"`, wantVariant: "VLTrader", wantMethod: "www_authenticate"},
		{name: "Basic realm Cleo LexiCom", headerValue: `Basic realm="Cleo LexiCom"`, wantVariant: "LexiCom", wantMethod: "www_authenticate"},
		{name: "Non-Cleo realm returns empty", headerValue: `Basic realm="My App"`, wantVariant: "", wantMethod: ""},
		{name: "Empty header returns empty", headerValue: "", wantVariant: "", wantMethod: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := make(http.Header)
			if tt.headerValue != "" {
				header.Set("WWW-Authenticate", tt.headerValue)
			}
			variant, method := extractCleoFromWWWAuthenticate(header)
			if variant != tt.wantVariant {
				t.Errorf("variant = %q, want %q", variant, tt.wantVariant)
			}
			if method != tt.wantMethod {
				t.Errorf("method = %q, want %q", method, tt.wantMethod)
			}
		})
	}
}

// ── TestExtractCleoFromServerHeader ───────────────────────────────────────────

func TestExtractCleoFromServerHeader(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		wantVariant string
		wantVersion string
		wantMethod  string
	}{
		{name: "Harmony with four-part version", header: "Cleo Harmony/5.8.0.21", wantVariant: "Harmony", wantVersion: "5.8.0.21", wantMethod: "server_header"},
		{name: "VLTrader with three-part version", header: "Cleo VLTrader/5.8.0", wantVariant: "VLTrader", wantVersion: "5.8.0", wantMethod: "server_header"},
		{name: "LexiCom with two-part version", header: "Cleo LexiCom/5.7", wantVariant: "LexiCom", wantVersion: "5.7", wantMethod: "server_header"},
		{name: "Harmony with Linux OS suffix", header: "Cleo Harmony/5.8.0.21 (Linux)", wantVariant: "Harmony", wantVersion: "5.8.0.21", wantMethod: "server_header"},
		{name: "VLTrader with Windows OS suffix", header: "Cleo VLTrader/5.8.0.24 (Windows Server 2019)", wantVariant: "VLTrader", wantVersion: "5.8.0.24", wantMethod: "server_header"},
		{name: "Unknown variant not matched", header: "Cleo Enterprise/1.0.0", wantVariant: "", wantVersion: "", wantMethod: ""},
		{name: "Empty header", header: "", wantVariant: "", wantVersion: "", wantMethod: ""},
		{name: "nginx header not matched", header: "nginx/1.24.0", wantVariant: "", wantVersion: "", wantMethod: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variant, version, method := extractCleoFromServerHeader(tt.header)
			if variant != tt.wantVariant {
				t.Errorf("variant = %q, want %q", variant, tt.wantVariant)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
			if method != tt.wantMethod {
				t.Errorf("method = %q, want %q", method, tt.wantMethod)
			}
		})
	}
}

// ── TestBuildCleoCPE ───────────────────────────────────────────────────────────

func TestBuildCleoCPE(t *testing.T) {
	tests := []struct {
		name    string
		variant string
		version string
		want    string
	}{
		{name: "Harmony with version", variant: "Harmony", version: "5.8.0.21", want: "cpe:2.3:a:cleo:harmony:5.8.0.21:*:*:*:*:*:*:*"},
		{name: "VLTrader with version", variant: "VLTrader", version: "5.8.0.24", want: "cpe:2.3:a:cleo:vltrader:5.8.0.24:*:*:*:*:*:*:*"},
		{name: "LexiCom with version", variant: "LexiCom", version: "5.7.0.1", want: "cpe:2.3:a:cleo:lexicom:5.7.0.1:*:*:*:*:*:*:*"},
		{name: "Harmony empty version uses wildcard", variant: "Harmony", version: "", want: "cpe:2.3:a:cleo:harmony:*:*:*:*:*:*:*:*"},
		{name: "VLTrader empty version uses wildcard", variant: "VLTrader", version: "", want: "cpe:2.3:a:cleo:vltrader:*:*:*:*:*:*:*:*"},
		{name: "LexiCom empty version uses wildcard", variant: "LexiCom", version: "", want: "cpe:2.3:a:cleo:lexicom:*:*:*:*:*:*:*:*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildCleoCPE(tt.variant, tt.version); got != tt.want {
				t.Errorf("buildCleoCPE(%q, %q) = %q, want %q", tt.variant, tt.version, got, tt.want)
			}
		})
	}
}

// ── Integration test ──────────────────────────────────────────────────────────

func TestCleoFingerprinter_Integration(t *testing.T) {
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &CleoFingerprinter{}
	Register(fp)

	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Server", "Cleo Harmony/5.8.0.21")

	results := RunFingerprinters(resp, []byte(""))

	found := false
	for _, result := range results {
		if result.Technology == "cleo" {
			found = true
			if result.Version != "5.8.0.21" {
				t.Errorf("Version = %q, want 5.8.0.21", result.Version)
			}
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			} else if result.CPEs[0] != "cpe:2.3:a:cleo:harmony:5.8.0.21:*:*:*:*:*:*:*" {
				t.Errorf("CPE = %q, want canonical CPE", result.CPEs[0])
			}
			if v, ok := result.Metadata["vendor"].(string); !ok || v != "Cleo" {
				t.Errorf("Metadata[vendor] = %v, want Cleo", result.Metadata["vendor"])
			}
			if prod, ok := result.Metadata["product"].(string); !ok || prod != "Harmony" {
				t.Errorf("Metadata[product] = %v, want Harmony", result.Metadata["product"])
			}
		}
	}
	if !found {
		t.Error("CleoFingerprinter not found in RunFingerprinters results")
	}
}

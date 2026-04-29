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
	"net/url"
	"testing"
)

// ── Name / ProbeEndpoint ───────────────────────────────────────────────────────

func TestCrushFTPFingerprinter_Name(t *testing.T) {
	fp := &CrushFTPFingerprinter{}
	if got := fp.Name(); got != "crushftp" {
		t.Errorf("Name() = %q, want %q", got, "crushftp")
	}
}

func TestCrushFTPFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &CrushFTPFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/WebInterface/" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/WebInterface/")
	}
}

// ── Match ──────────────────────────────────────────────────────────────────────

func TestCrushFTPFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{name: "200 OK passes", statusCode: 200, want: true},
		{name: "302 redirect passes", statusCode: 302, want: true},
		{name: "404 Not Found passes", statusCode: 404, want: true},
		{name: "499 passes (upper boundary)", statusCode: 499, want: true},
		{name: "100 Informational rejected", statusCode: 100, want: false},
		{name: "500 Internal Server Error rejected", statusCode: 500, want: false},
		{name: "503 Service Unavailable rejected", statusCode: 503, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CrushFTPFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ── Fingerprint: positive (valid) ─────────────────────────────────────────────

func TestCrushFTPFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		server        string
		p3p           string
		cookies       [][2]string // [name, value] pairs to set as Set-Cookie headers
		body          string
		probePath     string
		wantVersion   string
		wantCPE       string
		wantDetection string
		wantProbePath string
	}{
		{
			// Server header is "CrushFTP HTTP Server" (fixed, no version). Detection fires
			// because "crushftp" appears in the server header value.
			name:          "Server header match (fixed string, no version)",
			statusCode:    200,
			server:        "CrushFTP HTTP Server",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*",
			wantDetection: "server_header",
		},
		{
			name:       "Title CrushFTP WebInterface detected",
			statusCode: 200,
			body:       "<html><head><title>CrushFTP WebInterface</title></head><body>Login</body></html>",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*",
			wantDetection: "title",
		},
		{
			name:       "Title CrushFTP - Login detected",
			statusCode: 200,
			body:       "<html><head><title>CrushFTP - Login</title></head><body>Login</body></html>",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*",
			wantDetection: "title",
		},
		{
			name:       "Asset path crushftp.customize.js in body",
			statusCode: 200,
			body:       `<html><head><script src="/WebInterface/Resources/js/crushftp.customize.js"></script></head></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*",
			wantDetection: "asset_path",
		},
		{
			name:       "P3P header with CrushFTP path detected",
			statusCode: 200,
			p3p:        `/WebInterface/w3c/p3p.xml`,
			// p3p alone with wrong path should not detect — we need the specific path
			body:          "<html><body></body></html>",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*",
			wantDetection: "p3p_header",
		},
		{
			name:       "Cookie pair CrushAuth + currentAuth detected",
			statusCode: 200,
			cookies:    [][2]string{{"CrushAuth", "abc"}, {"currentAuth", "xyz"}},
			body:       "<html><body></body></html>",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*",
			wantDetection: "cookies",
		},
		{
			name:       "Meta generator tag provides version",
			statusCode: 200,
			body:       `<html><head><title>CrushFTP WebInterface</title><meta name="generator" content="CrushFTP 10.7.0"></head></html>`,
			wantVersion:   "10.7.0",
			wantCPE:       "cpe:2.3:a:crushftp:crushftp:10.7.0:*:*:*:*:*:*:*",
			wantDetection: "title",
		},
		{
			// server_header > cookies > p3p_header > title > asset_path
			name:          "Detection priority: server_header beats cookies",
			statusCode:    200,
			server:        "CrushFTP HTTP Server",
			cookies:       [][2]string{{"CrushAuth", "a"}, {"currentAuth", "b"}},
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*",
			wantDetection: "server_header",
		},
		{
			name:          "Detection priority: cookies beat p3p_header",
			statusCode:    200,
			p3p:           `/WebInterface/w3c/p3p.xml`,
			cookies:       [][2]string{{"CrushAuth", "a"}, {"currentAuth", "b"}},
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*",
			wantDetection: "cookies",
		},
		{
			// /WebInterface/ is the primary probe endpoint
			name:          "Active probe: /WebInterface/ sets probe_path",
			statusCode:    404,
			probePath:     "/WebInterface/",
			cookies:       [][2]string{{"CrushAuth", "x"}, {"currentAuth", "y"}},
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*",
			wantDetection: "cookies",
			wantProbePath: "/WebInterface/",
		},
		{
			// /WebInterface/login.html is also accepted per implementation
			name:          "Active probe: /WebInterface/login.html also accepted",
			statusCode:    200,
			probePath:     "/WebInterface/login.html",
			body:          "<html><head><title>CrushFTP WebInterface</title></head></html>",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*",
			wantDetection: "title",
			wantProbePath: "/WebInterface/login.html",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CrushFTPFingerprinter{}
			header := make(http.Header)
			if tt.server != "" {
				header.Set("Server", tt.server)
			}
			if tt.p3p != "" {
				header.Set("P3P", tt.p3p)
			}
			for _, c := range tt.cookies {
				cookie := &http.Cookie{Name: c[0], Value: c[1]}
				header.Add("Set-Cookie", cookie.String())
			}
			resp := &http.Response{StatusCode: tt.statusCode, Header: header}
			if tt.probePath != "" {
				resp.Request = &http.Request{URL: &url.URL{Path: tt.probePath}}
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want non-nil")
			}
			if result.Technology != "crushftp" {
				t.Errorf("Technology = %q, want crushftp", result.Technology)
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
			if dm, ok := result.Metadata["detection_method"].(string); !ok || dm != tt.wantDetection {
				t.Errorf("Metadata[detection_method] = %v, want %q", result.Metadata["detection_method"], tt.wantDetection)
			}
			if tt.wantProbePath != "" {
				if pp, ok := result.Metadata["probe_path"].(string); !ok || pp != tt.wantProbePath {
					t.Errorf("Metadata[probe_path] = %v, want %q", result.Metadata["probe_path"], tt.wantProbePath)
				}
			}
		})
	}
}

// ── Fingerprint: negative (must return nil) ────────────────────────────────────

func TestCrushFTPFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		server     string
		p3p        string
		cookies    [][2]string
		body       string
	}{
		{name: "Generic nginx page", statusCode: 200, server: "nginx/1.24.0", body: "<html><title>Welcome to nginx</title></html>"},
		{name: "Microsoft IIS page", statusCode: 200, server: "Microsoft-IIS/10.0", body: "<html><title>IIS Windows Server</title></html>"},
		{name: "Title CrushIQ Analytics (not CrushFTP)", statusCode: 200, body: "<html><head><title>CrushIQ Analytics</title></head><body>crush data</body></html>"},
		{name: "Title CrushFTP Admin (unrecognized format)", statusCode: 200, body: "<html><head><title>CrushFTP Admin</title></head><body>some content</body></html>"},
		{
			// Only CrushAuth, missing currentAuth — pair incomplete
			name:       "Only CrushAuth cookie (no currentAuth) → nil",
			statusCode: 200,
			cookies:    [][2]string{{"CrushAuth", "abc"}},
			body:       "<html><body></body></html>",
		},
		{
			// Only currentAuth, missing CrushAuth — pair incomplete
			name:       "Only currentAuth cookie (no CrushAuth) → nil",
			statusCode: 200,
			cookies:    [][2]string{{"currentAuth", "xyz"}},
			body:       "<html><body></body></html>",
		},
		{
			// P3P header present but with wrong path
			name:       "P3P header with wrong path → nil",
			statusCode: 200,
			p3p:        `CP="NOI ADM DEV"`,
			body:       "<html><body></body></html>",
		},
		{name: "CPE-injection attempt", statusCode: 200, server: "CrushFTP HTTP Server", body: "<html><body>version:*:malicious</body></html>"},
		{name: "Body length > 2 MiB rejected", statusCode: 200, body: "<title>CrushFTP WebInterface</title>" + string(make([]byte, 2*1024*1024+1))},
		{name: "Status 500 rejected", statusCode: 500, server: "CrushFTP HTTP Server", body: "<html><title>CrushFTP WebInterface</title></html>"},
		{name: "Status 503 rejected", statusCode: 503, body: "<html><title>CrushFTP WebInterface</title></html>"},
		{name: "Empty body and no crushftp server header", statusCode: 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CrushFTPFingerprinter{}
			header := make(http.Header)
			if tt.server != "" {
				header.Set("Server", tt.server)
			}
			if tt.p3p != "" {
				header.Set("P3P", tt.p3p)
			}
			for _, c := range tt.cookies {
				cookie := &http.Cookie{Name: c[0], Value: c[1]}
				header.Add("Set-Cookie", cookie.String())
			}
			resp := &http.Response{StatusCode: tt.statusCode, Header: header}

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

// ── P3P header detection ───────────────────────────────────────────────────────

func TestCrushFTPFingerprinter_P3PDetection(t *testing.T) {
	fp := &CrushFTPFingerprinter{}

	t.Run("P3P header with /WebInterface/w3c/p3p.xml detected", func(t *testing.T) {
		header := make(http.Header)
		header.Set("P3P", `CP="IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT" /WebInterface/w3c/p3p.xml`)
		resp := &http.Response{StatusCode: 200, Header: header}

		result, err := fp.Fingerprint(resp, []byte("<html></html>"))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil, want detection from P3P header")
		}
		if dm, ok := result.Metadata["detection_method"].(string); !ok || dm != "p3p_header" {
			t.Errorf("detection_method = %v, want p3p_header", result.Metadata["detection_method"])
		}
	})

	t.Run("P3P header without CrushFTP path returns nil", func(t *testing.T) {
		header := make(http.Header)
		header.Set("P3P", `CP="IDC DSP COR ADM"`)
		resp := &http.Response{StatusCode: 200, Header: header}

		result, err := fp.Fingerprint(resp, []byte("<html></html>"))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result != nil {
			t.Errorf("Fingerprint() = %+v, want nil for wrong P3P path", result)
		}
	})
}

// ── Cookie pair detection ──────────────────────────────────────────────────────

func TestCrushFTPHasCookiePair(t *testing.T) {
	t.Run("Both CrushAuth and currentAuth present", func(t *testing.T) {
		header := make(http.Header)
		header.Add("Set-Cookie", (&http.Cookie{Name: "CrushAuth", Value: "abc"}).String())
		header.Add("Set-Cookie", (&http.Cookie{Name: "currentAuth", Value: "xyz"}).String())
		resp := &http.Response{StatusCode: 200, Header: header}
		if !crushFTPHasCookiePair(resp.Cookies()) {
			t.Error("crushFTPHasCookiePair() = false, want true with both cookies")
		}
	})

	t.Run("Only CrushAuth present", func(t *testing.T) {
		header := make(http.Header)
		header.Add("Set-Cookie", (&http.Cookie{Name: "CrushAuth", Value: "abc"}).String())
		resp := &http.Response{StatusCode: 200, Header: header}
		if crushFTPHasCookiePair(resp.Cookies()) {
			t.Error("crushFTPHasCookiePair() = true, want false with only CrushAuth")
		}
	})

	t.Run("Only currentAuth present", func(t *testing.T) {
		header := make(http.Header)
		header.Add("Set-Cookie", (&http.Cookie{Name: "currentAuth", Value: "xyz"}).String())
		resp := &http.Response{StatusCode: 200, Header: header}
		if crushFTPHasCookiePair(resp.Cookies()) {
			t.Error("crushFTPHasCookiePair() = true, want false with only currentAuth")
		}
	})

	t.Run("No cookies", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
		if crushFTPHasCookiePair(resp.Cookies()) {
			t.Error("crushFTPHasCookiePair() = true, want false with no cookies")
		}
	})
}

// ── Active probe response ──────────────────────────────────────────────────────

func TestCrushFTPFingerprinter_ActiveProbeResponse(t *testing.T) {
	fp := &CrushFTPFingerprinter{}

	t.Run("/WebInterface/ (primary probe) sets probe_path", func(t *testing.T) {
		header := make(http.Header)
		header.Set("P3P", `/WebInterface/w3c/p3p.xml`)
		resp := &http.Response{
			StatusCode: 404,
			Header:     header,
			Request:    &http.Request{URL: &url.URL{Path: "/WebInterface/"}},
		}
		result, err := fp.Fingerprint(resp, []byte("<html></html>"))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil")
		}
		if pp, ok := result.Metadata["probe_path"].(string); !ok || pp != "/WebInterface/" {
			t.Errorf("probe_path = %v, want /WebInterface/", result.Metadata["probe_path"])
		}
	})

	t.Run("/WebInterface/login.html also accepted as probe path", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/WebInterface/login.html"}},
		}
		body := `<html><head><title>CrushFTP WebInterface</title></head><body></body></html>`
		result, err := fp.Fingerprint(resp, []byte(body))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil")
		}
		if pp, ok := result.Metadata["probe_path"].(string); !ok || pp != "/WebInterface/login.html" {
			t.Errorf("probe_path = %v, want /WebInterface/login.html", result.Metadata["probe_path"])
		}
	})

	t.Run("nil Request does not panic", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    nil,
		}
		body := `<html><head><title>CrushFTP WebInterface</title></head><body></body></html>`
		result, err := fp.Fingerprint(resp, []byte(body))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil")
		}
		if _, ok := result.Metadata["probe_path"]; ok {
			t.Errorf("probe_path should be absent when Request is nil, got %v", result.Metadata["probe_path"])
		}
	})
}

// ── TestExtractCrushFTPVersion ─────────────────────────────────────────────────

func TestExtractCrushFTPVersion(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantVersion string
	}{
		{
			name:        "Meta generator tag provides version",
			body:        `<meta name="generator" content="CrushFTP 10.7.0">`,
			wantVersion: "10.7.0",
		},
		{
			name:        "Meta generator with single quotes",
			body:        `<meta name='generator' content='CrushFTP 11.2.0'>`,
			wantVersion: "11.2.0",
		},
		{
			name:        "No version in body",
			body:        "<html><head><title>CrushFTP WebInterface</title></head></html>",
			wantVersion: "",
		},
		{
			name:        "Fixed server header string has no version",
			body:        "<html></html>",
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCrushFTPVersion([]byte(tt.body))
			if got != tt.wantVersion {
				t.Errorf("extractCrushFTPVersion() = %q, want %q", got, tt.wantVersion)
			}
		})
	}
}

// ── TestBuildCrushFTPCPE ───────────────────────────────────────────────────────

func TestBuildCrushFTPCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{name: "Version 10.7.0", version: "10.7.0", want: "cpe:2.3:a:crushftp:crushftp:10.7.0:*:*:*:*:*:*:*"},
		{name: "Version 11.2.0", version: "11.2.0", want: "cpe:2.3:a:crushftp:crushftp:11.2.0:*:*:*:*:*:*:*"},
		{name: "Empty version uses wildcard", version: "", want: "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildCrushFTPCPE(tt.version); got != tt.want {
				t.Errorf("buildCrushFTPCPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

// ── Integration test ──────────────────────────────────────────────────────────

func TestCrushFTPFingerprinter_Integration(t *testing.T) {
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &CrushFTPFingerprinter{}
	Register(fp)

	// Server header is fixed string with no version; version comes from meta generator.
	header := make(http.Header)
	header.Set("Server", "CrushFTP HTTP Server")
	resp := &http.Response{StatusCode: 200, Header: header}
	body := []byte(`<html><head><title>CrushFTP WebInterface</title>
<meta name="generator" content="CrushFTP 10.7.0">
</head><body></body></html>`)

	results := RunFingerprinters(resp, body)

	found := false
	for _, result := range results {
		if result.Technology == "crushftp" {
			found = true
			if result.Version != "10.7.0" {
				t.Errorf("Version = %q, want 10.7.0", result.Version)
			}
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			} else if result.CPEs[0] != "cpe:2.3:a:crushftp:crushftp:10.7.0:*:*:*:*:*:*:*" {
				t.Errorf("CPE = %q, want canonical CPE", result.CPEs[0])
			}
			if v, ok := result.Metadata["vendor"].(string); !ok || v != "CrushFTP" {
				t.Errorf("Metadata[vendor] = %v, want CrushFTP", result.Metadata["vendor"])
			}
		}
	}
	if !found {
		t.Error("CrushFTPFingerprinter not found in RunFingerprinters results")
	}
}

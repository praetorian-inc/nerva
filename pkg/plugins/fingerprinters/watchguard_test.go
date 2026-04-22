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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/url"
	"testing"
)

// Compile-time interface assertion: WatchGuardFingerprinter must implement
// ActiveHTTPFingerprinter (Name, Match, Fingerprint, ProbeEndpoint).
var _ ActiveHTTPFingerprinter = &WatchGuardFingerprinter{}

// TestWatchGuardFingerprinter_ActiveInterface is the runtime companion.
// The compile-time var above is the actual guard; this test documents intent.
func TestWatchGuardFingerprinter_ActiveInterface(t *testing.T) {
	var _ ActiveHTTPFingerprinter = &WatchGuardFingerprinter{}
}

func TestWatchGuardFingerprinter_Name(t *testing.T) {
	f := &WatchGuardFingerprinter{}
	if got := f.Name(); got != "watchguard-firebox" {
		t.Errorf("Name() = %q, want %q", got, "watchguard-firebox")
	}
}

func TestWatchGuardFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &WatchGuardFingerprinter{}
	if got := f.ProbeEndpoint(); got != "/auth/login.html" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/auth/login.html")
	}
}

// makeWatchGuardCert builds a minimal *x509.Certificate suitable for testing
// isWatchGuardCert without a real TLS handshake.
func makeWatchGuardCert(t *testing.T, issuerCN, subjectO, subjectOU string) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		Issuer:  pkix.Name{CommonName: issuerCN},
		Subject: pkix.Name{Organization: []string{subjectO}, OrganizationalUnit: []string{subjectOU}},
	}
}

// makeTLSResp wraps a certificate in a minimal *http.Response with TLS state.
func makeTLSResp(cert *x509.Certificate) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		},
	}
}

func TestWatchGuardFingerprinter_Match(t *testing.T) {
	f := &WatchGuardFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		tlsCert    *x509.Certificate
		want       bool
	}{
		{
			name:       "matches on wg_portald_session_id cookie",
			statusCode: 200,
			headers: http.Header{
				"Set-Cookie":   []string{"wg_portald_session_id=abc123; Path=/; HttpOnly"},
				"Content-Type": []string{"text/html"},
			},
			want: true,
		},
		{
			name:       "matches on Server: Fireware header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Fireware"},
			},
			want: true,
		},
		{
			name:       "matches on Server: Fireware XTM (legacy 11.x)",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Fireware XTM"},
			},
			want: true,
		},
		{
			name:       "matches on TLS cert with Fireware web CA issuer",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			tlsCert:    makeWatchGuardCert(t, "Fireware web CA", "", ""),
			want:       true,
		},
		{
			name:       "matches text/html content type for body analysis",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html; charset=UTF-8"}},
			want:       true,
		},
		{
			name:       "rejects 5xx responses",
			statusCode: 500,
			headers: http.Header{
				"Set-Cookie": []string{"wg_portald_session_id=abc"},
			},
			want: false,
		},
		{
			name:       "rejects 1xx responses",
			statusCode: 100,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			want:       false,
		},
		{
			name:       "rejects non-html without WG header or cookie",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"application/json"}},
			want:       false,
		},
		{
			name:       "generic Server header does not match alone",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"nginx"}},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     tt.headers,
			}
			if tt.tlsCert != nil {
				resp.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{tt.tlsCert},
				}
			}
			if got := f.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWatchGuardFingerprinter_TLSCertHelper(t *testing.T) {
	tests := []struct {
		name    string
		resp    *http.Response
		want    bool
	}{
		{
			name: "nil resp returns false",
			resp: nil,
			want: false,
		},
		{
			name:    "nil TLS returns false",
			resp:    &http.Response{StatusCode: 200, Header: http.Header{}},
			want:    false,
		},
		{
			name: "empty PeerCertificates returns false",
			resp: &http.Response{
				StatusCode: 200,
				Header:     http.Header{},
				TLS:        &tls.ConnectionState{PeerCertificates: []*x509.Certificate{}},
			},
			want: false,
		},
		{
			name: "nil leaf certificate returns false",
			resp: &http.Response{
				StatusCode: 200,
				Header:     http.Header{},
				TLS:        &tls.ConnectionState{PeerCertificates: []*x509.Certificate{nil}},
			},
			want: false,
		},
		{
			name: "matching issuer CN (exact case) returns true",
			resp: makeTLSResp(makeWatchGuardCert(t, "Fireware web CA", "", "")),
			want: true,
		},
		{
			name: "matching issuer CN (uppercase) returns true",
			resp: makeTLSResp(makeWatchGuardCert(t, "FIREWARE WEB CA", "", "")),
			want: true,
		},
		{
			name: "matching Subject Organization returns true",
			resp: makeTLSResp(makeWatchGuardCert(t, "Some Public CA", "WatchGuard Technologies", "")),
			want: true,
		},
		{
			name: "matching Subject OU returns true",
			resp: makeTLSResp(makeWatchGuardCert(t, "Some CA", "", "Fireware")),
			want: true,
		},
		{
			name: "non-matching cert returns false",
			resp: makeTLSResp(makeWatchGuardCert(t, "Let's Encrypt Authority X3", "Generic Corp", "IT Dept")),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isWatchGuardCert(tt.resp); got != tt.want {
				t.Errorf("isWatchGuardCert() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractFirewareVersion(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "HTML comment: Fireware v12.5.9",
			body: `<!-- Fireware v12.5.9 -->`,
			want: "12.5.9",
		},
		{
			name: "HTML comment: Fireware v12.5 (two-component)",
			body: `<!-- Fireware v12.5 -->`,
			want: "12.5",
		},
		{
			name: "HTML comment: case-insensitive",
			body: `<!-- FIREWARE V2025.1.4 -->`,
			want: "2025.1.4",
		},
		{
			name: "asset query string ?v=12.5.9",
			body: `<script src="/auth/js/auth.js?v=12.5.9"></script>`,
			want: "12.5.9",
		},
		{
			name: "asset query string ?ver=12.5",
			body: `<link href="/auth/css/style.css?ver=12.5">`,
			want: "12.5",
		},
		{
			name: "HTML comment preferred over asset query",
			body: `<!-- Fireware v12.5.9 --><script src="/js/app.js?v=11.0"></script>`,
			want: "12.5.9",
		},
		{
			name: "no version found",
			body: `<html><head><title>WatchGuard Access Portal</title></head><body></body></html>`,
			want: "",
		},
		{
			name: "injection attempt via HTML comment (4-component rejected)",
			body: `<!-- Fireware v12.5.9.0 -->`,
			want: "",
		},
		{
			name: "injection attempt with colon in comment (pattern does not match, returns empty)",
			// The HTML comment pattern requires \s*--> after the version capture.
			// "12.5.9:injected" does not satisfy \s*--> so the entire comment
			// pattern fails to match. Returns "" (no fallback asset pattern either).
			body: `<!-- Fireware v12.5.9:injected -->`,
			want: "",
		},
		{
			name: "oversized version string rejected by length cap H3 (17 chars, would match regex)",
			// "12345.67890123456" is 17 chars (> 16). The regex ^\d+\.\d+$ would
			// accept it but the length cap fires first.
			body: "<!-- Fireware v12345.67890123456 -->",
			want: "",
		},
		{
			name: "version string exactly 16 chars is accepted if valid (boundary check)",
			// "1234567.890123456" is 17 chars — exceeds cap.
			// "12345.6789012345" is 16 chars — exactly at cap, accepted if valid regex.
			// Valid 2-component: "12345.6789012345" = 16 chars; regex ^\d+\.\d+(?:\.\d+)?$ matches.
			body: "<!-- Fireware v12345.6789012345 -->",
			want: "12345.6789012345",
		},
		{
			name: "non-numeric version rejected",
			body: `<!-- Fireware v12.5.abc -->`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractFirewareVersion([]byte(tt.body)); got != tt.want {
				t.Errorf("extractFirewareVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildFirewareCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "",
			want:    "cpe:2.3:o:watchguard:fireware:*:*:*:*:*:*:*:*",
		},
		{
			version: "12.5.9",
			want:    "cpe:2.3:o:watchguard:fireware:12.5.9:*:*:*:*:*:*:*",
		},
		{
			version: "2025.1.4",
			want:    "cpe:2.3:o:watchguard:fireware:2025.1.4:*:*:*:*:*:*:*",
		},
		// Regression: product slug must be "fireware" not "fireware_os".
		{
			version: "12.5",
			want:    "cpe:2.3:o:watchguard:fireware:12.5:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := buildFirewareCPE(tt.version); got != tt.want {
				t.Errorf("buildFirewareCPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestWatchGuardFingerprinter_Fingerprint(t *testing.T) {
	f := &WatchGuardFingerprinter{}

	tests := []struct {
		name                string
		statusCode          int
		headers             http.Header
		body                string
		tlsCert             *x509.Certificate
		requestURL          string
		wantResult          bool
		wantTech            string
		wantVersion         string
		wantCPE             string
		wantComponent       string
		wantManagementIface bool
		wantVPNEnabled      bool
	}{
		// ── Tier-1 alone ──────────────────────────────────────────────────────────
		{
			name:       "tier1: wg_portald_session_id cookie alone",
			statusCode: 200,
			headers: http.Header{
				"Set-Cookie":   []string{"wg_portald_session_id=abc123; Path=/; HttpOnly"},
				"Content-Type": []string{"text/html"},
			},
			body:           `<html><body>Generic page</body></html>`,
			wantResult:     true,
			wantTech:       "watchguard-firebox",
			wantComponent:  "Access Portal",
			wantVPNEnabled: true,
		},
		{
			name:       "tier1: title WatchGuard Access Portal",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><head><title>WatchGuard Access Portal</title></head>
<body><p>Login page</p></body></html>`,
			wantResult:     true,
			wantTech:       "watchguard-firebox",
			wantComponent:  "Access Portal",
			wantVPNEnabled: true,
		},
		{
			name:       "tier1: title Fireware XTM User Authentication",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><head><title>Fireware XTM User Authentication</title></head>
<body></body></html>`,
			wantResult:     true,
			wantTech:       "watchguard-firebox",
			wantComponent:  "Authentication Portal",
			wantVPNEnabled: true,
		},
		{
			name:       "tier1: title Fireware Web UI",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><head><title>Fireware Web UI</title></head>
<body></body></html>`,
			wantResult:          true,
			wantTech:            "watchguard-firebox",
			wantComponent:       "Fireware Web UI",
			wantManagementIface: true, // Fireware Web UI → always admin
			wantVPNEnabled:      false,
		},
		{
			name:       "tier1: TLS cert with Fireware web CA issuer",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body>No branding here</body></html>`,
			tlsCert:    makeWatchGuardCert(t, "Fireware web CA", "", ""),
			wantResult:     true,
			wantTech:       "watchguard-firebox",
			wantVPNEnabled: true, // defaults to Access Portal fallback
		},
		// ── Tier-2: ≥2 with ≥1 strong ────────────────────────────────────────────
		{
			name:       "tier2: firebox keyword + form action (2 signals, 1 strong)",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><body>
<p>Firebox management</p>
<form action="/auth/login">Login</form>
</body></html>`,
			wantResult:     true,
			wantTech:       "watchguard-firebox",
			wantComponent:  "Access Portal",
			wantVPNEnabled: true,
		},
		{
			name:       "tier2: watchguard technologies + wg-logo (2 signals, 1 strong)",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><body>
<p>Powered by WatchGuard Technologies</p>
<img class="wg-logo" src="/logo.png">
</body></html>`,
			wantResult:     true,
			wantTech:       "watchguard-firebox",
			wantComponent:  "Access Portal",
			wantVPNEnabled: true,
		},
		{
			name:       "tier2: watchguard technologies + Firebox-DB (2 signals, 1 strong)",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><body>
<p>WatchGuard Technologies</p>
<select><option value="Firebox-DB">Firebox-DB</option></select>
</body></html>`,
			wantResult:     true,
			wantTech:       "watchguard-firebox",
			wantVPNEnabled: true, // defaults to Access Portal fallback
		},
		{
			name:       "tier2: wgLogo.gif + Firebox-DB (2 strong signals)",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><body>
<img src="/images/wgLogo.gif">
<option value="Firebox-DB">Firebox Database</option>
</body></html>`,
			wantResult:     true,
			wantTech:       "watchguard-firebox",
			wantVPNEnabled: true, // defaults to Access Portal fallback
		},
		// ── Tier-2 rejection: only weak signals ───────────────────────────────────
		{
			name:       "tier2 reject: firebox + watchguard technologies only (no strong signal)",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><body>
<p>Firebox and WatchGuard Technologies</p>
</body></html>`,
			wantResult: false, // H2: two weak signals only is NOT sufficient
		},
		{
			name:       "tier2 reject: only 1 Tier-2 signal total",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><form action="/auth/login">Login</form></body></html>`,
			wantResult: false, // Only 1 signal (form action) — need ≥2
		},
		// ── Dimension exclusion ───────────────────────────────────────────────────
		{
			name:       "dimension hard reject: title contains Dimension",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><head><title>WatchGuard Dimension</title></head>
<body>
<p>Firebox</p>
<p>WatchGuard Technologies</p>
<img src="wgLogo.gif">
<form action="/auth/login">login</form>
</body></html>`,
			wantResult: false,
		},
		{
			name:       "dimension hard reject even with Tier-1 cookie signal",
			statusCode: 200,
			headers: http.Header{
				"Set-Cookie":   []string{"wg_portald_session_id=abc; Path=/"},
				"Content-Type": []string{"text/html"},
			},
			body: `<html><head><title>WatchGuard Dimension</title></head>
<body></body></html>`,
			wantResult: false,
		},
		// ── 5xx rejection ─────────────────────────────────────────────────────────
		{
			name:       "5xx response rejected",
			statusCode: 503,
			headers: http.Header{
				"Set-Cookie": []string{"wg_portald_session_id=abc"},
			},
			body:       `<html><body>Service Unavailable</body></html>`,
			wantResult: false,
		},
		// ── Version extraction ────────────────────────────────────────────────────
		{
			name:       "version extracted from HTML comment",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><!-- Fireware v12.5.9 -->
<head><title>WatchGuard Access Portal</title></head>
<body></body></html>`,
			wantResult:     true,
			wantVersion:    "12.5.9",
			wantCPE:        "cpe:2.3:o:watchguard:fireware:12.5.9:*:*:*:*:*:*:*",
			wantVPNEnabled: true,
		},
		{
			name:       "version extracted from asset query string",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><head><title>WatchGuard Access Portal</title></head>
<body><script src="/auth/js/auth.js?v=12.5"></script></body></html>`,
			wantResult:     true,
			wantVersion:    "12.5",
			wantVPNEnabled: true,
		},
		{
			name:       "missing version returns empty (wildcard CPE)",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><head><title>WatchGuard Access Portal</title></head>
<body></body></html>`,
			wantResult:     true,
			wantVersion:    "",
			wantCPE:        "cpe:2.3:o:watchguard:fireware:*:*:*:*:*:*:*:*",
			wantVPNEnabled: true,
		},
		// ── management_interface detection ────────────────────────────────────────
		{
			name:       "management_interface: Fireware Web UI title → true",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><head><title>Fireware Web UI</title></head>
<body></body></html>`,
			wantResult:          true,
			wantManagementIface: true,
			wantVPNEnabled:      false,
		},
		{
			name:       "management_interface: port 8080 → true",
			statusCode: 200,
			headers: http.Header{
				"Set-Cookie":   []string{"wg_portald_session_id=abc"},
				"Content-Type": []string{"text/html"},
			},
			body:                `<html><body>Login</body></html>`,
			requestURL:          "https://10.0.0.1:8080/auth/login.html",
			wantResult:          true,
			wantManagementIface: true,
			wantVPNEnabled:      true, // component is Access Portal fallback
		},
		{
			name:       "management_interface: port 4117 → true",
			statusCode: 200,
			headers: http.Header{
				"Set-Cookie":   []string{"wg_portald_session_id=abc"},
				"Content-Type": []string{"text/html"},
			},
			body:                `<html><body>Login</body></html>`,
			requestURL:          "https://10.0.0.1:4117/auth/login.html",
			wantResult:          true,
			wantManagementIface: true,
			wantVPNEnabled:      true, // component is Access Portal fallback
		},
		{
			name:       "management_interface: port 443 → false",
			statusCode: 200,
			headers: http.Header{
				"Set-Cookie":   []string{"wg_portald_session_id=abc"},
				"Content-Type": []string{"text/html"},
			},
			body:                `<html><body>Login</body></html>`,
			requestURL:          "https://10.0.0.1:443/auth/login.html",
			wantResult:          true,
			wantManagementIface: false,
			wantVPNEnabled:      true, // component is Access Portal fallback
		},
		// ── vpn_enabled detection ─────────────────────────────────────────────────
		{
			name:       "vpn_enabled: Access Portal component → true",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><head><title>WatchGuard Access Portal</title></head>
<body></body></html>`,
			wantResult:     true,
			wantVPNEnabled: true,
		},
		{
			name:       "vpn_enabled: Authentication Portal component → true",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><head><title>Fireware XTM User Authentication</title></head>
<body></body></html>`,
			wantResult:     true,
			wantVPNEnabled: true,
		},
		{
			name:       "vpn_enabled: Fireware Web UI component → false (management_interface → true)",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><head><title>Fireware Web UI</title></head>
<body></body></html>`,
			wantResult:          true,
			wantVPNEnabled:      false,
			wantManagementIface: true, // Fireware Web UI is always a management surface
		},
		// ── AuthPoint-style exclusion (cloud WG, no markers) ─────────────────────
		{
			name:       "authpoint-style cloud page: no WG markers → nil",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body: `<html><head><title>Auth Portal</title></head>
<body><p>Login with your SSO credentials</p></body></html>`,
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     tt.headers,
			}
			if tt.tlsCert != nil {
				resp.TLS = &tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{tt.tlsCert},
				}
			}
			if tt.requestURL != "" {
				u, err := url.Parse(tt.requestURL)
				if err != nil {
					t.Fatalf("invalid requestURL %q: %v", tt.requestURL, err)
				}
				resp.Request = &http.Request{URL: u}
			}

			result, err := f.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}

			if tt.wantResult && result == nil {
				t.Fatal("Fingerprint() returned nil, expected result")
			}
			if !tt.wantResult && result != nil {
				t.Errorf("Fingerprint() returned result, want nil; Technology=%q", result.Technology)
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
			if tt.wantCPE != "" && (len(result.CPEs) == 0 || result.CPEs[0] != tt.wantCPE) {
				t.Errorf("CPEs[0] = %q, want %q", func() string {
					if len(result.CPEs) > 0 {
						return result.CPEs[0]
					}
					return "(empty)"
				}(), tt.wantCPE)
			}
			if tt.wantComponent != "" {
				if comp, ok := result.Metadata["component"]; !ok || comp != tt.wantComponent {
					t.Errorf("component = %v, want %q", comp, tt.wantComponent)
				}
			}
			if tt.wantResult {
				// Always check management_interface and vpn_enabled are present.
				if _, ok := result.Metadata["management_interface"]; !ok {
					t.Error("management_interface missing from metadata")
				}
				if _, ok := result.Metadata["vpn_enabled"]; !ok {
					t.Error("vpn_enabled missing from metadata")
				}
				mgmt, _ := result.Metadata["management_interface"].(bool)
				if mgmt != tt.wantManagementIface {
					t.Errorf("management_interface = %v, want %v", mgmt, tt.wantManagementIface)
				}
				vpn, _ := result.Metadata["vpn_enabled"].(bool)
				if vpn != tt.wantVPNEnabled {
					t.Errorf("vpn_enabled = %v, want %v", vpn, tt.wantVPNEnabled)
				}
			}
		})
	}
}

// TestWatchGuardFingerprinter_ShodanVectors tests detection against real-world
// response patterns representative of WatchGuard Firebox login pages, based on
// Shodan and Censys queries from protocol-research-watchguard.md.
func TestWatchGuardFingerprinter_ShodanVectors(t *testing.T) {
	f := &WatchGuardFingerprinter{}

	tests := []struct {
		name        string
		description string
		statusCode  int
		headers     http.Header
		body        string
		wantTech    string
		wantVersion string
		wantComp    string
	}{
		{
			// Shodan query: http.title:"WatchGuard Access Portal" port:443
			// Most common: Access Portal on HTTPS with wg_portald_session_id cookie.
			name:        "Shodan Vector 1: Access Portal port 443 with wg_portald cookie",
			description: "WatchGuard Firebox Access Portal login page, Fireware 12.x",
			statusCode:  200,
			headers: http.Header{
				"Set-Cookie":                []string{"wg_portald_session_id=RAND123; Path=/; Secure; HttpOnly"},
				"Content-Type":              []string{"text/html; charset=UTF-8"},
				"X-Frame-Options":           []string{"SAMEORIGIN"},
				"Strict-Transport-Security": []string{"max-age=31536000"},
			},
			body: `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WatchGuard Access Portal</title>
<!-- Fireware v12.5.9 -->
<link rel="stylesheet" href="/auth/css/portal.css?v=12.5.9">
</head>
<body>
<img class="wg-logo" src="/auth/images/logo.png" alt="WatchGuard">
<form action="/auth/login">
<input type="text" name="username">
<input type="password" name="password">
<select name="domain"><option value="Firebox-DB">Firebox-DB</option></select>
</form>
</body>
</html>`,
			wantTech:    "watchguard-firebox",
			wantVersion: "12.5.9",
			wantComp:    "Access Portal",
		},
		{
			// Shodan query: http.title:"Fireware Web UI" port:8080
			// Admin surface: Fireware Web UI on management port 8080.
			name:        "Shodan Vector 2: Fireware Web UI port 8080 with title",
			description: "WatchGuard Firebox Fireware Web UI admin interface, port 8080",
			statusCode:  200,
			headers: http.Header{
				"Server":       []string{"Fireware"},
				"Content-Type": []string{"text/html; charset=UTF-8"},
			},
			body: `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Fireware Web UI</title>
</head>
<body>
<div id="header">
<img src="/images/wgLogo.gif" alt="WatchGuard Logo">
<p>WatchGuard Technologies Fireware Web UI</p>
</div>
<form action="/auth/login">
<select><option value="Firebox-DB">Firebox Database</option></select>
</form>
</body>
</html>`,
			wantTech: "watchguard-firebox",
			wantComp: "Fireware Web UI",
		},
		{
			// Shodan query: http.title:"Fireware XTM User Authentication"
			// Legacy appliances running Fireware XTM 11.x, older logo + title.
			name:        "Shodan Vector 3: Legacy Fireware XTM 11.x with legacy logo and title",
			description: "Legacy WatchGuard Firebox XTM 11.x authentication portal",
			statusCode:  200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: `<!DOCTYPE html>
<html>
<head>
<title>Fireware XTM User Authentication</title>
</head>
<body>
<img src="/images/wgLogo.gif" alt="WatchGuard">
<p>WatchGuard Technologies<br>Firebox XTM</p>
<form action="/auth/login" method="post">
<input name="user" type="text">
<select name="domain">
<option value="Firebox-DB">Firebox-DB</option>
</select>
</form>
</body>
</html>`,
			wantTech: "watchguard-firebox",
			wantComp: "Authentication Portal",
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
				t.Fatalf("Fingerprint() error = %v: %s", err, tt.description)
			}
			if result == nil {
				t.Fatalf("Fingerprint() returned nil for Shodan vector: %s", tt.description)
			}
			if result.Technology != tt.wantTech {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
			}
			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if tt.wantComp != "" {
				comp, _ := result.Metadata["component"].(string)
				if comp != tt.wantComp {
					t.Errorf("component = %q, want %q", comp, tt.wantComp)
				}
			}
			if len(result.CPEs) == 0 {
				t.Error("CPEs is empty, expected at least one CPE string")
			}
		})
	}
}

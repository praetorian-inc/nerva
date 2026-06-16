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

func TestPanosMgmtFingerprinter_Name(t *testing.T) {
	f := &PanosMgmtFingerprinter{}
	if got := f.Name(); got != "panos-mgmt" {
		t.Errorf("Name() = %q, want %q", got, "panos-mgmt")
	}
}

func TestPanosMgmtFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &PanosMgmtFingerprinter{}
	if got := f.ProbeEndpoint(); got != "/php/login.php" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/php/login.php")
	}
}

func TestPanosMgmtFingerprinter_Match(t *testing.T) {
	f := &PanosMgmtFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "matches PanWeb Server header",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"PanWeb Server"}},
			want:       true,
		},
		{
			name:       "matches PanWeb Server header case-insensitive",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"PANWEB SERVER/1.0"}},
			want:       true,
		},
		{
			name:       "matches pan-os in Server header",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"PAN-OS 10.2.3"}},
			want:       true,
		},
		{
			name:       "matches Location header containing /php/login.php",
			statusCode: 302,
			headers:    http.Header{"Location": []string{"/php/login.php"}},
			want:       true,
		},
		{
			name:       "does not match plain server with no indicators",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"Apache/2.4"}},
			want:       false,
		},
		{
			name:       "does not match 5xx response",
			statusCode: 500,
			headers:    http.Header{"Server": []string{"PanWeb Server"}},
			want:       false,
		},
		{
			name:       "does not match empty headers",
			statusCode: 200,
			headers:    http.Header{},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: tt.statusCode, Header: tt.headers}
			if got := f.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPanosMgmtFingerprinter_Fingerprint(t *testing.T) {
	f := &PanosMgmtFingerprinter{}

	// Standard PAN-OS management login page HTML used across multiple tests.
	mgmtLoginHTML := `<!DOCTYPE html>
<html>
<head><title>Palo Alto Networks - Login</title></head>
<body>
<form name="login_form" method="post" action="/php/login.php">
<input type="text" name="user"/>
<input type="password" name="passwd"/>
<input type="submit" value="Login"/>
</form>
<script src="/php/utils/combined.js?v=10.2.3"></script>
</body>
</html>`

	tests := []struct {
		name        string
		statusCode  int
		headers     http.Header
		body        string
		wantNil     bool
		wantTech    string
		wantVersion string
		wantCPE     string
	}{
		// --- Positive cases ---
		{
			name:       "detects management login page: login_form + Palo Alto title",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"PanWeb Server"}},
			body: `<html>
<head><title>Palo Alto Networks Login</title></head>
<body><form name="login_form" method="post"></form></body>
</html>`,
			wantNil:  false,
			wantTech: "palo-alto-panos-management",
		},
		{
			name:       "detects management page: PanWeb Server header + login form",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"PanWeb Server"}},
			body:       mgmtLoginHTML,
			wantNil:    false,
			wantTech:   "palo-alto-panos-management",
			wantVersion: "10.2.3",
			wantCPE:    "cpe:2.3:o:paloaltonetworks:pan-os:10.2.3:*:*:*:*:*:*:*",
		},
		{
			name:       "detects management page: PAN-OS Server header with version",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"PAN-OS 10.2.3"}},
			body: `<html>
<head><title>Palo Alto Networks</title></head>
<body><form name="login_form"></form></body>
</html>`,
			wantNil:     false,
			wantTech:    "palo-alto-panos-management",
			wantVersion: "10.2.3",
			wantCPE:     "cpe:2.3:o:paloaltonetworks:pan-os:10.2.3:*:*:*:*:*:*:*",
		},
		{
			name:       "detects management page: Location header /php/login.php redirect",
			statusCode: 302,
			headers:    http.Header{"Location": []string{"/php/login.php"}},
			body: `<html>
<body><form name="login_form"></form>
<link rel="stylesheet" href="/login/css/main.css"/>
</body>
</html>`,
			wantNil:  false,
			wantTech: "palo-alto-panos-management",
		},
		{
			name:       "detects management page: combined.js asset path without login_form",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"PanWeb Server"}},
			body: `<html>
<head><title>Palo Alto Networks</title></head>
<body>
<script src="/php/utils/combined.js?v=11.1.0"></script>
</body>
</html>`,
			wantNil:     false,
			wantTech:    "palo-alto-panos-management",
			wantVersion: "11.1.0",
		},
		{
			name:       "detects management page: /login/css/ asset path",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"PanWeb Server"}},
			body: `<html>
<head><title>Palo Alto Networks</title></head>
<body>
<link href="/login/css/style.css"/>
</body>
</html>`,
			wantNil:  false,
			wantTech: "palo-alto-panos-management",
		},
		// --- Negative cases ---
		{
			name:       "rejects GlobalProtect XML at /php/login.php",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"PanWeb Server"}},
			body: `<?xml version="1.0" encoding="UTF-8"?>
<prelogin-response>
<status>Success</status>
<sw-version>10.2.3</sw-version>
</prelogin-response>`,
			wantNil: true,
		},
		{
			name:       "rejects body with global-protect marker",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"PanWeb Server"}},
			body: `<html>
<body>
<form name="login_form"></form>
<a href="/global-protect/login.esp">VPN Access</a>
</body>
</html>`,
			wantNil: true,
		},
		{
			name:       "rejects body with PAN_FORM marker even with management signals",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"PanWeb Server"}},
			body: `<html>
<body>
<form name="login_form"></form>
<form name="PAN_FORM"></form>
</body>
</html>`,
			wantNil: true,
		},
		{
			name:       "rejects body with portal-prelogin marker",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"PanWeb Server"}},
			body: `<html>
<body>
<form name="login_form"></form>
<div id="portal-prelogin"></div>
</body>
</html>`,
			wantNil: true,
		},
		{
			name:       "rejects generic PHP login page without PAN-OS markers",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"Apache/2.4"}},
			body: `<html>
<body>
<form name="login_form" method="post">
<input type="text" name="user"/>
</form>
</body>
</html>`,
			wantNil: true,
		},
		{
			name:       "rejects when body has Palo Alto title but no form or asset corroboration",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"PanWeb Server"}},
			body:       `<html><body>Palo Alto Networks documentation</body></html>`,
			wantNil:    true,
		},
		{
			name:       "rejects 5xx response",
			statusCode: 503,
			headers:    http.Header{"Server": []string{"PanWeb Server"}},
			body:       mgmtLoginHTML,
			wantNil:    true,
		},
		{
			name:       "rejects when header signal absent",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"nginx/1.18"}},
			body:       mgmtLoginHTML,
			wantNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: tt.statusCode, Header: tt.headers}
			result, err := f.Fingerprint(resp, []byte(tt.body))

			if err != nil {
				t.Fatalf("Fingerprint() unexpected error: %v", err)
			}

			if tt.wantNil && result != nil {
				t.Errorf("Fingerprint() = %+v, want nil", result)
				return
			}
			if !tt.wantNil && result == nil {
				t.Error("Fingerprint() = nil, want non-nil result")
				return
			}

			if result == nil {
				return
			}

			if result.Technology != tt.wantTech {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
			}
			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if tt.wantCPE != "" {
				if len(result.CPEs) == 0 {
					t.Error("CPEs is empty, expected at least one entry")
				} else if result.CPEs[0] != tt.wantCPE {
					t.Errorf("CPE[0] = %q, want %q", result.CPEs[0], tt.wantCPE)
				}
			}

			// Severity must never be set on management interface fingerprinter.
			if result.Severity != "" {
				t.Errorf("Severity = %q, want empty string (zero value)", result.Severity)
			}

			// Metadata must contain required fields.
			if result.Metadata["vendor"] != "Palo Alto Networks" {
				t.Errorf("Metadata[vendor] = %q, want %q", result.Metadata["vendor"], "Palo Alto Networks")
			}
			if result.Metadata["product"] != "PAN-OS Management Interface" {
				t.Errorf("Metadata[product] = %q, want %q", result.Metadata["product"], "PAN-OS Management Interface")
			}
			if result.Metadata["interface_type"] != "management" {
				t.Errorf("Metadata[interface_type] = %q, want %q", result.Metadata["interface_type"], "management")
			}
		})
	}
}

// TestPanosMgmtFingerprinter_VersionExtraction validates version parsing paths.
func TestPanosMgmtFingerprinter_VersionExtraction(t *testing.T) {
	f := &PanosMgmtFingerprinter{}

	tests := []struct {
		name        string
		headers     http.Header
		body        string
		wantVersion string
	}{
		{
			name:        "extracts version from Server header PAN-OS 10.2.3",
			headers:     http.Header{"Server": []string{"PAN-OS 10.2.3"}},
			body:        `<form name="login_form"></form>`,
			wantVersion: "10.2.3",
		},
		{
			name:        "extracts version from combined.js asset query param",
			headers:     http.Header{"Server": []string{"PanWeb Server"}},
			body:        `<form name="login_form"></form><script src="/php/utils/combined.js?v=10.2.4"></script>`,
			wantVersion: "10.2.4",
		},
		{
			name:        "Server header version takes precedence over asset param",
			headers:     http.Header{"Server": []string{"PAN-OS 11.0.1"}},
			body:        `<form name="login_form"></form><script src="/php/utils/combined.js?v=10.2.4"></script>`,
			wantVersion: "11.0.1",
		},
		{
			name:        "returns empty version when no version signals present",
			headers:     http.Header{"Server": []string{"PanWeb Server"}},
			body:        `<form name="login_form"></form>`,
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 200,
				Header:     tt.headers,
			}
			result, err := f.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error: %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() = nil, want non-nil result")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
		})
	}
}

// TestBuildPanOSMgmtCPE validates CPE output format.
func TestBuildPanOSMgmtCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "10.2.3",
			want:    "cpe:2.3:o:paloaltonetworks:pan-os:10.2.3:*:*:*:*:*:*:*",
		},
		{
			version: "10.1.9-h1",
			want:    "cpe:2.3:o:paloaltonetworks:pan-os:10.1.9-h1:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := buildPanOSMgmtCPE(tt.version); got != tt.want {
				t.Errorf("buildPanOSMgmtCPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

// TestPanosMgmtFingerprinter_NoOverlapWithGlobalProtect verifies that responses
// containing GlobalProtect markers never produce a management interface result,
// even when management signals are also present.
func TestPanosMgmtFingerprinter_NoOverlapWithGlobalProtect(t *testing.T) {
	f := &PanosMgmtFingerprinter{}

	gpMarkers := []struct {
		name   string
		marker string
	}{
		{"global-protect marker", "global-protect"},
		{"prelogin-response marker", "prelogin-response"},
		{"PAN_FORM marker", "PAN_FORM"},
		{"portal-prelogin marker", "portal-prelogin"},
	}

	for _, m := range gpMarkers {
		t.Run(m.name, func(t *testing.T) {
			body := `<form name="login_form"></form>` + m.marker
			resp := &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Server": []string{"PanWeb Server"}},
			}
			result, err := f.Fingerprint(resp, []byte(body))
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error: %v", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil when GlobalProtect marker %q present", result, m.marker)
			}
		})
	}
}

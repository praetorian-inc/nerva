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

// -- Name --

func TestKenticoFingerprinter_Name(t *testing.T) {
	fp := &KenticoFingerprinter{}
	if got := fp.Name(); got != "kentico" {
		t.Errorf("Name() = %q, want %q", got, "kentico")
	}
}

// -- Match --

func TestKenticoFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{name: "200 OK passes", statusCode: 200, want: true},
		{name: "302 redirect passes", statusCode: 302, want: true},
		{name: "404 passes", statusCode: 404, want: true},
		{name: "499 passes", statusCode: 499, want: true},
		{name: "100 rejected", statusCode: 100, want: false},
		{name: "500 rejected", statusCode: 500, want: false},
		{name: "503 rejected", statusCode: 503, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &KenticoFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// -- Fingerprint: positive --

func TestKenticoFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		cookies       [][2]string
		body          string
		wantVersion   string
		wantCPE       string
		wantDetection string
	}{
		{
			name:          "Meta generator with build number",
			statusCode:    200,
			body:          `<html><head><meta name="generator" content="Kentico CMS 7.0 (build 7.0.5000)" /></head></html>`,
			wantVersion:   "7.0.5000",
			wantCPE:       "cpe:2.3:a:kentico:kentico_cms:7.0.5000:*:*:*:*:*:*:*",
			wantDetection: "generator",
		},
		{
			name:          "Meta generator with build and FREE LICENSE suffix",
			statusCode:    200,
			body:          `<html><head><meta name="generator" content="Kentico CMS 3.1a (build 3.1.3142) FREE LICENSE" /></head></html>`,
			wantVersion:   "3.1.3142",
			wantCPE:       "cpe:2.3:a:kentico:kentico_cms:3.1.3142:*:*:*:*:*:*:*",
			wantDetection: "generator",
		},
		{
			name:          "Meta generator version without build number",
			statusCode:    200,
			body:          `<html><head><meta name="generator" content="Kentico CMS 13.0" /></head></html>`,
			wantVersion:   "13.0",
			wantCPE:       "cpe:2.3:a:kentico:kentico_cms:13.0:*:*:*:*:*:*:*",
			wantDetection: "generator",
		},
		{
			name:          "Meta generator Kentico Xperience",
			statusCode:    200,
			body:          `<html><head><meta name="generator" content="Kentico Xperience 13.0 (build 13.0.178)" /></head></html>`,
			wantVersion:   "13.0.178",
			wantCPE:       "cpe:2.3:a:kentico:kentico_cms:13.0.178:*:*:*:*:*:*:*",
			wantDetection: "generator",
		},
		{
			name:          "CMSPreferredCulture cookie",
			statusCode:    200,
			cookies:       [][2]string{{"CMSPreferredCulture", "en-US"}},
			body:          "<html><body>Welcome</body></html>",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:kentico:kentico_cms:*:*:*:*:*:*:*:*",
			wantDetection: "cookies",
		},
		{
			name:          "CMSCookieLevel cookie",
			statusCode:    200,
			cookies:       [][2]string{{"CMSCookieLevel", "200"}},
			body:          "<html><body>Welcome</body></html>",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:kentico:kentico_cms:*:*:*:*:*:*:*:*",
			wantDetection: "cookies",
		},
		{
			name:          "CMSCsrfCookie cookie",
			statusCode:    200,
			cookies:       [][2]string{{"CMSCsrfCookie", "token123"}},
			body:          "<html><body>Welcome</body></html>",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:kentico:kentico_cms:*:*:*:*:*:*:*:*",
			wantDetection: "cookies",
		},
		{
			name:          "CMSCurrentTheme cookie",
			statusCode:    200,
			cookies:       [][2]string{{"CMSCurrentTheme", "Default"}},
			body:          "<html><body>Welcome</body></html>",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:kentico:kentico_cms:*:*:*:*:*:*:*:*",
			wantDetection: "cookies",
		},
		{
			name:          "CMSPages resource path in body",
			statusCode:    200,
			body:          `<html><head><script src="/CMSPages/GetResource.ashx?scriptfile=~/CMSScripts/Custom/script.js"></script></head></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:kentico:kentico_cms:*:*:*:*:*:*:*:*",
			wantDetection: "body_path",
		},
		{
			name:          "Priority: generator beats cookies",
			statusCode:    200,
			cookies:       [][2]string{{"CMSPreferredCulture", "en-US"}},
			body:          `<html><head><meta name="generator" content="Kentico CMS 13.0 (build 13.0.178)" /></head></html>`,
			wantVersion:   "13.0.178",
			wantCPE:       "cpe:2.3:a:kentico:kentico_cms:13.0.178:*:*:*:*:*:*:*",
			wantDetection: "generator",
		},
		{
			name:          "Priority: cookies beat body_path",
			statusCode:    200,
			cookies:       [][2]string{{"CMSCookieLevel", "200"}},
			body:          `<html><head><script src="/CMSPages/GetResource.ashx"></script></head></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:kentico:kentico_cms:*:*:*:*:*:*:*:*",
			wantDetection: "cookies",
		},
		{
			name:          "Meta generator with single quotes",
			statusCode:    200,
			body:          `<html><head><meta name='generator' content='Kentico CMS 8.0 (build 8.0.5112)' /></head></html>`,
			wantVersion:   "8.0.5112",
			wantCPE:       "cpe:2.3:a:kentico:kentico_cms:8.0.5112:*:*:*:*:*:*:*",
			wantDetection: "generator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &KenticoFingerprinter{}
			header := make(http.Header)
			for _, c := range tt.cookies {
				cookie := &http.Cookie{Name: c[0], Value: c[1]}
				header.Add("Set-Cookie", cookie.String())
			}
			resp := &http.Response{StatusCode: tt.statusCode, Header: header}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want non-nil")
			}
			if result.Technology != "kentico-cms" {
				t.Errorf("Technology = %q, want kentico-cms", result.Technology)
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
		})
	}
}

// -- Fingerprint: negative --

func TestKenticoFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		cookies    [][2]string
		body       string
	}{
		{name: "Generic page", statusCode: 200, body: "<html><title>Welcome</title></html>"},
		{name: "WordPress generator", statusCode: 200, body: `<html><head><meta name="generator" content="WordPress 6.5" /></head></html>`},
		{name: "Random CMS cookie (not Kentico)", statusCode: 200, cookies: [][2]string{{"PHPSESSID", "abc123"}}, body: "<html></html>"},
		{name: "CPE-injection attempt", statusCode: 200, body: `<html><head><meta name="generator" content="Kentico CMS 13.0" /></head><body>:*:malicious</body></html>`},
		{name: "Body > 2 MiB rejected", statusCode: 200, body: `<meta name="generator" content="Kentico CMS 13.0">` + string(make([]byte, 2*1024*1024+1))},
		{name: "Status 500 rejected", statusCode: 500, body: `<html><head><meta name="generator" content="Kentico CMS 13.0" /></head></html>`},
		{name: "Status 199 rejected", statusCode: 199, body: `<html><head><meta name="generator" content="Kentico CMS 13.0" /></head></html>`},
		{name: "Empty body", statusCode: 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &KenticoFingerprinter{}
			header := make(http.Header)
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

// -- kenticoHasCMSCookies --

func TestKenticoHasCMSCookies(t *testing.T) {
	tests := []struct {
		name    string
		cookies [][2]string
		want    bool
	}{
		{name: "CMSPreferredCulture present", cookies: [][2]string{{"CMSPreferredCulture", "en-US"}}, want: true},
		{name: "CMSCookieLevel present", cookies: [][2]string{{"CMSCookieLevel", "200"}}, want: true},
		{name: "CMSCsrfCookie present", cookies: [][2]string{{"CMSCsrfCookie", "tok"}}, want: true},
		{name: "CMSCurrentTheme present", cookies: [][2]string{{"CMSCurrentTheme", "Default"}}, want: true},
		{name: "No CMS cookies", cookies: [][2]string{{"PHPSESSID", "abc"}}, want: false},
		{name: "Empty cookies", cookies: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := make(http.Header)
			for _, c := range tt.cookies {
				cookie := &http.Cookie{Name: c[0], Value: c[1]}
				header.Add("Set-Cookie", cookie.String())
			}
			resp := &http.Response{StatusCode: 200, Header: header}
			if got := kenticoHasCMSCookies(resp.Cookies()); got != tt.want {
				t.Errorf("kenticoHasCMSCookies() = %v, want %v", got, tt.want)
			}
		})
	}
}

// -- extractKenticoVersion --

func TestExtractKenticoVersion(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantVersion string
	}{
		{
			name:        "Build number extracted",
			body:        `<meta name="generator" content="Kentico CMS 7.0 (build 7.0.5000)" />`,
			wantVersion: "7.0.5000",
		},
		{
			name:        "Build with FREE LICENSE suffix",
			body:        `<meta name="generator" content="Kentico CMS 3.1a (build 3.1.3142) FREE LICENSE" />`,
			wantVersion: "3.1.3142",
		},
		{
			name:        "Main version fallback (no build)",
			body:        `<meta name="generator" content="Kentico CMS 13.0" />`,
			wantVersion: "13.0",
		},
		{
			name:        "Xperience with build",
			body:        `<meta name="generator" content="Kentico Xperience 13.0 (build 13.0.178)" />`,
			wantVersion: "13.0.178",
		},
		{
			name:        "No generator tag",
			body:        `<html><body>Hello</body></html>`,
			wantVersion: "",
		},
		{
			name:        "WordPress generator ignored",
			body:        `<meta name="generator" content="WordPress 6.5" />`,
			wantVersion: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractKenticoVersion([]byte(tt.body))
			if got != tt.wantVersion {
				t.Errorf("extractKenticoVersion() = %q, want %q", got, tt.wantVersion)
			}
		})
	}
}

// -- buildKenticoCPE --

func TestBuildKenticoCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{name: "Version 7.0.5000", version: "7.0.5000", want: "cpe:2.3:a:kentico:kentico_cms:7.0.5000:*:*:*:*:*:*:*"},
		{name: "Version 13.0.178", version: "13.0.178", want: "cpe:2.3:a:kentico:kentico_cms:13.0.178:*:*:*:*:*:*:*"},
		{name: "Empty version uses wildcard", version: "", want: "cpe:2.3:a:kentico:kentico_cms:*:*:*:*:*:*:*:*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildKenticoCPE(tt.version); got != tt.want {
				t.Errorf("buildKenticoCPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

// -- Integration --

func TestKenticoFingerprinter_Integration(t *testing.T) {
	fp := &KenticoFingerprinter{}

	header := make(http.Header)
	header.Add("Set-Cookie", (&http.Cookie{Name: "CMSPreferredCulture", Value: "en-US"}).String())
	header.Add("Set-Cookie", (&http.Cookie{Name: "CMSCookieLevel", Value: "200"}).String())
	resp := &http.Response{StatusCode: 200, Header: header}
	body := []byte(`<html><head>
<meta name="generator" content="Kentico CMS 13.0 (build 13.0.178)" />
<script src="/CMSPages/GetResource.ashx?scriptfile=~/CMSScripts/Custom/jquery.js"></script>
</head><body></body></html>`)

	if !fp.Match(resp) {
		t.Fatal("Match() returned false, want true")
	}
	result, err := fp.Fingerprint(resp, body)
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}
	if result.Technology != "kentico-cms" {
		t.Errorf("Technology = %q, want kentico-cms", result.Technology)
	}
	if result.Version != "13.0.178" {
		t.Errorf("Version = %q, want 13.0.178", result.Version)
	}
	if len(result.CPEs) == 0 {
		t.Error("Expected at least one CPE")
	} else if result.CPEs[0] != "cpe:2.3:a:kentico:kentico_cms:13.0.178:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %q, want canonical CPE", result.CPEs[0])
	}
	if v, ok := result.Metadata["vendor"].(string); !ok || v != "Kentico" {
		t.Errorf("Metadata[vendor] = %v, want Kentico", result.Metadata["vendor"])
	}
	if dm, ok := result.Metadata["detection_method"].(string); !ok || dm != "generator" {
		t.Errorf("Metadata[detection_method] = %v, want generator", result.Metadata["detection_method"])
	}
}

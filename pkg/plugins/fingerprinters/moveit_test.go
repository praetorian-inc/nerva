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

func TestMOVEitFingerprinter_Name(t *testing.T) {
	fp := &MOVEitFingerprinter{}
	if got := fp.Name(); got != "moveit" {
		t.Errorf("Name() = %q, want %q", got, "moveit")
	}
}

func TestMOVEitFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &MOVEitFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/human.aspx" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/human.aspx")
	}
}

// ── Match ──────────────────────────────────────────────────────────────────────

func TestMOVEitFingerprinter_Match(t *testing.T) {
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
			fp := &MOVEitFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ── Fingerprint: positive (valid) ─────────────────────────────────────────────

func TestMOVEitFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name            string
		statusCode      int
		body            string
		cookies         [][2]string // [name, value] pairs to set as Set-Cookie headers
		probePath       string
		wantVersion     string
		wantCPE         string
		wantDetection   string
		wantProbePath   bool
		wantDocYear     string
		wantDMZCookie   bool
		wantSiLock      bool
	}{
		{
			name:          "stylesheet_MOVEit marker detected",
			statusCode:    200,
			body:          `<link rel="stylesheet" href="/human/stylesheet_MOVEit.css">`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:          "moveit.transfer marker detected",
			statusCode:    200,
			body:          `<script src="/human/moveit.transfer.min.js"></script>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:          "MOVEitPopUp marker detected",
			statusCode:    200,
			body:          `<div id="MOVEitPopUp"></div>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:          "MOVEitDMZ_Form marker detected",
			statusCode:    200,
			body:          `<div id="MOVEitDMZ_Form"><form></form></div>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:          "MOVEit Transfer Sign On title marker detected",
			statusCode:    200,
			body:          `<title>MOVEit Transfer Sign On</title>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:          "Doc year 2023 maps to major version 15",
			statusCode:    200,
			body:          `<div id="MOVEitPopUp"></div><a href="https://docs.ipswitch.com/MOVEit/Transfer2023/Help/Admin/en/">Docs</a>`,
			wantVersion:   "15",
			wantCPE:       "cpe:2.3:a:progress:moveit_transfer:15:*:*:*:*:*:*:*",
			wantDetection: "body",
			wantDocYear:   "2023",
		},
		{
			name:          "Doc year 2021 maps to major version 13 (corrected)",
			statusCode:    200,
			body:          `<div id="MOVEitPopUp"></div><a href="https://docs.ipswitch.com/MOVEit/Transfer2021/Help/">Docs</a>`,
			wantVersion:   "13",
			wantCPE:       "cpe:2.3:a:progress:moveit_transfer:13:*:*:*:*:*:*:*",
			wantDetection: "body",
			wantDocYear:   "2021",
		},
		{
			name:          "Doc year 2024 maps to major version 16 (corrected)",
			statusCode:    200,
			body:          `<div id="MOVEitPopUp"></div><a href="https://docs.ipswitch.com/MOVEit/Transfer2024/Help/">Docs</a>`,
			wantVersion:   "16",
			wantCPE:       "cpe:2.3:a:progress:moveit_transfer:16:*:*:*:*:*:*:*",
			wantDetection: "body",
			wantDocYear:   "2024",
		},
		{
			name:          "Doc year 2019 maps to major version 11",
			statusCode:    200,
			body:          `<div id="MOVEitPopUp"></div><a href="https://docs.ipswitch.com/MOVEit/Transfer2019/Help/">Docs</a>`,
			wantVersion:   "11",
			wantCPE:       "cpe:2.3:a:progress:moveit_transfer:11:*:*:*:*:*:*:*",
			wantDetection: "body",
			wantDocYear:   "2019",
		},
		{
			name:          "Doc year 2022 maps to major version 14",
			statusCode:    200,
			body:          `<div id="MOVEitPopUp"></div><a href="https://docs.ipswitch.com/MOVEit/Transfer2022/Help/">Docs</a>`,
			wantVersion:   "14",
			wantCPE:       "cpe:2.3:a:progress:moveit_transfer:14:*:*:*:*:*:*:*",
			wantDetection: "body",
			wantDocYear:   "2022",
		},
		{
			// DMZCookieTest alone (no body markers) is sufficient for detection
			name:          "DMZCookieTest cookie alone is sufficient for detection",
			statusCode:    200,
			cookies:       [][2]string{{"DMZCookieTest", "ifyoucanreadthisyourbrowsersupportscookies"}},
			body:          "<html><body></body></html>",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*",
			wantDetection: "dmz_cookie",
			wantDMZCookie: true,
		},
		{
			// DMZCookieTest + active probe path → detectionMethod "active_probe", dmz_cookie_present=true
			name:          "DMZCookieTest + active probe path → active_probe with dmz_cookie_present",
			statusCode:    200,
			cookies:       [][2]string{{"DMZCookieTest", "ifyoucanreadthisyourbrowsersupportscookies"}},
			body:          "<html><body></body></html>",
			probePath:     "/human.aspx",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*",
			wantDetection: "active_probe",
			wantProbePath: true,
			wantDMZCookie: true,
		},
		{
			// siLock cookie + body marker → detected, silock_cookie_present=true
			name:       "siLock cookie + body marker → silock_cookie_present in metadata",
			statusCode: 200,
			cookies:    [][2]string{{"siLockLongTermInstID", "abc123"}, {"siLockCSRFToken", "xyz"}},
			body:       `<div id="MOVEitPopUp"></div>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*",
			wantDetection: "body",
			wantSiLock:    true,
		},
		{
			name:          "Active probe: /human.aspx with marker sets probe_path and active_probe method",
			statusCode:    200,
			body:          "<html><head><title>MOVEit Transfer Sign On</title></head><body><div id=\"MOVEitPopUp\"></div></body></html>",
			probePath:     "/human.aspx",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*",
			wantDetection: "active_probe",
			wantProbePath: true,
		},
		{
			name:       "Full mock page matches (all markers)",
			statusCode: 200,
			body: `<!DOCTYPE html>
<html><head><title>MOVEit Transfer Sign On</title>
<link rel="stylesheet" href="/human/stylesheet_MOVEit.css">
<script src="/human/moveit.transfer.min.js"></script>
</head><body>
<div id="MOVEitPopUp"></div>
<div id="MOVEitDMZ_Form"><form method="post" action="/human.aspx"></form></div>
<a href="https://docs.ipswitch.com/MOVEit/Transfer2023/Help/Admin/en/">Docs</a>
</body></html>`,
			wantVersion:   "15",
			wantCPE:       "cpe:2.3:a:progress:moveit_transfer:15:*:*:*:*:*:*:*",
			wantDetection: "body",
			wantDocYear:   "2023",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MOVEitFingerprinter{}
			header := make(http.Header)
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
			if result.Technology != "moveit" {
				t.Errorf("Technology = %q, want moveit", result.Technology)
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
			if tt.wantProbePath {
				if pp, ok := result.Metadata["probe_path"].(string); !ok || pp != "/human.aspx" {
					t.Errorf("Metadata[probe_path] = %v, want /human.aspx", result.Metadata["probe_path"])
				}
			} else {
				if _, ok := result.Metadata["probe_path"]; ok {
					t.Errorf("Metadata[probe_path] should be absent, got %v", result.Metadata["probe_path"])
				}
			}
			if tt.wantDocYear != "" {
				if dy, ok := result.Metadata["doc_year"].(string); !ok || dy != tt.wantDocYear {
					t.Errorf("Metadata[doc_year] = %v, want %q", result.Metadata["doc_year"], tt.wantDocYear)
				}
			}
			if tt.wantDMZCookie {
				if v, ok := result.Metadata["dmz_cookie_present"].(bool); !ok || !v {
					t.Errorf("Metadata[dmz_cookie_present] = %v, want true", result.Metadata["dmz_cookie_present"])
				}
			}
			if tt.wantSiLock {
				if v, ok := result.Metadata["silock_cookie_present"].(bool); !ok || !v {
					t.Errorf("Metadata[silock_cookie_present] = %v, want true", result.Metadata["silock_cookie_present"])
				}
			}
		})
	}
}

// ── Fingerprint: negative (must return nil) ────────────────────────────────────

func TestMOVEitFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		cookies    [][2]string
	}{
		{name: "Generic IIS login page, no MOVEit markers", statusCode: 200, body: "<html><head><title>Sign In</title></head><body><form></form></body></html>"},
		{name: "FTP site with Move in text but no MOVEit markers", statusCode: 200, body: "<html><body>Move files here.</body></html>"},
		{name: "SharePoint login page (no MOVEit markers)", statusCode: 200, body: "<html><head><title>Sign In - SharePoint</title></head><body>Sign in</body></html>"},
		{name: "CPE-injection attempt", statusCode: 200, body: `<div id="MOVEitPopUp"></div><script>var v = ":*:malicious";</script>`},
		{name: "Body length > 2 MiB rejected", statusCode: 200, body: `<div id="MOVEitPopUp"></div>` + string(make([]byte, 2*1024*1024+1))},
		{name: "Status 500 rejected", statusCode: 500, body: `<div id="MOVEitPopUp"></div>`},
		{name: "Status 503 rejected", statusCode: 503, body: `<div id="MOVEitPopUp"></div>`},
		{name: "Empty body", statusCode: 200, body: ""},
		{name: "Partial marker: 'moveit' alone without full marker string", statusCode: 200, body: "<html><body>moveit to another folder</body></html>"},
		{
			// siLock cookie alone (no body markers, no DMZCookieTest) → nil
			name:       "siLock cookie alone without body markers → nil",
			statusCode: 200,
			body:       "<html><body><p>Login</p></body></html>",
			cookies:    [][2]string{{"siLockCSRFToken", "abc123"}},
		},
		{
			// DMZCookieTest with empty value → nil (value must contain the magic string)
			name:       "DMZCookieTest with empty value → nil",
			statusCode: 200,
			body:       "<html><body></body></html>",
			cookies:    [][2]string{{"DMZCookieTest", ""}},
		},
		{
			// DMZCookieTest with wrong value → nil
			name:       "DMZCookieTest with wrong value → nil",
			statusCode: 200,
			body:       "<html><body></body></html>",
			cookies:    [][2]string{{"DMZCookieTest", "someotherrandomvalue"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MOVEitFingerprinter{}
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

// ── DMZCookieTest detection ────────────────────────────────────────────────────

func TestMOVEitHasDMZCookieTest(t *testing.T) {
	t.Run("Cookie with correct value detected", func(t *testing.T) {
		header := make(http.Header)
		header.Add("Set-Cookie", (&http.Cookie{
			Name:  "DMZCookieTest",
			Value: "ifyoucanreadthisyourbrowsersupportscookies",
		}).String())
		resp := &http.Response{StatusCode: 200, Header: header}
		if !moveitHasDMZCookieTest(resp.Cookies()) {
			t.Error("moveitHasDMZCookieTest() = false, want true")
		}
	})

	t.Run("Cookie with wrong name not detected", func(t *testing.T) {
		header := make(http.Header)
		header.Add("Set-Cookie", (&http.Cookie{
			Name:  "SomeCookieTest",
			Value: "ifyoucanreadthisyourbrowsersupportscookies",
		}).String())
		resp := &http.Response{StatusCode: 200, Header: header}
		if moveitHasDMZCookieTest(resp.Cookies()) {
			t.Error("moveitHasDMZCookieTest() = true, want false for wrong name")
		}
	})

	t.Run("Cookie with wrong value not detected", func(t *testing.T) {
		header := make(http.Header)
		header.Add("Set-Cookie", (&http.Cookie{
			Name:  "DMZCookieTest",
			Value: "someothervalue",
		}).String())
		resp := &http.Response{StatusCode: 200, Header: header}
		if moveitHasDMZCookieTest(resp.Cookies()) {
			t.Error("moveitHasDMZCookieTest() = true, want false for wrong value")
		}
	})

	t.Run("No cookies not detected", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
		if moveitHasDMZCookieTest(resp.Cookies()) {
			t.Error("moveitHasDMZCookieTest() = true, want false with no cookies")
		}
	})
}

// ── siLock cookie detection ────────────────────────────────────────────────────

func TestMOVEitHasSiLockCookie(t *testing.T) {
	t.Run("siLockLongTermInstID cookie detected", func(t *testing.T) {
		header := make(http.Header)
		header.Add("Set-Cookie", (&http.Cookie{Name: "siLockLongTermInstID", Value: "abc"}).String())
		resp := &http.Response{StatusCode: 200, Header: header}
		if !moveitHasSiLockCookie(resp.Cookies()) {
			t.Error("moveitHasSiLockCookie() = false, want true")
		}
	})

	t.Run("siLockCSRFToken cookie detected", func(t *testing.T) {
		header := make(http.Header)
		header.Add("Set-Cookie", (&http.Cookie{Name: "siLockCSRFToken", Value: "abc"}).String())
		resp := &http.Response{StatusCode: 200, Header: header}
		if !moveitHasSiLockCookie(resp.Cookies()) {
			t.Error("moveitHasSiLockCookie() = false, want true")
		}
	})

	t.Run("Cookie not prefixed with siLock not detected", func(t *testing.T) {
		header := make(http.Header)
		header.Add("Set-Cookie", (&http.Cookie{Name: "sessionid", Value: "abc"}).String())
		resp := &http.Response{StatusCode: 200, Header: header}
		if moveitHasSiLockCookie(resp.Cookies()) {
			t.Error("moveitHasSiLockCookie() = true, want false")
		}
	})
}

// ── Active probe response ──────────────────────────────────────────────────────

func TestMOVEitFingerprinter_ActiveProbeResponse(t *testing.T) {
	fp := &MOVEitFingerprinter{}

	t.Run("/human.aspx response sets probe_path and active_probe detection", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/human.aspx"}},
		}
		body := `<html><head><title>MOVEit Transfer Sign On</title></head>
<body><div id="MOVEitPopUp"></div></body></html>`

		result, err := fp.Fingerprint(resp, []byte(body))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil, want non-nil")
		}
		if pp, ok := result.Metadata["probe_path"].(string); !ok || pp != "/human.aspx" {
			t.Errorf("probe_path = %v, want /human.aspx", result.Metadata["probe_path"])
		}
		if dm, ok := result.Metadata["detection_method"].(string); !ok || dm != "active_probe" {
			t.Errorf("detection_method = %v, want active_probe", result.Metadata["detection_method"])
		}
	})

	t.Run("Root response does not set probe_path", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
		result, err := fp.Fingerprint(resp, []byte(`<div id="MOVEitPopUp"></div>`))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil")
		}
		if _, ok := result.Metadata["probe_path"]; ok {
			t.Errorf("probe_path should be absent for root response, got %v", result.Metadata["probe_path"])
		}
	})

	t.Run("nil Request does not panic", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: make(http.Header), Request: nil}
		result, err := fp.Fingerprint(resp, []byte(`<div id="MOVEitPopUp"></div>`))
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

// ── TestExtractMOVEitVersion ───────────────────────────────────────────────────

func TestExtractMOVEitVersion(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantVersion string
		wantDocYear string
	}{
		{name: "2023 doc year → version 15", body: `<a href="https://docs.ipswitch.com/MOVEit/Transfer2023/Help/">Docs</a>`, wantVersion: "15", wantDocYear: "2023"},
		{name: "2022 doc year → version 14", body: `<a href="https://docs.ipswitch.com/MOVEit/Transfer2022/Help/">Docs</a>`, wantVersion: "14", wantDocYear: "2022"},
		{name: "2021 doc year → version 13 (corrected)", body: `<a href="https://docs.ipswitch.com/MOVEit/Transfer2021/Help/">Docs</a>`, wantVersion: "13", wantDocYear: "2021"},
		{name: "2020 doc year → version 12", body: `<a href="https://docs.ipswitch.com/MOVEit/Transfer2020/Help/">Docs</a>`, wantVersion: "12", wantDocYear: "2020"},
		{name: "2019 doc year → version 11", body: `<a href="https://docs.ipswitch.com/MOVEit/Transfer2019/Help/">Docs</a>`, wantVersion: "11", wantDocYear: "2019"},
		{name: "2024 doc year → version 16 (corrected)", body: `<a href="https://docs.ipswitch.com/MOVEit/Transfer2024/Help/">Docs</a>`, wantVersion: "16", wantDocYear: "2024"},
		{name: "Unknown year → doc_year returned, no version", body: `<a href="https://docs.ipswitch.com/MOVEit/Transfer2018/Help/">Docs</a>`, wantVersion: "", wantDocYear: "2018"},
		{name: "No doc link → empty version and doc_year", body: `<div id="MOVEitPopUp"></div>`, wantVersion: "", wantDocYear: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, docYear := extractMOVEitVersion([]byte(tt.body))
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
			if docYear != tt.wantDocYear {
				t.Errorf("docYear = %q, want %q", docYear, tt.wantDocYear)
			}
		})
	}
}

// ── TestBuildMOVEitCPE ─────────────────────────────────────────────────────────

func TestBuildMOVEitCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{name: "Major version 15", version: "15", want: "cpe:2.3:a:progress:moveit_transfer:15:*:*:*:*:*:*:*"},
		{name: "Major version 11", version: "11", want: "cpe:2.3:a:progress:moveit_transfer:11:*:*:*:*:*:*:*"},
		{name: "Empty version uses wildcard", version: "", want: "cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildMOVEitCPE(tt.version); got != tt.want {
				t.Errorf("buildMOVEitCPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

// ── Integration test ──────────────────────────────────────────────────────────

func TestMOVEitFingerprinter_Integration(t *testing.T) {
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &MOVEitFingerprinter{}
	Register(fp)

	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	body := []byte(`<!DOCTYPE html>
<html><head><title>MOVEit Transfer Sign On</title>
<link rel="stylesheet" href="/human/stylesheet_MOVEit.css">
<script src="/human/moveit.transfer.min.js"></script>
</head><body>
<div id="MOVEitPopUp"></div>
<a href="https://docs.ipswitch.com/MOVEit/Transfer2023/Help/Admin/en/">Docs</a>
</body></html>`)

	results := RunFingerprinters(resp, body)

	found := false
	for _, result := range results {
		if result.Technology == "moveit" {
			found = true
			if result.Version != "15" {
				t.Errorf("Version = %q, want 15", result.Version)
			}
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			} else if result.CPEs[0] != "cpe:2.3:a:progress:moveit_transfer:15:*:*:*:*:*:*:*" {
				t.Errorf("CPE = %q, want canonical CPE", result.CPEs[0])
			}
			if v, ok := result.Metadata["vendor"].(string); !ok || v != "Progress" {
				t.Errorf("Metadata[vendor] = %v, want Progress", result.Metadata["vendor"])
			}
			if prod, ok := result.Metadata["product"].(string); !ok || prod != "MOVEit Transfer" {
				t.Errorf("Metadata[product] = %v, want MOVEit Transfer", result.Metadata["product"])
			}
		}
	}
	if !found {
		t.Error("MOVEitFingerprinter not found in RunFingerprinters results")
	}
}

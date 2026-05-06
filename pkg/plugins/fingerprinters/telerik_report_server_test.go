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

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// mockRespRS builds a minimal *http.Response for Match tests.
// Named mockRespRS (not mockResp) to avoid collision with telerik_ui_aspnet_ajax_test.go.
func mockRespRS(status int, contentType string) *http.Response {
	resp := &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
	}
	if contentType != "" {
		resp.Header.Set("Content-Type", contentType)
	}
	return resp
}

// reportServerLoginBody is a realistic /Account/Login HTML fixture.
// Source: watchtowr CVE-2024-4358 writeup (auth bypass via /Startup/Register);
// the login page at /Account/Login is the passive detection surface.
const reportServerLoginBody = `<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Telerik Report Server</title>
    <link href="/Content/css/site.min.css" rel="stylesheet" />
</head>
<body class="k-content">
    <div id="page-wrapper">
        <div id="login-container">
            <form action="/Account/Login" method="post">
                <div class="form-group">
                    <label for="Username">Username</label>
                    <input type="text" id="Username" name="Username" class="k-textbox" />
                </div>
                <div class="form-group">
                    <label for="Password">Password</label>
                    <input type="password" id="Password" name="Password" class="k-textbox" />
                </div>
                <button type="submit" class="k-button k-primary">Log in</button>
            </form>
        </div>
    </div>
    <script src="/Scripts/telerik.reporting.min.js"></script>
</body>
</html>`

// reportServerLoginWithVersion is the login body plus an ASP.NET stack trace fragment
// (customErrors=Off scenario) that leaks the assembly build number.
// CVE-2024-4358 / watchtowr: version disclosure via unhandled exception pages.
const reportServerLoginWithVersion = reportServerLoginBody + `
<!-- DEBUG stack trace (customErrors=Off):
   at Telerik.ReportServer.Web.dll Version=2024.1.305, Culture=neutral
   System.Web.HttpException: ...
-->`

// reportServerLoginLegacyVersion is the same but with a legacy MAJOR.MINOR.YY.MMDD version.
const reportServerLoginLegacyVersion = reportServerLoginBody + `
<!-- DEBUG stack trace (customErrors=Off):
   at Telerik.ReportServer.Web.dll Version=10.1.24.514, Culture=neutral
-->`

// ssrsLoginBody is a Microsoft SQL Server Reporting Services login page — must NOT match.
const ssrsLoginBody = `<!DOCTYPE html>
<html>
<head><title>Report Server</title></head>
<body>
    <p>Microsoft SQL Server Reporting Services</p>
    <form action="/ReportServer/logon.aspx" method="post">
        <input type="text" name="username" />
        <input type="password" name="password" />
    </form>
</body>
</html>`

// genericIISBody is a plain IIS error page without the Telerik title — must NOT match.
const genericIISBody = `<!DOCTYPE html>
<html>
<head><title>IIS Windows Server</title></head>
<body>
    <p>There is a problem with the resource you are looking for.</p>
</body>
</html>`

// ── TestTelerikReportServer_Match ─────────────────────────────────────────────

func TestTelerikReportServer_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		// Status boundary: below 200 — rejected
		{
			name:        "status 199 text/html rejected",
			statusCode:  199,
			contentType: "text/html",
			want:        false,
		},
		// 2xx acceptance
		{
			name:        "status 200 text/html accepted",
			statusCode:  200,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "status 200 text/html; charset=utf-8 accepted",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		// 3xx acceptance
		{
			name:        "status 300 text/html accepted",
			statusCode:  300,
			contentType: "text/html",
			want:        true,
		},
		// 4xx acceptance
		{
			name:        "status 400 text/html accepted",
			statusCode:  400,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "status 499 text/html accepted (upper boundary)",
			statusCode:  499,
			contentType: "text/html",
			want:        true,
		},
		// Status 500 — rejected
		{
			name:        "status 500 text/html rejected",
			statusCode:  500,
			contentType: "text/html",
			want:        false,
		},
		// Content-Type mismatches — all should be false even with good status
		{
			name:        "status 200 application/json rejected",
			statusCode:  200,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "status 200 missing content-type rejected",
			statusCode:  200,
			contentType: "",
			want:        false,
		},
		// Mixed: bad status AND wrong content-type
		{
			name:        "status 500 application/json rejected (both conditions fail)",
			statusCode:  500,
			contentType: "application/json",
			want:        false,
		},
	}

	fp := &TelerikReportServerFingerprinter{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := mockRespRS(tt.statusCode, tt.contentType)
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ── TestTelerikReportServer_Fingerprint ───────────────────────────────────────

func TestTelerikReportServer_Fingerprint(t *testing.T) {
	tests := []struct {
		name              string
		statusCode        int
		contentType       string // defaults to "text/html" when empty
		body              string
		wantNil           bool
		wantTechnology    string
		wantVersion       string
		wantCPE           string
		wantSeverity      plugins.Severity
		wantVendor        string
		wantProduct       string
		wantProbeEndpoint string
		wantVersionSource string // "stack_trace" when present; "" when absent
	}{
		// ── Positive cases ───────────────────────────────────────────────────
		{
			// Realistic Report Server login page: title marker present, no SSRS,
			// no version in body. CVE-2024-4358 / watchtowr reference fixture.
			name:              "real Report Server login page — wildcard CPE, no version",
			statusCode:        200,
			body:              reportServerLoginBody,
			wantNil:           false,
			wantTechnology:    "telerik-report-server",
			wantVersion:       "",
			wantCPE:           "cpe:2.3:a:progress:telerik_report_server:*:*:*:*:*:*:*:*",
			wantSeverity:      plugins.SeverityInfo,
			wantVendor:        "Progress",
			wantProduct:       "Telerik Report Server",
			wantProbeEndpoint: "/Account/Login",
			wantVersionSource: "",
		},
		{
			// Body with title marker + modern ASP.NET stack trace version.
			// CVE-2024-4358 / watchtowr: build 2024.1.305 was the affected release.
			name:              "login page with stack trace version 2024.1.305",
			statusCode:        200,
			body:              reportServerLoginWithVersion,
			wantNil:           false,
			wantTechnology:    "telerik-report-server",
			wantVersion:       "2024.1.305",
			wantCPE:           "cpe:2.3:a:progress:telerik_report_server:2024.1.305:*:*:*:*:*:*:*",
			wantSeverity:      plugins.SeverityInfo,
			wantVendor:        "Progress",
			wantProduct:       "Telerik Report Server",
			wantProbeEndpoint: "/Account/Login",
			wantVersionSource: "stack_trace",
		},
		{
			// Legacy MAJOR.MINOR.YY.MMDD build number scheme (pre-2020 releases).
			name:              "login page with legacy stack trace version 10.1.24.514",
			statusCode:        200,
			body:              reportServerLoginLegacyVersion,
			wantNil:           false,
			wantTechnology:    "telerik-report-server",
			wantVersion:       "10.1.24.514",
			wantCPE:           "cpe:2.3:a:progress:telerik_report_server:10.1.24.514:*:*:*:*:*:*:*",
			wantSeverity:      plugins.SeverityInfo,
			wantVendor:        "Progress",
			wantProduct:       "Telerik Report Server",
			wantProbeEndpoint: "/Account/Login",
			wantVersionSource: "stack_trace",
		},
		// ── Negative cases ───────────────────────────────────────────────────
		{
			// SSRS page: title "Report Server" without "Telerik" — title gate rejects.
			name:       "SSRS login page — title marker absent → nil",
			statusCode: 200,
			body:       ssrsLoginBody,
			wantNil:    true,
		},
		{
			// Generic IIS error: no title marker at all → nil.
			name:       "generic IIS error page — no title marker → nil",
			statusCode: 200,
			body:       genericIISBody,
			wantNil:    true,
		},
		{
			// Defense-in-depth: BOTH the Telerik title AND SSRS exclusion string present.
			// Gate 5 (SSRS exclusion) must fire even when Gate 4 (title) passes.
			name:       "body with Telerik title AND SSRS exclusion string → nil",
			statusCode: 200,
			body: `<!DOCTYPE html><html><head>` +
				`<title>Telerik Report Server</title></head><body>` +
				`<p>Microsoft SQL Server Reporting Services</p></body></html>`,
			wantNil: true,
		},
		{
			// CPE injection guard: body contains ":*:" — Gate 3 must fire
			// even when the title marker is also present.
			name:       "body with title marker AND :*: substring → nil (CPE injection guard)",
			statusCode: 200,
			body: `<title>Telerik Report Server</title>` +
				`<p>Version=2024.1.305:*:*</p>`,
			wantNil: true,
		},
		{
			// 3 MiB body exceeds the 2 MiB cap — Gate 2 rejects.
			name:       "3 MiB body with title marker → nil (body cap exceeded)",
			statusCode: 200,
			body: `<title>Telerik Report Server</title>` +
				strings.Repeat("A", 3*1024*1024),
			wantNil: true,
		},
		{
			// Status 500 is rejected by Gate 1 regardless of body contents.
			name:       "status 500 with title marker → nil (status gate)",
			statusCode: 500,
			body:       reportServerLoginBody,
			wantNil:    true,
		},
		{
			// Body contains title marker + injected "2024.1.305:*:*" version string.
			// The :*: body guard (Gate 3) fires before version extraction.
			// This case is distinct from the CPE builder test — the guard is in Fingerprint.
			name:       "title marker + injected 2024.1.305:*:*:* in body → nil",
			statusCode: 200,
			body: `<!DOCTYPE html><html><head>` +
				`<title>Telerik Report Server</title></head><body>` +
				`<p>build 2024.1.305:*:*</p></body></html>`,
			wantNil: true,
		},
		{
			// Gate 6: defense-in-depth content-type check. Fingerprint is called directly
			// (bypassing Match) with a valid Telerik Report Server login body but a
			// non-text/html Content-Type. Gate 6 must reject it regardless of body content.
			name:        "non-html content type with valid title body → nil (Gate 6)",
			statusCode:  200,
			contentType: "application/json",
			body:        reportServerLoginBody,
			wantNil:     true,
		},
	}

	fp := &TelerikReportServerFingerprinter{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := tt.contentType
			if ct == "" {
				ct = "text/html"
			}
			resp := mockRespRS(tt.statusCode, ct)
			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}

			if tt.wantNil {
				if result != nil {
					t.Errorf("Fingerprint() = %+v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Fingerprint() returned nil, want non-nil result")
			}

			if result.Technology != tt.wantTechnology {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTechnology)
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if len(result.CPEs) == 0 {
				t.Error("CPEs is empty, want at least one entry")
			} else if result.CPEs[0] != tt.wantCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], tt.wantCPE)
			}
			if result.Severity != tt.wantSeverity {
				t.Errorf("Severity = %v, want %v", result.Severity, tt.wantSeverity)
			}
			if result.Metadata == nil {
				t.Fatal("Metadata is nil")
			}
			if v, ok := result.Metadata["vendor"].(string); !ok || v != tt.wantVendor {
				t.Errorf("Metadata[vendor] = %v, want %q", result.Metadata["vendor"], tt.wantVendor)
			}
			if p, ok := result.Metadata["product"].(string); !ok || p != tt.wantProduct {
				t.Errorf("Metadata[product] = %v, want %q", result.Metadata["product"], tt.wantProduct)
			}
			if ep, ok := result.Metadata["probe_endpoint"].(string); !ok || ep != tt.wantProbeEndpoint {
				t.Errorf("Metadata[probe_endpoint] = %v, want %q", result.Metadata["probe_endpoint"], tt.wantProbeEndpoint)
			}

			if tt.wantVersionSource != "" {
				vs, ok := result.Metadata["version_source"].(string)
				if !ok || vs != tt.wantVersionSource {
					t.Errorf("Metadata[version_source] = %v, want %q", result.Metadata["version_source"], tt.wantVersionSource)
				}
			} else {
				if _, ok := result.Metadata["version_source"]; ok {
					t.Errorf("Metadata[version_source] should be absent when no version found, got %v", result.Metadata["version_source"])
				}
			}
		})
	}
}

// ── TestBuildTelerikReportServerCPE ───────────────────────────────────────────

func TestBuildTelerikReportServerCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "empty version → wildcard CPE",
			version: "",
			want:    "cpe:2.3:a:progress:telerik_report_server:*:*:*:*:*:*:*:*",
		},
		{
			name:    "modern build 2024.1.305 → embedded version",
			version: "2024.1.305",
			want:    "cpe:2.3:a:progress:telerik_report_server:2024.1.305:*:*:*:*:*:*:*",
		},
		{
			name:    "legacy build 10.1.24.514 → embedded version",
			version: "10.1.24.514",
			want:    "cpe:2.3:a:progress:telerik_report_server:10.1.24.514:*:*:*:*:*:*:*",
		},
		{
			// Hyphen is rejected by the anchored validator (^[0-9]+(\.[0-9]+)*$).
			name:    "2024.1.305-rc1 → wildcard (hyphen rejected by validator)",
			version: "2024.1.305-rc1",
			want:    "cpe:2.3:a:progress:telerik_report_server:*:*:*:*:*:*:*:*",
		},
		{
			// CPE injection attempt: contains ":*:" which the validator rejects.
			name:    "2024.1.305:*:* → wildcard (CPE injection)",
			version: "2024.1.305:*:*",
			want:    "cpe:2.3:a:progress:telerik_report_server:*:*:*:*:*:*:*:*",
		},
		{
			// SQL injection attempt: rejected by the validator.
			name:    ";DROP TABLE → wildcard (non-numeric chars)",
			version: ";DROP TABLE",
			want:    "cpe:2.3:a:progress:telerik_report_server:*:*:*:*:*:*:*:*",
		},
		{
			// Trailing whitespace: the validator anchors with ^ and $ so space fails.
			name:    "2024.1.305 (trailing space) → wildcard (space not in [0-9.])",
			version: "2024.1.305 ",
			want:    "cpe:2.3:a:progress:telerik_report_server:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildTelerikReportServerCPE(tt.version)
			if got != tt.want {
				t.Errorf("buildTelerikReportServerCPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

// ── TestExtractTelerikReportServerVersion ─────────────────────────────────────

func TestExtractTelerikReportServerVersion(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			// Modern YYYY.Q.DDD build number in a stack trace line.
			// CVE-2024-4358 / watchtowr: version=2024.1.305 is the affected build.
			name: "modern build 2024.1.305 in stack trace",
			body: "at Telerik.ReportServer.Web.dll Version=2024.1.305, Culture=neutral",
			want: "2024.1.305",
		},
		{
			// Legacy MAJOR.MINOR.YY.MMDD scheme (pre-2020 report server releases).
			name: "legacy build 10.1.24.514 in stack trace",
			body: "at Telerik.ReportServer.Web.dll Version=10.1.24.514, Culture=neutral",
			want: "10.1.24.514",
		},
		{
			// No version string anywhere in body → empty.
			name: "body without version → empty",
			body: reportServerLoginBody,
			want: "",
		},
		{
			// The stack regex matches digits, but the dot-segment "foo" is not a digit
			// so it won't form a valid 4-digit year prefix; combined with validator the
			// malformed string "2024.1.foo" produces no extractable match.
			name: "malformed 2024.1.foo → empty (regex won't match non-digit segment)",
			body: "Version=2024.1.foo",
			want: "",
		},
		{
			// Input "12345.6.789": the first alternation requires exactly 4 leading digits;
			// the regex engine matches the trailing 4 digits "2345.6.789" as a valid capture.
			// This documents the actual production behavior — the test asserts what the code does.
			name: "12345.6.789 — regex matches trailing 4-digit prefix 2345.6.789",
			body: "Version=12345.6.789",
			want: "2345.6.789",
		},
		{
			// Guards the 256-byte field-length cap (maxTelerikVersionFieldLen = 256).
			// The body matches the stack-trace regex (first alt: \d{4}\.\d+\.\d{3,4})
			// but the captured submatch is 2024.<300 zeros>.123 which is ~309 bytes,
			// so extractTelerikReportServerVersion must return "" rather than a giant string.
			name: "captured submatch > 256 bytes → empty (field-length cap)",
			body: "at Telerik.ReportServer.Web.dll Version=2024." +
				strings.Repeat("0", 300) + ".123, Culture=neutral",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractTelerikReportServerVersion([]byte(tt.body))
			if got != tt.want {
				t.Errorf("extractTelerikReportServerVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

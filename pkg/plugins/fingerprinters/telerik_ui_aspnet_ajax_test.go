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
	"bytes"
	"net/http"
	"strings"
	"testing"
)

// mockResp builds a minimal *http.Response for testing. Body bytes are passed
// separately to Fingerprint; this helper only wires StatusCode and Content-Type.
// Named mockResp (not mockRespAJAX) because it is defined once here; the parallel
// telerik_report_server_test.go must use a differently-named helper to avoid
// duplicate-symbol errors within the same package.
func mockResp(status int, contentType string) *http.Response {
	resp := &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
	}
	if contentType != "" {
		resp.Header.Set("Content-Type", contentType)
	}
	return resp
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// radAsyncUploadRealBody is the canonical JSON returned by Telerik.Web.UI.WebResource.axd?type=rau
// when the RadAsyncUpload handler is registered. The misspelling of "successfully" is
// vendor-canonical and has been stable since ~2010. Shape derived from Tenable plugin 130128
// reference response.
const radAsyncUploadRealBody = `{"message":"RadAsyncUpload handler is registered succesfully, however, it may not be accessed directly."}`

// dialogHandlerRealBody is a realistic HTML fragment returned by
// Telerik.Web.UI.DialogHandler.aspx when accessed unauthenticated. Both required
// markers must be present: Telerik.Web.UI.DialogHandler and dialogParametersHolder.
const dialogHandlerRealBody = `<!DOCTYPE html>
<html>
<head><title>Telerik.Web.UI.DialogHandler</title></head>
<body>
<form id="aspnetForm" method="post" action="/Telerik.Web.UI.DialogHandler.aspx">
<input type="hidden" name="dialogParametersHolder" id="dialogParametersHolder" value="" />
<script>
  Telerik.Web.UI.DialogHandler.initialize();
</script>
</form>
</body>
</html>`

// dialogHandlerStackTraceBody contains both markers plus a Telerik.Web.UI assembly
// version embedded in an ASP.NET stack trace (customErrors=Off). Used to test
// opportunistic version extraction.
const dialogHandlerStackTraceBody = `<!DOCTYPE html>
<html>
<head><title>Telerik.Web.UI.DialogHandler</title></head>
<body>
<form action="/Telerik.Web.UI.DialogHandler.aspx">
<input type="hidden" name="dialogParametersHolder" id="dialogParametersHolder" value="" />
</form>
<div id="stackTrace">
System.Web.HttpException: Error
   at Telerik.Web.UI, Version=2019.3.1023, Culture=neutral, PublicKeyToken=121fae78165ba3d4
   at System.Web.UI.Page.ProcessRequest(HttpContext context)
</div>
</body>
</html>`

// ---------------------------------------------------------------------------
// TestTelerikRadAsyncUpload_Match
// ---------------------------------------------------------------------------

func TestTelerikRadAsyncUpload_Match(t *testing.T) {
	fp := &TelerikRadAsyncUploadFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{"status 199 below boundary → false", 199, false},
		{"status 200 lower boundary → true", 200, true},
		{"status 300 redirect → true", 300, true},
		{"status 400 client error → true", 400, true},
		{"status 499 upper boundary → true", 499, true},
		{"status 500 server error → false", 500, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := mockResp(tt.statusCode, "")
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestTelerikRadAsyncUpload_Fingerprint
// ---------------------------------------------------------------------------

func TestTelerikRadAsyncUpload_Fingerprint(t *testing.T) {
	fp := &TelerikRadAsyncUploadFingerprinter{}

	tests := []struct {
		name           string
		statusCode     int
		contentType    string
		body           []byte
		wantNil        bool
		wantTechnology string
		wantVersion    string
		wantCPE        string
		wantVendor     string // non-empty → assert metadata["vendor"]
		wantProduct    string // non-empty → assert metadata["product"]
	}{
		{
			// Tenable plugin 130128 reference response shape.
			name:           "real rau body with application/json → detected, empty version, wildcard CPE",
			statusCode:     200,
			contentType:    "application/json; charset=utf-8",
			body:           []byte(radAsyncUploadRealBody),
			wantNil:        false,
			wantTechnology: "telerik-ui-aspnet-ajax",
			wantVersion:    "",
			wantCPE:        "cpe:2.3:a:telerik:ui_for_asp.net_ajax:*:*:*:*:*:*:*:*",
			wantVendor:     "Telerik",
			wantProduct:    "Telerik UI for ASP.NET AJAX",
		},
		{
			name:        "rau JSON body without misspelled marker → nil",
			statusCode:  200,
			contentType: "application/json; charset=utf-8",
			body:        []byte(`{"message":"RadAsyncUpload handler is registered successfully."}`),
			wantNil:     true,
		},
		{
			name:        "body containing :*: injection sequence → nil",
			statusCode:  200,
			contentType: "application/json; charset=utf-8",
			body:        []byte(`{"message":"RadAsyncUpload handler is registered succesfully:*:*:*"}`),
			wantNil:     true,
		},
		{
			name:        "3 MiB body with marker → nil (body cap exceeded)",
			statusCode:  200,
			contentType: "application/json; charset=utf-8",
			body: func() []byte {
				// Prefix is the real marker; pad to exceed 2 MiB cap.
				prefix := []byte(radAsyncUploadRealBody)
				pad := bytes.Repeat([]byte("x"), 3*1024*1024)
				return append(prefix, pad...)
			}(),
			wantNil: true,
		},
		{
			name:        "status 500 with valid body → nil",
			statusCode:  500,
			contentType: "application/json; charset=utf-8",
			body:        []byte(radAsyncUploadRealBody),
			wantNil:     true,
		},
		{
			name:        "marker present, non-JSON Content-Type, body does not start with { → nil",
			statusCode:  200,
			contentType: "text/plain",
			body:        []byte("RadAsyncUpload handler is registered succesfully, however, it may not be accessed directly."),
			wantNil:     true,
		},
		{
			name:           "marker present, no JSON Content-Type, but body starts with { → success",
			statusCode:     200,
			contentType:    "application/octet-stream",
			body:           []byte(radAsyncUploadRealBody),
			wantNil:        false,
			wantTechnology: "telerik-ui-aspnet-ajax",
			wantVersion:    "",
			wantCPE:        "cpe:2.3:a:telerik:ui_for_asp.net_ajax:*:*:*:*:*:*:*:*",
			wantVendor:     "Telerik",
			wantProduct:    "Telerik UI for ASP.NET AJAX",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := mockResp(tt.statusCode, tt.contentType)

			result, err := fp.Fingerprint(resp, tt.body)
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}

			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Fingerprint() returned nil, expected result")
			}

			if result.Technology != tt.wantTechnology {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTechnology)
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if len(result.CPEs) == 0 {
				t.Fatal("CPEs is empty")
			}
			if result.CPEs[0] != tt.wantCPE {
				t.Errorf("CPEs[0] = %q, want %q", result.CPEs[0], tt.wantCPE)
			}
			if tt.wantVendor != "" {
				if v, ok := result.Metadata["vendor"].(string); !ok || v != tt.wantVendor {
					t.Errorf("Metadata[vendor] = %v, want %q", result.Metadata["vendor"], tt.wantVendor)
				}
			}
			if tt.wantProduct != "" {
				if p, ok := result.Metadata["product"].(string); !ok || p != tt.wantProduct {
					t.Errorf("Metadata[product] = %v, want %q", result.Metadata["product"], tt.wantProduct)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestTelerikDialogHandler_Match
// ---------------------------------------------------------------------------

func TestTelerikDialogHandler_Match(t *testing.T) {
	fp := &TelerikDialogHandlerFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{"status 199 below boundary → false", 199, false},
		{"status 200 lower boundary → true", 200, true},
		{"status 300 redirect → true", 300, true},
		{"status 400 client error → true", 400, true},
		{"status 499 upper boundary → true", 499, true},
		{"status 500 server error → false", 500, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := mockResp(tt.statusCode, "")
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestTelerikDialogHandler_Fingerprint
// ---------------------------------------------------------------------------

func TestTelerikDialogHandler_Fingerprint(t *testing.T) {
	fp := &TelerikDialogHandlerFingerprinter{}

	tests := []struct {
		name              string
		statusCode        int
		contentType       string
		body              []byte
		wantNil           bool
		wantTechnology    string
		wantVersion       string
		wantCPE           string
		wantVersionSource string // non-empty → assert metadata["version_source"]
		wantVendor        string // non-empty → assert metadata["vendor"]
		wantProduct       string // non-empty → assert metadata["product"]
	}{
		{
			name:           "real DialogHandler body with both markers → detected, empty version, wildcard CPE",
			statusCode:     200,
			contentType:    "text/html; charset=utf-8",
			body:           []byte(dialogHandlerRealBody),
			wantNil:        false,
			wantTechnology: "telerik-ui-aspnet-ajax",
			wantVersion:    "",
			wantCPE:        "cpe:2.3:a:telerik:ui_for_asp.net_ajax:*:*:*:*:*:*:*:*",
			wantVendor:     "Telerik",
			wantProduct:    "Telerik UI for ASP.NET AJAX",
		},
		{
			// Sitefinity-style FP guard: only first marker present.
			name:        "body with only dialogHandlerMarker1 (missing dialogParametersHolder) → nil",
			statusCode:  200,
			contentType: "text/html",
			body:        []byte(`<html><body>Telerik.Web.UI.DialogHandler is available.</body></html>`),
			wantNil:     true,
		},
		{
			name:        "body with only dialogParametersHolder (missing Telerik.Web.UI.DialogHandler) → nil",
			statusCode:  200,
			contentType: "text/html",
			body:        []byte(`<html><body><input name="dialogParametersHolder" /></body></html>`),
			wantNil:     true,
		},
		{
			// Sitefinity CMS pages may reference Telerik.Web.UI in stack traces without
			// being the standalone DialogHandler endpoint. Missing DialogHandler marker ensures no FP.
			name:        "Sitefinity-style body with Telerik.Web.UI in stack trace only → nil",
			statusCode:  200,
			contentType: "text/html",
			body: []byte(`<!DOCTYPE html><html><head><title>Error</title></head><body>
<div>Sitefinity CMS Error
   at Telerik.Web.UI.RadAjaxManager.OnPreRender
</div>
</body></html>`),
			wantNil: true,
		},
		{
			name:              "body with both markers + stack-trace version 2019.3.1023 → version extracted, correct CPE, metadata set",
			statusCode:        200,
			contentType:       "text/html; charset=utf-8",
			body:              []byte(dialogHandlerStackTraceBody),
			wantNil:           false,
			wantTechnology:    "telerik-ui-aspnet-ajax",
			wantVersion:       "2019.3.1023",
			wantCPE:           "cpe:2.3:a:telerik:ui_for_asp.net_ajax:2019.3.1023:*:*:*:*:*:*:*",
			wantVersionSource: "stack_trace",
			wantVendor:        "Telerik",
			wantProduct:       "Telerik UI for ASP.NET AJAX",
		},
		{
			// The body contains `:*:` (injected via the version-like string in the stack trace),
			// which is rejected by the body-level CPE-injection guard before markers are checked.
			name:        "body with both markers + injected :*: in stack trace → nil (body-level guard)",
			statusCode:  200,
			contentType: "text/html",
			body: []byte(`<!DOCTYPE html><html><head><title>Telerik.Web.UI.DialogHandler</title></head>
<body>
<form action="/Telerik.Web.UI.DialogHandler.aspx">
<input type="hidden" name="dialogParametersHolder" id="dialogParametersHolder" value="" />
</form>
<div>
  Telerik.Web.UI, Version=2019.3.1023:*:*:*
</div>
</body></html>`),
			wantNil: true,
		},
		{
			name:        "3 MiB body with both markers → nil (body cap exceeded)",
			statusCode:  200,
			contentType: "text/html",
			body: func() []byte {
				prefix := []byte(dialogHandlerRealBody)
				pad := bytes.Repeat([]byte("x"), 3*1024*1024)
				return append(prefix, pad...)
			}(),
			wantNil: true,
		},
		{
			name:        "status 500 with both markers → nil",
			statusCode:  500,
			contentType: "text/html",
			body:        []byte(dialogHandlerRealBody),
			wantNil:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := mockResp(tt.statusCode, tt.contentType)

			result, err := fp.Fingerprint(resp, tt.body)
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}

			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Fingerprint() returned nil, expected result")
			}

			if result.Technology != tt.wantTechnology {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTechnology)
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if len(result.CPEs) == 0 {
				t.Fatal("CPEs is empty")
			}
			if result.CPEs[0] != tt.wantCPE {
				t.Errorf("CPEs[0] = %q, want %q", result.CPEs[0], tt.wantCPE)
			}
			if tt.wantVersionSource != "" {
				vs, _ := result.Metadata["version_source"].(string)
				if vs != tt.wantVersionSource {
					t.Errorf("Metadata[version_source] = %q, want %q", vs, tt.wantVersionSource)
				}
			}
			if tt.wantVendor != "" {
				if v, ok := result.Metadata["vendor"].(string); !ok || v != tt.wantVendor {
					t.Errorf("Metadata[vendor] = %v, want %q", result.Metadata["vendor"], tt.wantVendor)
				}
			}
			if tt.wantProduct != "" {
				if p, ok := result.Metadata["product"].(string); !ok || p != tt.wantProduct {
					t.Errorf("Metadata[product] = %v, want %q", result.Metadata["product"], tt.wantProduct)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestBuildTelerikUICPE
// ---------------------------------------------------------------------------

func TestBuildTelerikUICPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "empty version → wildcard CPE",
			version: "",
			want:    "cpe:2.3:a:telerik:ui_for_asp.net_ajax:*:*:*:*:*:*:*:*",
		},
		{
			name:    "valid version 2019.3.1023 → embedded",
			version: "2019.3.1023",
			want:    "cpe:2.3:a:telerik:ui_for_asp.net_ajax:2019.3.1023:*:*:*:*:*:*:*",
		},
		{
			name:    "valid version with build 2024.1.305.45 → embedded",
			version: "2024.1.305.45",
			want:    "cpe:2.3:a:telerik:ui_for_asp.net_ajax:2024.1.305.45:*:*:*:*:*:*:*",
		},
		{
			// Not a 4-digit year prefix; the anchored validator rejects non-YYYY.Q.MMDD shape.
			name:    "version 1.2 (not 4-digit year) → wildcard fallback",
			version: "1.2",
			want:    "cpe:2.3:a:telerik:ui_for_asp.net_ajax:*:*:*:*:*:*:*:*",
		},
		{
			// CPE injection attempt: injected :*: component separators.
			name:    "injection attempt 2019.3.1023:*:*:*:*:*:*:* → wildcard fallback",
			version: "2019.3.1023:*:*:*:*:*:*:*",
			want:    "cpe:2.3:a:telerik:ui_for_asp.net_ajax:*:*:*:*:*:*:*:*",
		},
		{
			// SQL-like injection; fails anchored validator.
			name:    ";DROP TABLE users; → wildcard fallback",
			version: ";DROP TABLE users;",
			want:    "cpe:2.3:a:telerik:ui_for_asp.net_ajax:*:*:*:*:*:*:*:*",
		},
		{
			// Leading/trailing space fails anchored validator (space not in \d+\.\d+…).
			name:    "space-only string → wildcard fallback",
			version: " ",
			want:    "cpe:2.3:a:telerik:ui_for_asp.net_ajax:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildTelerikUICPE(tt.version); got != tt.want {
				t.Errorf("buildTelerikUICPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestExtractTelerikAJAXVersion
// ---------------------------------------------------------------------------

func TestExtractTelerikAJAXVersion(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "plain HTML without version pattern → empty",
			body: `<html><body><p>Hello World</p></body></html>`,
			want: "",
		},
		{
			name: "body with valid Telerik.Web.UI, Version=2019.3.1023 → 2019.3.1023",
			body: `Server error: Telerik.Web.UI, Version=2019.3.1023, Culture=neutral`,
			want: "2019.3.1023",
		},
		{
			name: "body with Telerik.Web.UI Version=2019.3.1023 (no comma) → 2019.3.1023 (regex allows [, ]+)",
			body: `Error at Telerik.Web.UI Version=2019.3.1023 PublicKeyToken=abc`,
			want: "2019.3.1023",
		},
		{
			name: "body with malformed Telerik.Web.UI, Version=foo.bar → empty (validator rejects)",
			body: `Error at Telerik.Web.UI, Version=foo.bar, Culture=neutral`,
			want: "",
		},
		{
			name: "multi-line content containing version → still extracts (regex not line-anchored)",
			body: strings.Join([]string{
				"Line one of the error response.",
				"Line two contains the assembly info:",
				"  Telerik.Web.UI, Version=2024.1.305, Culture=neutral, PublicKeyToken=121fae78165ba3d4",
				"Line four continues normally.",
			}, "\n"),
			want: "2024.1.305",
		},
		{
			name: "version-like string without Telerik.Web.UI prefix → empty",
			body: `Version=2019.3.1023 is referenced here but not preceded by Telerik.Web.UI`,
			want: "",
		},
		{
			// Guards the 256-byte field-length cap (maxTelerikVersionFieldLen = 256).
			// The body matches the AJAX stack-trace regex but the captured submatch
			// is 2024.1.<300 zeros> which is ~307 bytes, so extractTelerikAJAXVersion
			// must return "" rather than a giant version string.
			name: "captured submatch > 256 bytes → empty (field-length cap)",
			body: "at Telerik.Web.UI, Version=2024.1." + strings.Repeat("0", 300) +
				", Culture=neutral, PublicKeyToken=121fae78165ba3d4",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractTelerikAJAXVersion([]byte(tt.body)); got != tt.want {
				t.Errorf("extractTelerikAJAXVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestTelerikUI_DistinctRegistryNames is a regression guard. Both Telerik UI for
// ASP.NET AJAX fingerprinters share a Technology slug but MUST use distinct Name()
// values so they don't collide in registry.GetProbeEndpoints (keyed by Name).
func TestTelerikUI_DistinctRegistryNames(t *testing.T) {
	// Snapshot and restore the global registry so this test is order-independent.
	// Other tests in the suite reset httpFingerprinters = nil after themselves, so
	// we must re-register the two fingerprinters explicitly here.
	saved := append([]HTTPFingerprinter(nil), httpFingerprinters...)
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil
	Register(&TelerikRadAsyncUploadFingerprinter{})
	Register(&TelerikDialogHandlerFingerprinter{})

	endpoints := GetProbeEndpoints()
	cases := map[string]string{
		"telerik-ui-aspnet-ajax-rau":    "/Telerik.Web.UI.WebResource.axd?type=rau",
		"telerik-ui-aspnet-ajax-dialog": "/Telerik.Web.UI.DialogHandler.aspx",
	}
	for name, wantEndpoint := range cases {
		if got := endpoints[name]; got != wantEndpoint {
			t.Errorf("GetProbeEndpoints()[%q] = %q, want %q", name, got, wantEndpoint)
		}
	}
}

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
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const citrixGatewayBody = `<!DOCTYPE html PUBLIC "-//W3C//DTD XDEV_HTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html><head>
<title class="_ctxstxt_NetscalerGateway">Citrix Gateway</title>
<link rel="SHORTCUT ICON" href="/vpn/images/AccessGateway.ico">
<script src="/vpn/login.js"></script>
<script src="/vpn/js/rdx.js"></script>
</head><body class="ns_body"></body></html>`

const citrixAAABody = `<!DOCTYPE html><html><head>
<title class="_ctxstxt_NetscalerAAA">NetScaler AAA</title>
<link rel="ICON" href="/logon/LogonPoint/receiver/images/common/icon_vpn.ico">
<script src="/logon/LogonPoint/init.js"></script>
</head><body></body></html>`

func newCitrixResp(body string, headers map[string]string) *http.Response {
	h := make(http.Header)
	h.Set("Content-Type", "text/html; charset=utf-8")
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: 200, Header: h}
}

// newCitrix302Resp builds a 302 response with the given Location and cookies.
// cookies is a slice of raw Set-Cookie header values (e.g. "NSC_AAAC=xyz; Path=/").
func newCitrix302Resp(location string, extraHeaders map[string]string, cookies []string) *http.Response {
	h := make(http.Header)
	h.Set("Content-Type", "text/html; charset=utf-8")
	if location != "" {
		h.Set("Location", location)
	}
	for k, v := range extraHeaders {
		h.Set(k, v)
	}
	for _, c := range cookies {
		h.Add("Set-Cookie", c)
	}
	return &http.Response{StatusCode: 302, Header: h}
}

// --- TestCitrixNetScalerFingerprinter_Name ---

func TestCitrixNetScalerFingerprinter_Name(t *testing.T) {
	assert.Equal(t, "citrix-netscaler", (&CitrixNetScalerFingerprinter{}).Name())
}

// --- TestCitrixNetScalerFingerprinter_Match ---

func TestCitrixNetScalerFingerprinter_Match(t *testing.T) {
	fp := &CitrixNetScalerFingerprinter{}
	tests := []struct {
		name string
		ct   string
		want bool
	}{
		{"text/html", "text/html", true},
		{"text/html charset", "text/html; charset=utf-8", true},
		{"application/xhtml+xml", "application/xhtml+xml", true},
		{"empty CT", "", true},
		{"application/json", "application/json", false},
		{"text/plain", "text/plain", false},
		{"uppercase TEXT/HTML", "TEXT/HTML", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{"Content-Type": []string{tt.ct}}}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
	t.Run("nil response returns false", func(t *testing.T) { assert.False(t, fp.Match(nil)) })
}

// --- TestCitrixNetScalerFingerprinter_Fingerprint ---

func TestCitrixNetScalerFingerprinter_Fingerprint(t *testing.T) {
	cspCSP := map[string]string{"Content-Security-Policy": "default-src citrixng://"}
	viahdr := map[string]string{"Via": "NS-CACHE-10.0:  10"}
	nscsp := map[string]string{"Content-Security-Policy": "report-uri /nscsp_violation/report_uri"}

	cookieResp := func(extra map[string]string) *http.Response {
		r := &http.Response{StatusCode: 200, Header: make(http.Header)}
		r.Header.Set("Content-Type", "text/html")
		r.Header.Add("Set-Cookie", "pwcount=0; HttpOnly")
		for k, v := range extra {
			r.Header.Set(k, v)
		}
		return r
	}

	type row struct {
		name, body    string
		resp          *http.Response
		wantNil       bool
		wantProd      string
		wantLoginPath string
	}
	gTitle := `<title class="_ctxstxt_NetscalerGateway">Citrix Gateway</title>`
	tests := []row{
		{"gateway class+CSP citrixng", gTitle, newCitrixResp("", cspCSP), false, "Gateway", "/vpn/index.html"},
		{"gateway class+Via NS-CACHE", gTitle, newCitrixResp("", viahdr), false, "Gateway", "/vpn/index.html"},
		{"gateway class+cookie pwcount", gTitle, cookieResp(nil), false, "Gateway", ""},
		{"gateway class+/vpn/login.js (A+C)", gTitle + `<script src="/vpn/login.js"></script>`, newCitrixResp("", nil), false, "Gateway", ""},
		{"AAA class+Via tmindex", citrixAAABody, newCitrixResp("", viahdr), false, "AAA", "/logon/LogonPoint/tmindex.html"},
		{"AAA class+LogonPoint/receiver", citrixAAABody, newCitrixResp("", nil), false, "AAA", ""},
		{"plain NetScaler Gateway+report-uri nscsp", `<title>NetScaler Gateway</title>`, newCitrixResp("", nscsp), false, "Gateway", "/vpn/index.html"},
		{"plain Citrix Gateway+CSP citrixng", `<title>Citrix Gateway</title>`, newCitrixResp("", cspCSP), false, "Gateway", ""},
		{"plain NetScaler AAA+cookie", `<title>NetScaler AAA</title>`, cookieResp(nil), false, "AAA", ""},
		{"realistic gateway body all signals", citrixGatewayBody, newCitrixResp("", map[string]string{"Content-Security-Policy": "default-src citrixng://", "Via": "NS-CACHE-10.0:  10"}), false, "Gateway", "/vpn/index.html"},
		// Body-marker login_path coverage — explicit switch branches.
		{"body has LogonPoint/index.html marker", gTitle + `<a href="/logon/LogonPoint/index.html">login</a><script src="/vpn/js/rdx.js"></script>`, newCitrixResp("", viahdr), false, "Gateway", "/logon/LogonPoint/index.html"},
		{"body has vpn/index.html marker no other marker", gTitle + `<a href="/vpn/index.html">start</a>` + `<script src="/vpn/login.js"></script>`, newCitrixResp("", nil), false, "Gateway", "/vpn/index.html"},
		// Negative cases — gate failures
		{"title-class only no B/C", gTitle, newCitrixResp("", nil), true, "", ""},
		{"CSP only no title", `<title>Welcome</title>`, newCitrixResp("", cspCSP), true, "", ""},
		{"cookie only no title", `<title>Welcome</title>`, cookieResp(nil), true, "", ""},
		{"vpn/login.js body no title", `<script src="/vpn/login.js"></script>`, newCitrixResp("", nil), true, "", ""},
		{"empty body", "", newCitrixResp("", nil), true, "", ""},
		{"non-HTML body", `{"status":"ok"}`, newCitrixResp("", nil), true, "", ""},
		{"nil resp", citrixGatewayBody, nil, true, "", ""},
		{"phishing title only no corroboration", `<title>Citrix Gateway</title>`, newCitrixResp("", nil), true, "", ""},
		{"Shodan FP vpn/images meta-refresh vicidial", `<html><head><title>Welcome</title><meta http-equiv="refresh" content="0;url=/vicidial/welcome.php"><link href="/vpn/images/logo.png"></head></html>`, newCitrixResp("", nil), true, "", ""},
		{"OpenCms on 3794 no Citrix title", `<title>OpenCms</title>`, newCitrixResp("", map[string]string{"Server": "Apache-Coyote/1.1"}), true, "", ""},
		{"Coturn on 2351 no Citrix title", `<title>Coturn TURN Server</title>`, newCitrixResp("", nil), true, "", ""},
		// --- 302 redirect detection: NSC_ cookie iron-clad path ---
		{"302 redirect to /vpn/ with NSC_AAAC+CSP",
			"",
			newCitrix302Resp("/vpn/index.html",
				map[string]string{"Content-Security-Policy": "default-src 'self'; frame-src citrixng://"},
				[]string{"NSC_AAAC=xyz; Path=/; Secure"}),
			false, "Gateway", "/vpn/index.html"},
		{"302 redirect to /logon/LogonPoint/ with NSC_EPAC",
			"",
			newCitrix302Resp("/logon/LogonPoint/tmindex.html", nil,
				[]string{"NSC_EPAC=xyz; Path=/"}),
			false, "AAA", "/logon/LogonPoint/tmindex.html"},
		{"NSC_AAAC cookie alone no body no Location",
			"",
			newCitrix302Resp("", nil, []string{"NSC_AAAC=xyz; Path=/; Secure"}),
			false, "unknown", ""},
		{"realistic 302 full Citrix headers all 8 NSC cookies",
			"",
			newCitrix302Resp("/vpn/index.html",
				map[string]string{
					"Strict-Transport-Security": "max-age=157680000",
					"Content-Security-Policy":   "default-src 'self'; frame-src citrixng://* nsgcepa://nsgcepa; report-uri /nscsp_violation/report_uri",
				},
				[]string{
					"NSC_AAAC=xyz; Path=/; Secure",
					"NSC_EPAC=xyz; Path=/",
					"NSC_USER=xyz; Path=/",
					"NSC_TEMP=xyz; Path=/",
					"NSC_PERS=xyz; Path=/",
					"NSC_BASEURL=xyz; Path=/",
					"NSC_TMAA=xyz; Path=/",
					"NSC_TMAS=xyz; Path=/",
				}),
			false, "Gateway", "/vpn/index.html"},
		// --- 302 redirect negative cases (no Class A signal) ---
		{"302 to /admin no NSC_ cookies",
			"",
			newCitrix302Resp("/admin", nil, []string{"session=abc123; Path=/"}),
			true, "", ""},
		{"CSP citrixng only no title no NSC_ cookie",
			"",
			newCitrix302Resp("",
				map[string]string{"Content-Security-Policy": "default-src citrixng://"},
				nil),
			true, "", ""},
	}

	fp := &CitrixNetScalerFingerprinter{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := fp.Fingerprint(tt.resp, []byte(tt.body))
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			assert.Equal(t, "citrix-netscaler", result.Technology)
			assert.Equal(t, "", result.Version)
			assert.Equal(t, tt.wantProd, result.Metadata["product"])
			if tt.wantLoginPath != "" {
				assert.Equal(t, tt.wantLoginPath, result.Metadata["login_path"])
			}
			require.Len(t, result.CPEs, 1)
			assert.Equal(t, "cpe:2.3:a:citrix:netscaler_application_delivery_controller:*:*:*:*:*:*:*:*", result.CPEs[0])
		})
	}
}

// --- TestCitrixNetScalerFingerprinter_CookieValueNeverInMetadata (C3 BLOCKING) ---

func TestCitrixNetScalerFingerprinter_CookieValueNeverInMetadata(t *testing.T) {
	// NSC_AAAC is THE cookie leaked by CitrixBleed CVE-2023-4966.
	// This test exercises the NSC_-alone iron-clad detection path (no title, no Via,
	// no body) and verifies that the session token value never appears in metadata.
	const leakToken = "DO_NOT_LEAK_CITRIXBLEED_SESSION_TOKEN_xyz"
	resp := &http.Response{StatusCode: 302, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/html")
	resp.Header.Add("Set-Cookie", "NSC_AAAC="+leakToken+"; path=/; HttpOnly; Secure")

	fp := &CitrixNetScalerFingerprinter{}
	result, err := fp.Fingerprint(resp, []byte{})
	require.NoError(t, err)
	require.NotNil(t, result, "expected non-nil: NSC_AAAC cookie is iron-clad Class A signal")
	b, _ := json.Marshal(result)
	assert.NotContains(t, string(b), leakToken, "CitrixBleed session token must not appear in FingerprintResult JSON")
	assert.NotContains(t, string(b), "NSC_AAAC", "sensitive cookie name must not appear in FingerprintResult JSON")
}

// --- TestCitrixNetScalerFingerprinter_NoReDoSOn10MBBody (C2 BLOCKING) ---

func TestCitrixNetScalerFingerprinter_NoReDoSOn10MBBody(t *testing.T) {
	body := append([]byte(`<title class="_ctxstxt_NetscalerGateway">`), bytes.Repeat([]byte{'A'}, 10*1024*1024)...)
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/html")
	fp := &CitrixNetScalerFingerprinter{}
	start := time.Now()
	result, err := fp.Fingerprint(resp, body)
	elapsed := time.Since(start)
	require.NoError(t, err)
	assert.Nil(t, result)
	assert.Less(t, elapsed, 100*time.Millisecond, "Fingerprint must complete in <100ms on 10MB body (elapsed: %v)", elapsed)
}

// --- TestSanitizeCitrixNetScalerVersion ---

func TestSanitizeCitrixNetScalerVersion(t *testing.T) {
	tests := []struct{ name, version, want string }{
		{"valid 13.1.49", "13.1.49", "13.1.49"},
		{"valid 14.1.8", "14.1.8", "14.1.8"},
		{"dash suffix rejected", "13.1-49.15", ""},
		{"two-part rejected", "1.2", ""},
		{"alpha rejected", "abc", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { assert.Equal(t, tt.want, sanitizeCitrixNetScalerVersion(tt.version)) })
	}
}

// --- TestBuildCitrixNetScalerCPE ---

func TestBuildCitrixNetScalerCPE(t *testing.T) {
	assert.Equal(t, "cpe:2.3:a:citrix:netscaler_application_delivery_controller:*:*:*:*:*:*:*:*", buildCitrixNetScalerCPE(""))
	assert.Equal(t, "cpe:2.3:a:citrix:netscaler_application_delivery_controller:13.1.49:*:*:*:*:*:*:*", buildCitrixNetScalerCPE("13.1.49"))
}

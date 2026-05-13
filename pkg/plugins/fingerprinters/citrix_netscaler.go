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

// Package fingerprinters provides HTTP fingerprinting for Citrix NetScaler ADC
// and Citrix Gateway. Gate logic (asymmetric by design):
//   - NSC_ cookie prefix alone → DETECTED (iron-clad)
//   - Title alone → REJECTED (require Class B/C corroborator)
//   - Title + (Class B header OR Class C asset) → DETECTED
package fingerprinters

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var (
	// Class A — title with NetScaler CSS class; capture group 1 = "Gateway" or "AAA".
	citrixTitleClassPattern = regexp.MustCompile(
		`(?i)<title[^>]{0,200}class=["']_ctxstxt_Netscaler(Gateway|AAA)["'][^>]{0,200}>[^<]{0,400}</title>`,
	)
	// Class A fallback — plain title text; capture group 1 = full title string.
	citrixTitleTextPattern = regexp.MustCompile(
		`(?i)<title[^>]{0,200}>\s*(Citrix Gateway|NetScaler Gateway|NetScaler AAA)\s*</title>`,
	)
	// Class B — Citrix-specific CSP report-uri directive.
	citrixNscspReportURIPattern = regexp.MustCompile(`(?i)report-uri\s{1,10}/nscsp_violation/report_uri`)
	// Phase 2 prep: version sanitizer patterns (tested, never called from Fingerprint in Phase 1).
	citrixSemverPattern      = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	citrixVersionCharPattern = regexp.MustCompile(`^[0-9.]{1,16}$`)
)

// Byte-literal slices for substring detection (bytes.Contains on []byte is allocation-free).
var (
	citrixngURIScheme             = []byte("citrixng://")
	nsgcepaURIScheme              = []byte("nsgcepa://")
	citrixVPNLoginJSAsset         = []byte("/vpn/login.js")
	citrixVPNRdxJSAsset           = []byte("/vpn/js/rdx.js")
	citrixLogonPointReceiverAsset = []byte("/logon/LogonPoint/receiver/")
)

// CitrixNetScalerFingerprinter detects Citrix NetScaler ADC and Citrix Gateway
// via passive multi-signal HTML and header inspection (C8: no ProbeEndpoint).
type CitrixNetScalerFingerprinter struct{}

func init()                                          { Register(&CitrixNetScalerFingerprinter{}) }
func (f *CitrixNetScalerFingerprinter) Name() string { return "citrix-netscaler" }

// Match accepts HTML, XHTML, or empty Content-Type (C4: case-insensitive).
func (f *CitrixNetScalerFingerprinter) Match(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return ct == "" || strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml+xml")
}

// Fingerprint applies an asymmetric gate:
//   - NSC_ cookie prefix alone → DETECTED (iron-clad; only real NetScalers set these)
//   - Title alone → REJECTED (phishing sites can copy titles; require B or C corroborator)
//   - Title + (Class B header OR Class C asset) → DETECTED
//
// This handles 302 redirect responses (empty body) that carry NSC_* cookies.
func (f *CitrixNetScalerFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp == nil {
		return nil, nil
	}

	// Class A (title): body title — product discriminator.
	// titleMatched is true only when a title match is found.
	var titleMatched bool
	var product string
	if len(body) > 0 {
		if m := citrixTitleClassPattern.FindSubmatch(body); m != nil {
			titleMatched = true
			product = string(m[1]) // "Gateway" or "AAA"
		} else if m := citrixTitleTextPattern.FindSubmatch(body); m != nil {
			titleMatched = true
			if strings.Contains(strings.ToLower(string(m[1])), "gateway") {
				product = "Gateway"
			} else {
				product = "AAA"
			}
		}
	}

	// Class A (NSC_ cookie): iron-clad; C3: name-only, .Value never read.
	// Single pass also collects "pwcount" Class B cookie.
	var nscCookieMatched, pwcountCookieFound bool
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, "NSC_") {
			nscCookieMatched = true
		}
		if c.Name == "pwcount" {
			pwcountCookieFound = true
		}
		if nscCookieMatched && pwcountCookieFound {
			break
		}
	}

	// Gate: require at least one Class A signal.
	if !titleMatched && !nscCookieMatched {
		return nil, nil
	}

	// Class B: headers; iterate all CSP values (RFC-valid servers may send multiple).
	cspMatched := false
	for _, csp := range resp.Header.Values("Content-Security-Policy") {
		cspBytes := []byte(csp)
		if bytes.Contains(cspBytes, citrixngURIScheme) || bytes.Contains(cspBytes, nsgcepaURIScheme) || citrixNscspReportURIPattern.Match(cspBytes) {
			cspMatched = true
			break
		}
	}
	classBMatched := cspMatched ||
		strings.Contains(resp.Header.Get("Via"), "NS-CACHE-") ||
		pwcountCookieFound

	// Class C: body asset paths.
	classCMatched := bytes.Contains(body, citrixVPNLoginJSAsset) ||
		bytes.Contains(body, citrixVPNRdxJSAsset) ||
		bytes.Contains(body, citrixLogonPointReceiverAsset)

	// Asymmetric gate: title alone requires a corroborator; NSC_ alone is sufficient.
	if titleMatched && !nscCookieMatched && !classBMatched && !classCMatched {
		return nil, nil
	}

	// Normalize Location header (extract path from absolute URLs; reject unsafe schemes).
	locPath := normalizeLocationPath(resp.Header.Get("Location"))

	// Derive product from Location when no title (header-only / 302 case).
	if !titleMatched {
		switch {
		case strings.HasPrefix(locPath, "/vpn/"):
			product = "Gateway"
		case strings.HasPrefix(locPath, "/logon/LogonPoint/"):
			product = "AAA"
		default:
			product = "unknown"
		}
	}

	// Derive login_path: body markers take priority; Location header is the fallback.
	var loginPath string
	switch {
	case bytes.Contains(body, []byte("/logon/LogonPoint/tmindex.html")):
		loginPath = "/logon/LogonPoint/tmindex.html"
	case bytes.Contains(body, []byte("/logon/LogonPoint/index.html")):
		loginPath = "/logon/LogonPoint/index.html"
	case bytes.Contains(body, []byte("/vpn/index.html")):
		loginPath = "/vpn/index.html"
	default:
		// Only store locPath when it maps to a known Citrix product prefix.
		if product == "AAA" || product == "Gateway" {
			if locPath != "" {
				loginPath = locPath
			} else if product == "AAA" {
				loginPath = "/logon/LogonPoint/tmindex.html"
			} else {
				loginPath = "/vpn/index.html"
			}
		}
	}

	return &FingerprintResult{
		Technology: "citrix-netscaler",
		Version:    "",
		CPEs:       []string{buildCitrixNetScalerCPE("")},
		Metadata: map[string]any{
			"product":    product,
			"login_path": loginPath,
		},
	}, nil
}

// buildCitrixNetScalerCPE constructs a CPE 2.3 string; empty version → "*".
func buildCitrixNetScalerCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:citrix:netscaler_application_delivery_controller:%s:*:*:*:*:*:*:*", version)
}

// normalizeLocationPath extracts and validates the path from a Location header.
// Absolute URLs have scheme+host stripped; non-http/https schemes (javascript:,
// data:, ftp:) are rejected. Path must start with "/", be ≤200 chars, and
// contain only letters, digits, and safe punctuation (/_-.?=&).
func normalizeLocationPath(loc string) string {
	if loc == "" {
		return ""
	}
	u, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	p := u.Path
	if p == "" || !strings.HasPrefix(p, "/") || len(p) > 200 {
		return ""
	}
	for _, r := range p {
		if !isLocationPathRune(r) {
			return ""
		}
	}
	return p
}

// isLocationPathRune reports whether r is a permitted path character.
func isLocationPathRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
		r == '/' || r == '_' || r == '-' || r == '.' || r == '?' || r == '=' || r == '&'
}

// sanitizeCitrixNetScalerVersion enforces charset + semver (C1, Phase 2 prep).
// Returns "" on any violation; exercised by tests for Phase 2 readiness.
func sanitizeCitrixNetScalerVersion(version string) string {
	if !citrixVersionCharPattern.MatchString(version) || !citrixSemverPattern.MatchString(version) {
		return ""
	}
	return version
}

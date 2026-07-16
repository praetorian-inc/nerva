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
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

const webminMaxBodySize = 1 << 20

// WebminFingerprinter detects Webmin and Usermin instances.
//
// Detection Strategy:
//
// Webmin (and its sibling Usermin) is served by the MiniServ web server, which
// sets a distinctive "MiniServ" Server response header on every response.
// Detection uses two signals:
//
//  1. Standalone: Server response header matches "^MiniServ" (case-insensitive).
//     MiniServ is unique to Webmin/Usermin and is a reliable standalone indicator.
//  2. Corroborated (body-only fallback when the Server header is absent or does
//     not match): body contains a "Login to Webmin" or "Login to Usermin" title
//     AND references "session_login.cgi" — both required together, since the
//     product name alone can appear in unrelated documentation or comparison
//     pages.
//
// Product Differentiation:
// When the MiniServ Server header matches, the body is checked for a login page
// title to distinguish Webmin from Usermin ("Login to Webmin" vs "Login to
// Usermin"). If neither title is present, the technology defaults to "webmin"
// (the far more prevalent of the two products).
//
// Version Detection:
// Extracted from the Server header when present. Webmin/Usermin emit headers
// like "MiniServ/2.104". Validated with `^\d+\.\d+(?:\.\d+)?$`. Empty string if
// not found or invalid.
//
// CPE:
//   - cpe:2.3:a:webmin:webmin:<version>:*:*:*:*:*:*:*
//   - cpe:2.3:a:webmin:usermin:<version>:*:*:*:*:*:*:*
type WebminFingerprinter struct{}

func init() {
	Register(&WebminFingerprinter{})
}

// webminServerPattern matches the MiniServ Server header value, case-insensitively.
// Precompiled to avoid per-call allocation.
var webminServerPattern = regexp.MustCompile(`(?i)^miniserv`)

// webminVersionPattern extracts the version from a Server header value.
// Matches "MiniServ/2.104". Requires end-of-string or whitespace after the
// version to prevent partial matches from garbled strings like "2.104abc"
// (which would otherwise match "2.104").
var webminVersionPattern = regexp.MustCompile(`(?i)miniserv/(\d+\.\d+(?:\.\d+)?)(?:\s|$)`)

// webminVersionValidRegex validates extracted version strings before CPE use.
var webminVersionValidRegex = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)

// webminLoginTitlePattern matches the Webmin/Usermin login page title and
// captures which product it identifies.
var webminLoginTitlePattern = regexp.MustCompile(`(?i)Login\s+to\s+(Webmin|Usermin)`)

func (f *WebminFingerprinter) Name() string {
	return "webmin"
}

// Match rejects 5xx. Accepts any response with a Server header matching
// MiniServ (standalone signal) or text/html content type (for the body-based
// fallback path).
func (f *WebminFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode >= 500 {
		return false
	}

	if webminServerPattern.MatchString(resp.Header.Get("Server")) {
		return true
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs full detection and returns a result if this is a
// Webmin or Usermin instance. Returns nil, nil for non-matching responses.
func (f *WebminFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode >= 500 {
		return nil, nil
	}

	if len(body) > webminMaxBodySize {
		body = body[:webminMaxBodySize]
	}

	serverHeader := resp.Header.Get("Server")
	bodyStr := string(body)

	// Signal 1 (standalone): Server header matches MiniServ.
	if webminServerPattern.MatchString(serverHeader) {
		version := extractWebminVersion(serverHeader)
		product := "webmin"
		if m := webminLoginTitlePattern.FindStringSubmatch(bodyStr); len(m) == 2 {
			product = strings.ToLower(m[1])
		}
		return buildWebminResult(product, version, serverHeader), nil
	}

	// Signal 2 (body-only fallback, no Server header): login title AND
	// session_login.cgi reference, both required together.
	if m := webminLoginTitlePattern.FindStringSubmatch(bodyStr); len(m) == 2 && strings.Contains(bodyStr, "session_login.cgi") {
		product := strings.ToLower(m[1])
		return buildWebminResult(product, "", ""), nil
	}

	return nil, nil
}

// extractWebminVersion extracts a version string from the Server header.
// Returns empty string if no valid version is found.
func extractWebminVersion(serverHeader string) string {
	m := webminVersionPattern.FindStringSubmatch(serverHeader)
	if len(m) < 2 {
		return ""
	}
	v := m[1]
	if !webminVersionValidRegex.MatchString(v) {
		return ""
	}
	return v
}

// buildWebminResult constructs the FingerprintResult for the given product
// ("webmin" or "usermin"), version, and raw Server header (empty if the
// header was not the detection signal).
func buildWebminResult(product, version, serverHeader string) *FingerprintResult {
	displayProduct := "Webmin"
	if product == "usermin" {
		displayProduct = "Usermin"
	}

	metadata := map[string]any{
		"vendor":  "Webmin",
		"product": displayProduct,
	}
	if serverHeader != "" {
		metadata["server_header"] = serverHeader
	}

	return &FingerprintResult{
		Technology: product,
		Version:    version,
		CPEs:       []string{buildWebminCPE(product, version)},
		Metadata:   metadata,
	}
}

// buildWebminCPE builds a CPE 2.3 string for the given product ("webmin" or
// "usermin") and version. Uses "*" when version is empty. Guards against CPE
// metacharacters (":", "*") in the version string.
func buildWebminCPE(product, version string) string {
	v := version
	if v == "" || strings.ContainsAny(v, ":*") {
		v = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:webmin:%s:%s:*:*:*:*:*:*:*", product, v)
}

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

/*
Package fingerprinters provides HTTP fingerprinting for the CivetWeb embedded web server.

# Detection Strategy

CivetWeb is an embedded HTTP/HTTPS server library and a fork of Mongoose, commonly
embedded in medical and industrial devices. Roughly 10K-50K instances are exposed on
the public internet.

In practice, embedded devices rarely expose "Server: CivetWeb/..." directly.
Embedders set Server to their own product name (e.g. "iSYS Embedded Web Server")
and advertise CivetWeb in "X-Powered-By: Civetweb 1.7" using a SPACE separator.
Detection is therefore presence-positive / absence-neutral on EITHER header.

Version casing changed across releases:
  - v1.6-1.9 used "Civetweb/"
  - v1.10+   used "CivetWeb/"

All matching is therefore case-insensitive.

# Detection Method

 1. Check Server header for "civetweb" with word-boundary guards on both sides
    (leading char must not be [a-z]; trailing char must be '/', ' ', ':', or
    end-of-string) — case-insensitive. All occurrences are scanned so that a header
    like "civetwebproxy/1.0 civetweb/1.15" correctly detects the second token.
    This avoids false positives like "mycivetweb/1.0".
 2. Check X-Powered-By header with the same boundary rule. X-Powered-By uses a SPACE
    separator: "Civetweb 1.7" (not a slash). Either header alone is Tier-1 sufficient.
 3. Accept status codes 200-499 (reject 5xx server errors).
 4. Extract version after "civetweb" + separator ('/' or ' '), validate format.
    Reuses the anchored regex ^\d+\.\d+(?:\.\d+)?$ for CPE safety.
 5. Reject CPE-injection patterns (":*:" in the raw header value) on both headers.
 6. Version precedence: prefer the first header (Server, then X-Powered-By) that
    yields a valid (non-empty) version. If neither yields a valid version, use ""
    (wildcard CPE). This means Server version beats X-Powered-By version when both
    are valid, which is conservative: the Server header is the canonical identity
    signal for HTTP servers.
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// CivetWebFingerprinter detects the CivetWeb embedded web server via Server or X-Powered-By header.
type CivetWebFingerprinter struct{}

// civetWebVersionValidateRegex validates an extracted version token for CPE safety.
// CivetWeb publishes MAJOR.MINOR (1.15) and MAJOR.MINOR.PATCH (1.9.1) versions.
var civetWebVersionValidateRegex = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)

func init() {
	Register(&CivetWebFingerprinter{})
}

func (f *CivetWebFingerprinter) Name() string {
	return "civetweb"
}

func (f *CivetWebFingerprinter) Match(resp *http.Response) bool {
	// Reject 5xx server errors and anything below 200 (parallels boa.go:67-69).
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	// Either header carrying a CivetWeb signal is sufficient (Tier-1 standalone).
	return civetWebSignalInHeader(resp.Header.Get("Server")) ||
		civetWebSignalInHeader(resp.Header.Get("X-Powered-By"))
}

func (f *CivetWebFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// 1. Re-apply the status gate (Fingerprint may be called directly in tests).
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	serverHeader := resp.Header.Get("Server")
	xpbHeader := resp.Header.Get("X-Powered-By")

	serverMatch := civetWebSignalInHeader(serverHeader)
	xpbMatch := civetWebSignalInHeader(xpbHeader)

	// 2. At least one header must carry a CivetWeb signal.
	if !serverMatch && !xpbMatch {
		return nil, nil
	}

	// 3. CPE-injection guard: reject any matched header carrying ":*:".
	//    Both headers are attacker-controlled and must be sanitised before use.
	if serverMatch && strings.Contains(serverHeader, ":*:") {
		serverMatch = false
	}
	if xpbMatch && strings.Contains(xpbHeader, ":*:") {
		xpbMatch = false
	}
	if !serverMatch && !xpbMatch {
		return nil, nil
	}

	// 4. Version precedence: try Server first, then X-Powered-By.
	//    Accept the first header that yields a valid (non-empty) version.
	//    If neither yields a valid version, version = "" (wildcard CPE).
	//    Rationale: Server is the canonical HTTP identity header; when it
	//    carries a valid CivetWeb version that version is preferred over any
	//    X-Powered-By value.
	version := ""
	if serverMatch {
		version = extractCivetWebVersionFromHeader(serverHeader)
	}
	if version == "" && xpbMatch {
		version = extractCivetWebVersionFromHeader(xpbHeader)
	}

	// 5. Build metadata. Record raw value(s) of matched header(s) and which
	//    header(s) contributed to the detection.
	metadata := map[string]any{
		"vendor":  "CivetWeb",
		"product": "CivetWeb",
	}
	switch {
	case serverMatch && xpbMatch:
		metadata["server_header"] = serverHeader
		metadata["x_powered_by"] = xpbHeader
		metadata["matched_header"] = "both"
	case serverMatch:
		metadata["server_header"] = serverHeader
		metadata["matched_header"] = "server"
	default:
		metadata["x_powered_by"] = xpbHeader
		metadata["matched_header"] = "x-powered-by"
	}

	// 6. Emit result. Severity left unset (zero value) like boa/mongoose.
	return &FingerprintResult{
		Technology: "civetweb",
		Version:    version,
		CPEs:       []string{buildCivetWebCPE(version)},
		Metadata:   metadata,
	}, nil
}

// scanCivetWebInHeader scans all occurrences of "civetweb" (case-insensitive) in
// headerValue and returns (true, version) for the first occurrence that satisfies
// both the leading and trailing word-boundary rules. Returns (false, "") if no
// valid occurrence is found.
//
// Leading boundary: the character immediately before "civetweb" must be absent
// (start-of-string) or a non-letter. This rejects tokens like "mycivetweb/1.0"
// where 'y' is a letter, preventing false positives.
//
// Trailing boundary: the character immediately after "civetweb" must be '/', ' ',
// ':', or end-of-string. This rejects "civetwebproxy/1.0".
//
// Version extraction: when the trailing separator is '/' or ' ', the version token
// is read up to the next space, '(', ')', ';', ',' or end-of-string. Validating the
// complete token against civetWebVersionValidateRegex prevents "Civetweb/1.15:*:*"
// from yielding "1.15" (the anchored regex is the primary control; the ":*:" guard
// in Fingerprint is belt-and-suspenders defense-in-depth and is intentionally kept).
func scanCivetWebInHeader(headerValue string) (found bool, version string) {
	if headerValue == "" {
		return false, ""
	}
	lower := strings.ToLower(headerValue)
	const marker = "civetweb"
	const markerLen = len(marker)

	searchFrom := 0
	for {
		idx := strings.Index(lower[searchFrom:], marker)
		if idx == -1 {
			return false, ""
		}
		idx += searchFrom // absolute index into lower/headerValue

		// Check leading boundary: char before "civetweb" must not be [a-z].
		if idx > 0 {
			prev := lower[idx-1]
			if prev >= 'a' && prev <= 'z' {
				// Leading letter — not a standalone token; skip to next occurrence.
				searchFrom = idx + markerLen
				continue
			}
		}

		after := idx + markerLen

		// Check trailing boundary.
		if after < len(lower) {
			next := lower[after]
			if next != '/' && next != ' ' && next != ':' {
				// Trailing non-boundary character — not a valid token; skip.
				searchFrom = idx + markerLen
				continue
			}
		}
		// Valid occurrence found. Extract version if a '/' or ' ' separator follows.
		found = true
		if after < len(lower) {
			sep := lower[after]
			if sep == '/' || sep == ' ' {
				versionPart := headerValue[after+1:]
				endIdx := len(versionPart)
				for i, ch := range versionPart {
					if ch == ' ' || ch == '(' || ch == ')' || ch == ';' || ch == ',' {
						endIdx = i
						break
					}
				}
				candidate := versionPart[:endIdx]
				if civetWebVersionValidateRegex.MatchString(candidate) {
					version = candidate
				}
			}
		}
		return found, version
	}
}

// civetWebSignalInHeader reports whether the given header value contains a valid
// CivetWeb token (leading and trailing word-boundary checked across all occurrences).
func civetWebSignalInHeader(headerValue string) bool {
	found, _ := scanCivetWebInHeader(headerValue)
	return found
}

// extractCivetWebVersionFromHeader returns the version string from the first valid
// CivetWeb token in headerValue, or "" if none is found or the version is malformed.
func extractCivetWebVersionFromHeader(headerValue string) string {
	_, version := scanCivetWebInHeader(headerValue)
	return version
}

// buildCivetWebCPE returns the CPE 2.3 string. Empty version => "*" wildcard.
// Vendor/product are the NVD-confirmed civetweb_project:civetweb (NOT civetweb:civetweb).
func buildCivetWebCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:civetweb_project:civetweb:%s:*:*:*:*:*:*:*", version)
}

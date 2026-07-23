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
Package fingerprinters provides HTTP fingerprinting for Oracle Commerce Platform (ATG Web Commerce).

# Detection Strategy

Oracle ATG Web Commerce (now Oracle Commerce Platform) emits an X-ATG-Version response
header on any response. The header value is a base64-encoded string of the form
"ATGPlatform/11.2" or "ATGPlatform/11.3.2", optionally prefixed with "version=".
Secondary corroboration comes from ATG session cookies. ATG_SESSION_ID is a
standalone detection signal (checked in Match); DYN_USER_ID and DYN_USER_CONFIRM
are Dynamo application server cookies collected as supplementary metadata only.
Additional corroboration is drawn from body references to the Dynamo admin path
(/dyn/admin) and Commerce Reference Store (/crs), recorded in metadata when present.

This fingerprinter is passive: it detects the platform from ordinary HTTP responses
without issuing any additional probe requests.

# Version Extraction

  1. Read the X-ATG-Version header value.
  2. Strip the "version=" prefix (case-insensitive) if present.
  3. Base64-standard-decode the remainder.
  4. Apply atgVersionRegex to extract the version number from the decoded string
     (e.g., "ATGPlatform/11.2" → "11.2").

# CPE

cpe:2.3:a:oracle:commerce_platform:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// OracleCommerceFingerprinter detects Oracle Commerce Platform (ATG Web Commerce)
// instances via the X-ATG-Version response header and ATG session cookies.
type OracleCommerceFingerprinter struct{}

// atgVersionRegex matches the ATGPlatform version string embedded in the
// base64-decoded X-ATG-Version header value (e.g., "ATGPlatform/11.2").
var atgVersionRegex = regexp.MustCompile(`ATGPlatform/(\d+(?:\.\d+)+)`)

func init() {
	Register(&OracleCommerceFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *OracleCommerceFingerprinter) Name() string {
	return "oracle_commerce"
}

// Match returns true when the response carries the X-ATG-Version header or an
// ATG_SESSION_ID cookie — both are definitive ATG Commerce signals.
func (f *OracleCommerceFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Primary signal: ATG version header.
	if resp.Header.Get("X-Atg-Version") != "" {
		return true
	}

	// Corroborating signal: ATG session cookie.
	for _, cookie := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(strings.ToLower(cookie), "atg_session_id") {
			return true
		}
	}

	return false
}

// Fingerprint performs full detection, extracts the platform version from the
// base64-encoded X-ATG-Version header, and builds a CPE string.
func (f *OracleCommerceFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// 2 MiB body cap — defense-in-depth above the engine limit.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	rawHeaderValue := resp.Header.Get("X-Atg-Version")

	// Collect ATG cookie names present in the response. DYN_USER_ID and
	// DYN_USER_CONFIRM are Dynamo Application Server cookies collected as
	// supplementary metadata; only ATG_SESSION_ID and the X-ATG-Version
	// header are standalone detection signals (checked in Match).
	var cookiesFound []string
	for _, cookie := range resp.Header.Values("Set-Cookie") {
		cookieLower := strings.ToLower(cookie)
		switch {
		case strings.Contains(cookieLower, "atg_session_id"):
			cookiesFound = append(cookiesFound, "ATG_SESSION_ID")
		case strings.Contains(cookieLower, "dyn_user_id"):
			cookiesFound = append(cookiesFound, "DYN_USER_ID")
		case strings.Contains(cookieLower, "dyn_user_confirm"):
			cookiesFound = append(cookiesFound, "DYN_USER_CONFIRM")
		}
	}

	// Body-level corroborating signals: ATG Dynamo admin and Commerce Reference Store paths.
	bodyStr := string(body)
	var bodySignals []string
	if strings.Contains(bodyStr, "/dyn/admin") {
		bodySignals = append(bodySignals, "/dyn/admin")
	}
	if strings.Contains(bodyStr, "/crs") {
		bodySignals = append(bodySignals, "/crs")
	}

	// Require at least one signal.
	if rawHeaderValue == "" && len(cookiesFound) == 0 {
		return nil, nil
	}

	// Determine detection method.
	detectionMethod := "atg_session_cookie"
	if rawHeaderValue != "" {
		detectionMethod = "atg_version_header"
	}

	metadata := map[string]any{
		"vendor":           "Oracle",
		"product":          "Oracle Commerce Platform",
		"detection_method": detectionMethod,
	}

	var version string
	var decodedString string

	if rawHeaderValue != "" {
		metadata["atg_version_raw"] = rawHeaderValue

		// Strip optional "version=" prefix (case-insensitive).
		encoded := rawHeaderValue
		if strings.HasPrefix(strings.ToLower(encoded), "version=") {
			encoded = encoded[len("version="):]
		}

		// Base64 standard decode.
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err == nil {
			decodedString = string(decoded)
			metadata["atg_version_decoded"] = decodedString

			// Extract version from decoded string (e.g., "ATGPlatform/11.2").
			if matches := atgVersionRegex.FindStringSubmatch(decodedString); len(matches) > 1 {
				version = matches[1]
				metadata["version_note"] = "extracted from X-ATG-Version header (base64)"
			}
		}
	}

	// Guard against CPE metacharacters.
	if strings.ContainsAny(version, ":*?") {
		version = ""
	}

	if len(cookiesFound) > 0 {
		metadata["cookies_found"] = cookiesFound
	}

	if len(bodySignals) > 0 {
		metadata["corroborating_paths"] = bodySignals
	}

	return &FingerprintResult{
		Technology: "oracle_commerce",
		Version:    version,
		CPEs:       []string{buildCommerceCPE(version)},
		Metadata:   metadata,
	}, nil
}

// buildCommerceCPE constructs a CPE 2.3 string for Oracle Commerce Platform.
// When version is empty or contains CPE metacharacters, a wildcard is used to
// support asset inventory even when the version cannot be extracted.
func buildCommerceCPE(version string) string {
	if version == "" || strings.ContainsAny(version, ":*?") {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:oracle:commerce_platform:%s:*:*:*:*:*:*:*", version)
}

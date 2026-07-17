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
Package fingerprinters provides HTTP fingerprinting for phpMyAdmin.

# What We Detect

phpMyAdmin instances exposed at common installation paths. Four fingerprinters
probe distinct endpoints and share detection logic:

  - PhpMyAdminFingerprinter: probes /phpmyadmin/, the default install path.
  - PhpMyAdminPMAFingerprinter: probes /pma/, a common shorthand alias.
  - PhpMyAdminCasedFingerprinter: probes /phpMyAdmin/, a cased alias seen on
    case-sensitive filesystems.
  - PhpMyAdminSetupFingerprinter: probes /phpmyadmin/setup/, the (often
    unauthenticated) first-run configuration page. This page has a distinct
    title ("phpMyAdmin setup") but does not expose a version number itself;
    version extraction still succeeds via the shared static asset URL when
    present.

# What We Do NOT Detect

  - phpMyAdmin instances that have been moved to a non-standard path
  - phpMyAdmin behind a reverse proxy that alters the response content type

# Detection Strategy

Two independent signals, either of which is sufficient for detection:

  - Signal 1 (standalone): the page title is "phpMyAdmin" or "phpMyAdmin
    setup" (<title>phpMyAdmin</title> / <title>phpMyAdmin setup</title>,
    case-insensitive, tolerant of whitespace and attributes).
  - Signal 2 (corroborated pair): both a "phpMyAdmin=" Set-Cookie header AND
    a `name="pma_username"` login form field are present. Neither alone is
    specific enough to avoid false positives, so both must corroborate.

# Version Extraction

Version is extracted from the static asset cache-busting query parameter
shared across phpmyadmin.css.php, get_scripts.js.php, and messages.php:
"phpmyadmin.css.php?nocache=abc&v=5.2.1". The setup page never displays a
version number directly, but often still links the shared CSS asset, so
version extraction can still succeed there.

Extracted versions are validated against a strict `MAJOR.MINOR[.PATCH]`
pattern and rejected if they contain CPE metacharacters (`:`, `*`, `?`).

# CPE Format

cpe:2.3:a:phpmyadmin:phpmyadmin:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Package-level precompiled regexes.
var (
	// phpMyAdminTitleRegex matches <title>phpMyAdmin</title> or
	// <title>phpMyAdmin setup</title>, case-insensitive, tolerant of title
	// attributes and surrounding whitespace.
	phpMyAdminTitleRegex = regexp.MustCompile(`(?i)<title[^>]*>\s*phpMyAdmin(?:\s+setup)?\s*</title>`)

	// phpMyAdminAssetVersionRegex extracts the version from the cache-busting
	// v= query parameter shared by phpmyadmin.css.php, get_scripts.js.php, and
	// messages.php asset URLs. The v= parameter must directly follow "?" or a
	// parameter separator ("&", or its HTML-entity-encoded form "&amp;") so
	// it isn't confused with an unrelated parameter like "rev=" (which would
	// otherwise match the "v=" substring embedded inside "rev="). It must
	// also be followed by "&", a quote, whitespace, or end-of-string, so a
	// trailing non-digit/dot suffix like "5.38abc" is rejected rather than
	// silently truncated to "5.38".
	phpMyAdminAssetVersionRegex = regexp.MustCompile(`(?:phpmyadmin\.css\.php|get_scripts\.js\.php|messages\.php)\?(?:[^"'\s]*&(?:amp;)?)?v=(\d+\.\d+(?:\.\d+)?)(?:[&"'\s]|$)`)

	// phpMyAdminVersionRegex validates that an extracted version is safe to
	// embed in a CPE. Accepts: "5.2", "5.2.1".
	phpMyAdminVersionRegex = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)
)

// PhpMyAdminFingerprinter detects phpMyAdmin at the default /phpmyadmin/ path.
type PhpMyAdminFingerprinter struct{}

// PhpMyAdminPMAFingerprinter detects phpMyAdmin at the /pma/ shorthand alias.
type PhpMyAdminPMAFingerprinter struct{}

// PhpMyAdminCasedFingerprinter detects phpMyAdmin at the /phpMyAdmin/ cased alias.
type PhpMyAdminCasedFingerprinter struct{}

// PhpMyAdminSetupFingerprinter detects phpMyAdmin at the /phpmyadmin/setup/
// first-run configuration page.
type PhpMyAdminSetupFingerprinter struct{}

func init() {
	Register(&PhpMyAdminFingerprinter{})
	Register(&PhpMyAdminPMAFingerprinter{})
	Register(&PhpMyAdminCasedFingerprinter{})
	Register(&PhpMyAdminSetupFingerprinter{})
}

// --- PhpMyAdminFingerprinter ---

func (f *PhpMyAdminFingerprinter) Name() string { return "phpmyadmin" }

func (f *PhpMyAdminFingerprinter) ProbeEndpoint() string { return "/phpmyadmin/" }

func (f *PhpMyAdminFingerprinter) ProbeAccept() string { return "text/html" }

func (f *PhpMyAdminFingerprinter) Match(resp *http.Response) bool {
	return matchPhpMyAdmin(resp)
}

func (f *PhpMyAdminFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	return fingerprintPhpMyAdmin(resp, body)
}

// --- PhpMyAdminPMAFingerprinter ---

func (f *PhpMyAdminPMAFingerprinter) Name() string { return "phpmyadmin-pma" }

func (f *PhpMyAdminPMAFingerprinter) ProbeEndpoint() string { return "/pma/" }

func (f *PhpMyAdminPMAFingerprinter) ProbeAccept() string { return "text/html" }

func (f *PhpMyAdminPMAFingerprinter) Match(resp *http.Response) bool {
	return matchPhpMyAdmin(resp)
}

func (f *PhpMyAdminPMAFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	return fingerprintPhpMyAdmin(resp, body)
}

// --- PhpMyAdminCasedFingerprinter ---

func (f *PhpMyAdminCasedFingerprinter) Name() string { return "phpmyadmin-cased" }

func (f *PhpMyAdminCasedFingerprinter) ProbeEndpoint() string { return "/phpMyAdmin/" }

func (f *PhpMyAdminCasedFingerprinter) ProbeAccept() string { return "text/html" }

func (f *PhpMyAdminCasedFingerprinter) Match(resp *http.Response) bool {
	return matchPhpMyAdmin(resp)
}

func (f *PhpMyAdminCasedFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	return fingerprintPhpMyAdmin(resp, body)
}

// --- PhpMyAdminSetupFingerprinter ---

func (f *PhpMyAdminSetupFingerprinter) Name() string { return "phpmyadmin-setup" }

func (f *PhpMyAdminSetupFingerprinter) ProbeEndpoint() string { return "/phpmyadmin/setup/" }

func (f *PhpMyAdminSetupFingerprinter) ProbeAccept() string { return "text/html" }

func (f *PhpMyAdminSetupFingerprinter) Match(resp *http.Response) bool {
	return matchPhpMyAdmin(resp)
}

func (f *PhpMyAdminSetupFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	return fingerprintPhpMyAdmin(resp, body)
}

// --- Shared detection logic ---

// matchPhpMyAdmin is the shared pre-filter for all four phpMyAdmin
// fingerprinters: any non-error-range HTML response is worth inspecting,
// since phpMyAdmin returns 200-499 across various auth/redirect states.
func matchPhpMyAdmin(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode > 499 {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// fingerprintPhpMyAdmin performs full phpMyAdmin detection shared by all four
// fingerprinters.
func fingerprintPhpMyAdmin(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// 1 MiB body cap — defense-in-depth above the engine limit.
	if len(body) > 1*1024*1024 {
		return nil, nil
	}

	bodyStr := string(body)

	// Signal 1 (standalone): the page title is "phpMyAdmin" or "phpMyAdmin setup".
	hasTitle := phpMyAdminTitleRegex.MatchString(bodyStr)

	// Signal 2 (corroborated pair): both the phpMyAdmin session cookie and
	// the login form's username field must be present together. Neither
	// alone is specific enough to avoid false positives.
	hasCookie := false
	for _, cookie := range resp.Header["Set-Cookie"] {
		if strings.Contains(cookie, "phpMyAdmin=") {
			hasCookie = true
			break
		}
	}
	hasCookiePair := hasCookie && strings.Contains(bodyStr, `name="pma_username"`)

	if !hasTitle && !hasCookiePair {
		return nil, nil
	}

	detectionMethod := "cookie_form"
	if hasTitle {
		detectionMethod = "title"
	}

	version, versionSource := extractPhpMyAdminVersion(bodyStr)

	metadata := map[string]any{
		"vendor":           "phpMyAdmin",
		"product":          "phpMyAdmin",
		"detection_method": detectionMethod,
	}
	if versionSource != "" {
		metadata["version_source"] = versionSource
	}

	return &FingerprintResult{
		Technology: "phpmyadmin",
		Version:    version,
		CPEs:       []string{buildPhpMyAdminCPE(version)},
		Metadata:   metadata,
	}, nil
}

// extractPhpMyAdminVersion extracts and validates a version string from the
// response body via the static asset cache-busting v= parameter. Returns an
// empty version and source if no valid version is found.
func extractPhpMyAdminVersion(bodyStr string) (version, source string) {
	if m := phpMyAdminAssetVersionRegex.FindStringSubmatch(bodyStr); len(m) >= 2 {
		version, source = m[1], "asset_url"
	}

	if version == "" {
		return "", ""
	}

	// Validate format, then guard against CPE metacharacters (belt-and-suspenders).
	if !phpMyAdminVersionRegex.MatchString(version) || strings.ContainsAny(version, ":*?") {
		return "", ""
	}

	return version, source
}

// buildPhpMyAdminCPE constructs a CPE 2.3 string for phpMyAdmin.
// When version is empty, a wildcard CPE is emitted to support asset inventory.
func buildPhpMyAdminCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:phpmyadmin:phpmyadmin:%s:*:*:*:*:*:*:*", version)
}

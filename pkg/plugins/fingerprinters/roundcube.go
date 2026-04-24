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

// Package fingerprinters provides HTTP fingerprinting for Roundcube Webmail.
// RoundcubeFingerprinter inspects the HTML body for Roundcube-specific markers
// (title, session cookie, login form, skin path, rcversion JS). Version is
// decoded from rcversion = major*10000 + minor*100 + patch.
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

var (
	roundcubeTitlePattern       = regexp.MustCompile(`(?i)<title[^>]{0,200}>[^<]{0,200}roundcube\s*webmail[^<]{0,200}</title>`)
	roundcubeCookiePattern      = regexp.MustCompile(`(?i)^roundcube_sessid$`)
	roundcubeLoginFormPattern   = regexp.MustCompile(`id=["']rcmloginuser["']`)
	roundcubeVersionPattern     = regexp.MustCompile(`"rcversion"\s*:\s*(\d{1,8})`)
	roundcubeSkinPattern        = regexp.MustCompile(`\bskins/(elastic|larry)/`)
	roundcubeSemverPattern      = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	roundcubeVersionCharPattern = regexp.MustCompile(`^[0-9.]{1,16}$`)
)

// RoundcubeFingerprinter detects Roundcube Webmail via passive HTML inspection.
type RoundcubeFingerprinter struct{}

func init() { Register(&RoundcubeFingerprinter{}) }

// --- RoundcubeFingerprinter ---

func (f *RoundcubeFingerprinter) Name() string { return "roundcube" }

func (f *RoundcubeFingerprinter) Match(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "application/xhtml+xml") ||
		ct == ""
}

func (f *RoundcubeFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp == nil || len(body) == 0 {
		return nil, nil
	}

	// Collect all five signals; emit only when ≥ 2 match (architecture.md §3).
	signalCount := 0

	if roundcubeTitlePattern.Match(body) {
		signalCount++
	}

	// Signal 2: inspect only the cookie Name as a boolean signal (C3).
	cookieMatched := false
	for _, c := range resp.Cookies() {
		if roundcubeCookiePattern.MatchString(c.Name) {
			cookieMatched = true
			break
		}
	}
	if cookieMatched {
		signalCount++
	}

	if roundcubeLoginFormPattern.Match(body) {
		signalCount++
	}

	skinMatch := roundcubeSkinPattern.FindSubmatch(body)
	if len(skinMatch) >= 2 {
		signalCount++
	}

	rcvMatch := roundcubeVersionPattern.FindSubmatch(body)
	if len(rcvMatch) >= 2 {
		signalCount++
	}

	if signalCount < 2 {
		return nil, nil
	}

	version := ""
	if len(rcvMatch) >= 2 {
		version = sanitizeRoundcubeVersion(decodeRoundcubeVersion(string(rcvMatch[1])))
	}

	skin := "unknown"
	if len(skinMatch) >= 2 {
		skin = string(skinMatch[1])
	}

	return &FingerprintResult{
		Technology: "roundcube",
		Version:    version,
		CPEs:       []string{buildRoundcubeCPE(version)},
		Metadata: map[string]any{
			"skin":       skin,
			"login_path": "/?_task=login",
		},
	}, nil
}

// decodeRoundcubeVersion decodes rcversion = major*10000+minor*100+patch into
// "M.m.p". Returns "" for values < 1000 (pre-1.0) or parse errors.
func decodeRoundcubeVersion(raw string) string {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1000 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", n/10000, (n/100)%100, n%100)
}

// sanitizeRoundcubeVersion enforces charset allowlist and semver structure
// before CPE interpolation (C1). Returns "" on any violation.
func sanitizeRoundcubeVersion(version string) string {
	if len(version) > 16 || !roundcubeVersionCharPattern.MatchString(version) {
		return ""
	}
	if !roundcubeSemverPattern.MatchString(version) {
		return ""
	}
	return version
}

// buildRoundcubeCPE returns the CPE 2.3 string for Roundcube Webmail (C9).
func buildRoundcubeCPE(version string) string {
	v := version
	if v == "" {
		v = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:roundcube:webmail:%s:*:*:*:*:*:*:*", v)
}

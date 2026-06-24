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
Package fingerprinters provides HTTP fingerprinting for Rancher (SUSE Rancher),
the open-source multi-cluster Kubernetes management platform.

# What We Detect

  - Rancher management server version via the unauthenticated GET /rancherversion
    JSON endpoint (Rancher 2.7.0+) — exact version + Rancher Prime flag.
  - Rancher dashboard (the Vue single-page web UI) via GET /dashboard/ — presence
    detection that works across versions and survives /rancherversion being blocked.

# What We Do NOT Detect

  - Rancher 2.5/2.6 exact version: /rancherversion does not exist before 2.7.0 and
    /v3/settings/server-version is authentication-gated. Such hosts are still
    detected (presence) via the dashboard probe when the Vue UI is reachable.
  - Number of managed clusters: /v3/clusters is authentication-gated and cannot be
    read by a passive, unauthenticated fingerprinter.
  - Rancher Desktop (cpe:2.3:a:suse:rancher_desktop) — a separate NVD product (the
    local developer application). This fingerprinter never emits that CPE.
  - Bare Kubernetes API servers, k3s, RKE/RKE2 (no Rancher dashboard or /rancherversion).
  - Installs that replace the dashboard with a fully custom static build (the
    ui-dashboard-index setting) that strips the title/structural markers — a rare,
    deliberate configuration outside the exposed-server detection threat model.

# Security Context

Rancher manages multiple downstream Kubernetes clusters with elevated privileges, so
an exposed Rancher server is a high-value, supply-chain-style target (a compromise can
propagate across every managed cluster). Notable CVEs include CVE-2021-36782 (CVSS 9.9,
cleartext credential storage). Rancher's own hardening guidance recommends L7-blocking
/rancherversion, so the dashboard probe provides a fallback presence signal.

# Active Probe Safety

Both probes are plain, unauthenticated GET requests issued by the engine with no
request body: GET /rancherversion (read-only version JSON) and GET /dashboard/
(the static SPA shell). No write operations and no authentication attempts are made.

# CPE

cpe:2.3:a:suse:rancher:{version}:*:*:*:*:*:*:*  (vendor "suse", NVD-verified)
*/
package fingerprinters

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// ── Version-endpoint markers (GET /rancherversion) ─────────────────────────────

// rancherVersionFieldMarker and rancherPrimeMarker are the two JSON keys that
// together uniquely identify a Rancher /rancherversion response. RancherPrime is
// Rancher-specific, so requiring it alongside Version avoids matching the many
// generic {"Version":"..."} JSON documents served by unrelated software.
const (
	rancherVersionFieldMarker = `"Version"`
	rancherPrimeMarker        = `"RancherPrime"`
)

// rancherVersionExtractRegex captures the semantic version from the /rancherversion
// JSON "Version" field. Rancher tags are v-prefixed (e.g. "v2.8.5", "v2.8.0-rc1");
// the leading v is optional here and stripped during validation.
var rancherVersionExtractRegex = regexp.MustCompile(`"Version"\s*:\s*"v?([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.\-]+)?)"`)

// rancherVersionValidateRegex is the anchored second-stage validator applied before
// a version is emitted into a CPE.
var rancherVersionValidateRegex = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.\-]+)?$`)

// rancherPrimeExtractRegex captures the RancherPrime flag ("true"/"false" string).
var rancherPrimeExtractRegex = regexp.MustCompile(`"RancherPrime"\s*:\s*"(true|false)"`)

// rancherGitCommitExtractRegex captures the GitCommit hash for metadata enrichment.
var rancherGitCommitExtractRegex = regexp.MustCompile(`"GitCommit"\s*:\s*"([0-9a-f]{7,40})"`)

// ── Dashboard markers (GET /dashboard/) ────────────────────────────────────────

// rancherDashboardTitleRegex matches the Vue dashboard title tag: <title>Rancher</title>.
// The shipped index.html ships this title statically, so runtime white-labeling (which
// rewrites document.title via JS) does not change what this fingerprinter sees on the wire.
var rancherDashboardTitleRegex = regexp.MustCompile(`(?i)<title[^>]*>\s*rancher\s*</title>`)

// Structural markers verified present in the shipped rancher/dashboard index.html across
// releases 2.7–2.11/master. Each is matched as a raw substring, so none is used on its own;
// they only corroborate the <title>Rancher</title> tag (see Fingerprint).
const (
	rancherLoadSpinnerMarker       = `initial-load-spinner` // SPA boot spinner container/class
	rancherColorSchemeCookieMarker = `R_PCS`                // inline bootstrap script reads the R_PCS preferred-color-scheme cookie
	rancherThemeCookieMarker       = `R_THEME`              // ...and the R_THEME theme cookie
)

const rancherCPEVendorProduct = "cpe:2.3:a:suse:rancher"

func init() {
	Register(&RancherFingerprinter{})
	Register(&RancherDashboardFingerprinter{})
}

// ── FP1: RancherFingerprinter (version, /rancherversion) ───────────────────────

// RancherFingerprinter detects Rancher and extracts its exact version from the
// unauthenticated /rancherversion JSON endpoint (Rancher 2.7.0+).
type RancherFingerprinter struct{}

// Name returns the fingerprinter identifier.
func (f *RancherFingerprinter) Name() string { return "rancher" }

// ProbeEndpoint returns the unauthenticated Rancher version endpoint. A plain GET
// returns the JSON body {"Version":"v2.x.y","GitCommit":"...","RancherPrime":"true|false"}.
// Note: the handler does not set Content-Type, so the body is served as sniffed
// text/plain — Match therefore keys on the request path, not the response Content-Type.
func (f *RancherFingerprinter) ProbeEndpoint() string { return "/rancherversion" }

// ProbeAccept sets the request Accept header for the version probe. (The server ignores
// it and returns a sniffed text/plain JSON body regardless.)
func (f *RancherFingerprinter) ProbeAccept() string { return "application/json" }

// Match is a lenient pre-filter: any 2xx–4xx response from the /rancherversion probe path
// (the active-probe case) or any JSON response is a candidate. Definitive confirmation is
// in Fingerprint.
func (f *RancherFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	if resp.Request != nil && resp.Request.URL != nil &&
		strings.HasSuffix(strings.ToLower(resp.Request.URL.Path), "/rancherversion") {
		return true
	}
	return strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "application/json")
}

// Fingerprint confirms a Rancher /rancherversion response and extracts the version.
//
// Definitive signal: the body contains both the "RancherPrime" and "Version" JSON
// keys. RancherPrime is Rancher-specific, so this will not fire on the many generic
// {"Version":"..."} documents served by unrelated software.
func (f *RancherFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}
	// Defense-in-depth body cap (the version JSON is tiny); below the engine's 10MB limit.
	if len(body) > 512*1024 {
		return nil, nil
	}

	if !bytes.Contains(body, []byte(rancherPrimeMarker)) || !bytes.Contains(body, []byte(rancherVersionFieldMarker)) {
		return nil, nil
	}

	version := extractRancherVersion(body)

	metadata := map[string]any{
		"vendor":           "SUSE",
		"product":          "Rancher",
		"detection_method": "rancherversion_api",
	}
	if version != "" {
		metadata["version"] = version
	}
	if m := rancherPrimeExtractRegex.FindSubmatch(body); len(m) >= 2 {
		metadata["rancher_prime"] = string(m[1]) == "true"
	}
	if m := rancherGitCommitExtractRegex.FindSubmatch(body); len(m) >= 2 {
		metadata["git_commit"] = string(m[1])
	}

	return &FingerprintResult{
		Technology: "rancher",
		Version:    version,
		CPEs:       []string{buildRancherCPE(version)},
		Metadata:   metadata,
	}, nil
}

// ── FP2: RancherDashboardFingerprinter (presence, /dashboard/) ─────────────────

// RancherDashboardFingerprinter detects the Rancher Vue dashboard (web UI) via a
// GET to /dashboard/. It provides presence detection (markers verified across releases
// 2.7–2.11/master) that does not depend on /rancherversion being reachable. It does not
// extract a version (the Vue SPA ships content-hashed bundles with no embedded semver).
type RancherDashboardFingerprinter struct{}

// Name returns the fingerprinter identifier.
func (f *RancherDashboardFingerprinter) Name() string { return "rancher_dashboard" }

// ProbeEndpoint returns the dashboard SPA path. The trailing slash is required: a GET
// to /dashboard returns a 302 to /dashboard/, and the engine does not follow redirects.
func (f *RancherDashboardFingerprinter) ProbeEndpoint() string { return "/dashboard/" }

// ProbeAccept requests HTML for the dashboard shell.
func (f *RancherDashboardFingerprinter) ProbeAccept() string { return "text/html" }

// Match is a lenient pre-filter: a 2xx–4xx response with an HTML (or unset)
// Content-Type is a candidate.
func (f *RancherDashboardFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return ct == "" || strings.Contains(ct, "text/html")
}

// Fingerprint confirms the Rancher dashboard SPA shell.
//
// Definitive signal: a <title>Rancher</title> tag corroborated by a Rancher-specific
// structural marker (initial-load-spinner, or the R_PCS/R_THEME cookie references in the
// inline bootstrap script). Never the title alone (too generic) and never a bare
// structural substring alone (only meaningful alongside the title).
func (f *RancherDashboardFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}
	// Defense-in-depth body cap (the SPA shell is ~13 KiB); below the engine's 10MB limit.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	hasTitle := rancherDashboardTitleRegex.Match(body)
	hasStructural := bytes.Contains(body, []byte(rancherLoadSpinnerMarker)) ||
		bytes.Contains(body, []byte(rancherColorSchemeCookieMarker)) ||
		bytes.Contains(body, []byte(rancherThemeCookieMarker))

	if !hasTitle || !hasStructural {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor":           "SUSE",
		"product":          "Rancher",
		"detection_method": "dashboard_spa",
		"ui_framework":     "vue",
	}

	return &FingerprintResult{
		Technology: "rancher_dashboard",
		Version:    "",
		CPEs:       []string{buildRancherCPE("")},
		Metadata:   metadata,
	}, nil
}

// ── Helpers ────────────────────────────────────────────────────────────────────

// extractRancherVersion pulls the version from the /rancherversion "Version" field,
// stripping the leading v and applying anchored two-stage validation. Returns "" when
// no valid version is present (e.g. an unbuilt "dev" server).
func extractRancherVersion(body []byte) string {
	m := rancherVersionExtractRegex.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	v := string(m[1])
	// Belt-and-suspenders: the validator and the metacharacter check are unreachable by
	// construction (the extract capture class only yields [0-9A-Za-z.-]), but they guard
	// against any future regex change letting CPE metacharacters into the version field.
	if !rancherVersionValidateRegex.MatchString(v) {
		return ""
	}
	if strings.ContainsAny(v, ":*") {
		return ""
	}
	return v
}

// buildRancherCPE constructs the NVD-verified Rancher CPE. A wildcard version is emitted
// when the version is unknown. A prerelease suffix (e.g. "2.8.0-rc1") is reduced to the
// core version in the CPE version field: NVD encodes prereleases in the separate update
// field, and a wildcard update matches both the final and rc CPEs during CVE correlation.
func buildRancherCPE(version string) string {
	v := version
	switch {
	case v == "":
		v = "*"
	default:
		if i := strings.IndexByte(v, '-'); i >= 0 {
			v = v[:i]
		}
	}
	return fmt.Sprintf("%s:%s:*:*:*:*:*:*:*", rancherCPEVendorProduct, v)
}

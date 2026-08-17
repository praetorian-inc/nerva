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
Package fingerprinters provides HTTP fingerprinting for Kibana.

# What We Detect

  - Kibana instances via the /api/status JSON endpoint (unauthenticated access)
  - Kibana login page and web UI (structural HTML markers)
  - Kibana presence via kbn-name, kbn-version, kbn-xsrf response headers

# What We Do NOT Detect

  - Kibana instances behind reverse proxies that strip all kbn-* headers and
    identifying page content
  - Kibana with a fully customized login page that removes all Elastic/Kibana
    branding and the kbn-injected-metadata tag

# Security Context

Kibana is the visualisation front-end for the Elastic Stack. Unauthenticated
access to /api/status exposes the Kibana version, build hash, connected
Elasticsearch cluster UUID, and overall health state. This information is
directly useful to an attacker scoping the target environment and selecting
exploits (CVE-2019-7609, CVE-2023-31414, CVE-2024-37288, and others).

Many Kibana deployments, especially internal analytics environments, do not
enable authentication. When /api/status returns full JSON without authentication
the finding is elevated to SeverityHigh.

# Active Probe Safety

The active probe issues a plain GET /api/status with Accept: application/json
and no request body. This is a read-only informational endpoint; no write
operations are performed.

# CPE

cpe:2.3:a:elastic:kibana:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// KibanaFingerprinter detects Kibana instances via the status API, login page,
// and kbn-* response headers.
type KibanaFingerprinter struct{}

// kibanaStatusResponse represents the JSON structure returned by GET /api/status.
type kibanaStatusResponse struct {
	Name    string             `json:"name"`
	UUID    string             `json:"uuid"`
	Version kibanaVersionBlock `json:"version"`
	Status  kibanaStatusBlock  `json:"status"`
}

// kibanaVersionBlock is the nested version object within the status response.
type kibanaVersionBlock struct {
	Number      string `json:"number"`
	BuildHash   string `json:"build_hash"`
	BuildNumber int    `json:"build_number"`
	BuildSnapshot bool `json:"build_snapshot"`
}

// kibanaStatusBlock is the nested status object within the status response.
type kibanaStatusBlock struct {
	Overall kibanaOverallState `json:"overall"`
}

// kibanaOverallState is the overall state object within the status block.
// Kibana ≤7.x uses "state"; Kibana 8.x uses "level".
type kibanaOverallState struct {
	State string `json:"state"`
	Level string `json:"level"`
}

// kibanaTitleRegex matches the Kibana login/app page title tag.
// Structural match — the <title> tag is a definitive page identity marker.
// Examples: "<title>Kibana</title>", "<title>Kibana - Dashboard</title>"
var kibanaTitleRegex = regexp.MustCompile(`(?i)<title[^>]*>[^<]*kibana[^<]*</title>`)

// kibanaInjectedMetaRegex matches the <kbn-injected-metadata> element that
// Kibana injects into every page it serves. This is a structural HTML marker
// unique to Kibana — it does not appear on any non-Kibana page.
var kibanaInjectedMetaRegex = regexp.MustCompile(`(?i)<kbn-injected-metadata`)

// kibanaVersionValidateRegex is the anchored second-stage validation gate.
// Accepts dotted digit versions with 2–4 components: "8.12.0", "7.17.3.1".
var kibanaVersionValidateRegex = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,3}$`)

func init() {
	Register(&KibanaFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *KibanaFingerprinter) Name() string {
	return "kibana"
}

// ProbeEndpoint returns the Kibana status API path.
// GET /api/status returns version, build, cluster, and health information
// without authentication on many deployments.
func (f *KibanaFingerprinter) ProbeEndpoint() string {
	return "/api/status"
}

// ProbeAccept returns the Accept header for the active probe.
func (f *KibanaFingerprinter) ProbeAccept() string {
	return "application/json"
}

// Match returns true when the response is a candidate for Kibana detection.
//
// Fast path: any kbn-* header present in the response is a definitive signal.
//
// Body-scan candidates: text/html (login page / web UI) and application/json
// (status API). Other content types are not worth scanning.
//
// 5xx responses are rejected (except 503, which Kibana returns during startup
// while Elasticsearch is not yet ready — kbn-* headers are still present).
// Responses below 200 (informational) are also rejected.
func (f *KibanaFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || (resp.StatusCode >= 500 && resp.StatusCode != 503) {
		return false
	}

	// Fast path: kbn-* headers are unique to Kibana.
	if resp.Header.Get("kbn-name") != "" ||
		resp.Header.Get("kbn-version") != "" ||
		resp.Header.Get("kbn-xsrf") != "" {
		return true
	}

	// Body-scan candidates: text/html (login page) or application/json (status API).
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "application/json") {
		return true
	}

	return false
}

// Fingerprint performs full detection and extracts technology information.
//
// Detection signals (in priority order):
//  1. /api/status JSON with version.number → "api_status" or "active_probe"
//  2. Login page HTML with <kbn-injected-metadata> or Kibana/Elastic title → "web_ui"
//  3. kbn-* headers only (no body signal) → "response_header"
//
// When the status API returns full JSON with a version the request was made
// without authentication (anonymous_access=true), reported as SeverityHigh.
// When only the login page is detected, authentication_enabled=true is set.
func (f *KibanaFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || (resp.StatusCode >= 500 && resp.StatusCode != 503) {
		return nil, nil
	}

	// Gate 2: 2 MiB body cap — defense-in-depth above the engine limit.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// --- Signal detection ---

	// PRIMARY: kbn-* headers.
	kbnName := resp.Header.Get("kbn-name")
	kbnVersion := resp.Header.Get("kbn-version")
	hasKbnHeaders := kbnName != "" || kbnVersion != "" || resp.Header.Get("kbn-xsrf") != ""

	// Determine if this response came from the active probe (/api/status).
	isActiveProbe := false
	if resp.Request != nil && resp.Request.URL != nil {
		if strings.EqualFold(resp.Request.URL.Path, "/api/status") {
			isActiveProbe = true
		}
	}

	// Try JSON parsing for /api/status detection.
	var statusResp kibanaStatusResponse
	hasAPISignal := false
	if err := json.Unmarshal(body, &statusResp); err == nil {
		// Require version.number AND at least one Kibana-specific field (name, uuid,
		// or build_hash) to avoid matching arbitrary JSON with a version.number key.
		// Also require status.overall (state or level) to distinguish from OpenSearch,
		// whose root response has name+version but never a status block.
		hasStatusBlock := statusResp.Status.Overall.State != "" || statusResp.Status.Overall.Level != ""
		if statusResp.Version.Number != "" && hasStatusBlock &&
			(statusResp.Name != "" || statusResp.UUID != "" || statusResp.Version.BuildHash != "") {
			hasAPISignal = true
		}
	}

	// SECONDARY: HTML structural markers — <kbn-injected-metadata> or title.
	hasWebUISignal := kibanaInjectedMetaRegex.Match(body) || kibanaTitleRegex.Match(body)

	// At least one definitive signal must fire.
	if !hasAPISignal && !hasWebUISignal && !hasKbnHeaders {
		return nil, nil
	}

	// --- Version extraction ---

	version := ""

	// Priority 1: status JSON version.number (most authoritative).
	if hasAPISignal {
		v := statusResp.Version.Number
		if strings.ContainsAny(v, ":*") {
			v = ""
		} else if kibanaVersionValidateRegex.MatchString(v) {
			version = v
		}
	}

	// Priority 2: kbn-version header (when API parsing did not yield a version).
	if version == "" && kbnVersion != "" {
		v := sanitizeHTTPHeaderValue(kbnVersion)
		if !strings.ContainsAny(v, ":*") && kibanaVersionValidateRegex.MatchString(v) {
			version = v
		}
	}

	// CPE injection defense — belt-and-suspenders guard.
	if strings.ContainsAny(version, ":*") {
		version = ""
	}

	// --- Detection method ---

	var detectionMethod string
	switch {
	case hasAPISignal && isActiveProbe:
		detectionMethod = "active_probe"
	case hasAPISignal:
		detectionMethod = "api_status"
	case hasWebUISignal:
		detectionMethod = "web_ui"
	default:
		detectionMethod = "response_header"
	}

	// --- Metadata ---

	metadata := map[string]any{
		"vendor":           "Elastic",
		"product":          "Kibana",
		"detection_method": detectionMethod,
	}

	if hasAPISignal {
		// Anonymous access to /api/status means no authentication.
		metadata["anonymous_access"] = true

		if statusResp.Version.BuildHash != "" {
			metadata["build_hash"] = statusResp.Version.BuildHash
		}
		if statusResp.Version.BuildNumber > 0 {
			metadata["build_number"] = statusResp.Version.BuildNumber
		}
		if statusResp.UUID != "" {
			metadata["instance_uuid"] = statusResp.UUID
		}
		statusState := statusResp.Status.Overall.State
		if statusState == "" {
			statusState = statusResp.Status.Overall.Level
		}
		if statusState != "" {
			metadata["status_state"] = statusState
		}
	} else if hasWebUISignal {
		// Login page detected — authentication is (likely) enabled.
		metadata["authentication_enabled"] = true
	}

	if kbnName != "" {
		metadata["kbn_name"] = sanitizeHTTPHeaderValue(kbnName)
	}
	if kbnVersion != "" {
		metadata["kbn_version"] = sanitizeHTTPHeaderValue(kbnVersion)
	}

	result := &FingerprintResult{
		Technology: "kibana",
		Version:    version,
		CPEs:       []string{buildKibanaCPE(version)},
		Metadata:   metadata,
	}

	// Unauthenticated access to the status API is a high-severity misconfiguration.
	if hasAPISignal {
		result.Severity = plugins.SeverityHigh
	}

	return result, nil
}

// buildKibanaCPE constructs a CPE 2.3 string for Kibana.
// When version is empty, a wildcard CPE is emitted to support asset inventory.
func buildKibanaCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:elastic:kibana:%s:*:*:*:*:*:*:*", version)
}

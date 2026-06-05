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
Package fingerprinters provides HTTP fingerprinting for Apache Airflow.

# What We Detect

  - Apache Airflow web UI (login page, DAG views)
  - Apache Airflow REST API (health endpoint)
  - Anonymous API access (unauthenticated API exposure)

# What We Do NOT Detect

  - Apache Airflow CLI-only installations (no web UI)
  - Airflow behind reverse proxies that strip all identifying headers/content
  - Managed Airflow services (MWAA, Cloud Composer) with vendor-specific UIs

# Security Context

Apache Airflow is a workflow orchestration platform widely deployed in data
engineering environments. Multiple 2025 CVEs expose secrets and allow
unauthorized access via the web UI. Default installations frequently lack
authentication. Compromise of Airflow can expose database credentials, API
keys, and cloud provider tokens stored in connections and variables.

# Active Probe Safety

The active probe issues a plain GET /api/v1/health with no request body.
This is a read-only health check endpoint that returns scheduler and
metadatabase status. No write operations are performed.

# CPE

cpe:2.3:a:apache:airflow:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// AirflowFingerprinter detects Apache Airflow web UI and REST API instances.
type AirflowFingerprinter struct{}

// airflowTitleRegex matches the Airflow web UI title tag.
// Examples: "<title>Airflow</title>", "<title>Airflow - Login</title>", "<title>Airflow - DAGs</title>"
var airflowTitleRegex = regexp.MustCompile(`(?i)<title[^>]*>[^<]*airflow[^<]*</title>`)

// airflowAssetRegex matches structural markers of the Airflow web UI: asset paths
// or CSS/JS references containing "airflow" in src/href attributes.
// Examples: src="/static/airflow/...", href="/airflow/static/..."
var airflowAssetRegex = regexp.MustCompile(`(?i)(?:src|href)=["'][^"']*(?:/static/airflow|airflow-webserver)[^"']*["']`)

// airflowMetadatabaseRegex matches the "metadatabase" key in Airflow health JSON.
var airflowMetadatabaseRegex = regexp.MustCompile(`"metadatabase"\s*:\s*\{[^}]*"status"`)

// airflowSchedulerRegex matches the "scheduler" key in Airflow health JSON.
// Both metadatabase AND scheduler must be present to confirm an Airflow health response.
var airflowSchedulerRegex = regexp.MustCompile(`"scheduler"\s*:\s*\{[^}]*"status"`)

// airflowVersionJSONRegex extracts version from Airflow API JSON responses.
// Matches: "version": "2.8.1", "version":"2.7.0"
var airflowVersionJSONRegex = regexp.MustCompile(`"version"\s*:\s*"([0-9]+(?:\.[0-9]+){1,3})"`)

// airflowVersionValidateRegex is the anchored second-stage validator.
var airflowVersionValidateRegex = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,3}$`)

func init() {
	Register(&AirflowFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *AirflowFingerprinter) Name() string {
	return "airflow"
}

// ProbeEndpoint returns the Airflow REST API health check path.
// A plain GET to /api/v1/health returns scheduler and metadatabase status
// when the API is accessible. No write operations are performed.
func (f *AirflowFingerprinter) ProbeEndpoint() string {
	return "/api/v1/health"
}

// ProbeAccept returns the Accept header for the active probe.
// Airflow's /api/v1/health endpoint returns application/json.
func (f *AirflowFingerprinter) ProbeAccept() string {
	return "application/json"
}

// Match returns true when the response is a candidate for Airflow detection.
//
// Body-scan candidates: text/html (web UI) or application/json (API).
// Airflow does not set a distinctive Server header, so no server header
// fast-path is available.
//
// 5xx responses are rejected: server errors do not provide usable fingerprint
// data. Responses below 200 (informational) are also rejected.
func (f *AirflowFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Body-scan candidates: text/html (web UI) or application/json (API).
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "application/json") {
		return true
	}

	return false
}

// Fingerprint performs full detection and extracts technology information.
//
// Detection requires at least one definitive signal:
//   - Web UI: Airflow title tag OR Airflow asset references in body — PRIMARY
//   - Health API: metadatabase/scheduler JSON structure in body — SECONDARY
//
// Version extraction: JSON "version" field from API responses or embedded HTML.
//
// Anonymous API access: when the health API signal is detected on the active
// probe, this means the API is accessible without authentication and is
// reported with SeverityHigh.
func (f *AirflowFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: internal 2 MiB body cap — defense-in-depth above the engine's
	// limit. An Airflow health response or login page is well under 2 MiB.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// --- Signal detection ---

	// PRIMARY: Web UI signals — title tag or asset references.
	hasWebUISignal := airflowTitleRegex.Match(body) || airflowAssetRegex.Match(body)

	// SECONDARY: Health API signal — both metadatabase AND scheduler keys must be present.
	hasHealthAPISignal := airflowMetadatabaseRegex.Match(body) && airflowSchedulerRegex.Match(body)

	// At least one definitive signal must be present.
	if !hasWebUISignal && !hasHealthAPISignal {
		return nil, nil
	}

	// Determine if this response came from the health endpoint path.
	// Accepts exact /api/v1/health or paths ending with /api/v1/health (prefix-proxied deployments).
	isHealthEndpointPath := false
	if resp.Request != nil && resp.Request.URL != nil {
		p := strings.ToLower(resp.Request.URL.Path)
		isHealthEndpointPath = p == "/api/v1/health" || strings.HasSuffix(p, "/api/v1/health")
	}

	// Determine detection method.
	var detectionMethod string
	switch {
	case isHealthEndpointPath && hasHealthAPISignal:
		detectionMethod = "active_probe"
	case hasHealthAPISignal:
		detectionMethod = "api_health"
	default:
		detectionMethod = "web_ui"
	}

	version := extractAirflowVersion(body)
	// Defense-in-depth: discard version if it somehow contains CPE metacharacters.
	// The extraction regex only captures digits and dots, so this should never trigger.
	if strings.ContainsAny(version, ":*") {
		version = ""
	}

	metadata := map[string]any{
		"vendor":           "Apache",
		"product":          "Airflow",
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}
	if hasHealthAPISignal && isHealthEndpointPath {
		metadata["anonymous_api_access"] = true
	}
	if hasHealthAPISignal && isHealthEndpointPath {
		metadata["probe_path"] = "/api/v1/health"
	}

	result := &FingerprintResult{
		Technology: "airflow",
		Version:    version,
		CPEs:       []string{buildAirflowCPE(version)},
		Metadata:   metadata,
	}

	// Anonymous API access confirmed on health endpoint path is a high-severity misconfiguration.
	if hasHealthAPISignal && isHealthEndpointPath {
		result.Severity = plugins.SeverityHigh
	}

	return result, nil
}

// extractAirflowVersion tries to extract the version from the JSON "version"
// field, applying two-stage validation before returning. Returns empty string
// if no valid version is found.
func extractAirflowVersion(body []byte) string {
	if m := airflowVersionJSONRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); airflowVersionValidateRegex.MatchString(v) {
			return v
		}
	}
	return ""
}

// buildAirflowCPE constructs a CPE 2.3 string for Apache Airflow.
// When version is empty, a wildcard CPE is emitted.
func buildAirflowCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:apache:airflow:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:apache:airflow:%s:*:*:*:*:*:*:*", version)
}

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
Package fingerprinters provides HTTP fingerprinting for the Envoy proxy
admin interface.

# What We Detect

  - Envoy /server_info API (active probe): version, build, and node metadata
  - Envoy admin web UI (passive): the "Envoy Admin" landing page

# What We Do NOT Detect

  - Envoy data-plane proxying (the admin interface is a separate, optional
    listener that operators may disable or bind to localhost only)
  - Envoy deployments that strip the Server header and are not reachable on
    the admin listener (no distinguishing signal remains)

# Security Context

The Envoy admin interface exposes operational endpoints (/stats, /config_dump,
/certs, /clusters) that can leak internal topology, TLS material metadata, and
in some configurations allow runtime configuration changes. Exposure of this
interface on a non-localhost listener is a common misconfiguration. This
ticket is fingerprinter-only: no misconfiguration finding is emitted (Severity
is left unset).

# Active Probe Safety

The active probe issues a plain GET /server_info with no request body. This
is a read-only status endpoint. No write operations are performed.

# CPE

cpe:2.3:a:envoyproxy:envoy:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// envoyMaxBodySize is an internal defense-in-depth cap on the body size
// considered for detection, applied above the engine's global response limit.
const envoyMaxBodySize = 2 * 1024 * 1024

// envoyVersionRegex validates a single semver-like segment extracted from the
// slash-delimited Envoy /server_info "version" field. Allows pre-release
// suffixes such as "-dev" or "-rc1".
var envoyVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+(-[a-zA-Z0-9._-]+)?$`)

// envoyAdminTitleRegex matches the Envoy admin web UI title tag exactly
// (anchored, case-insensitive), avoiding false positives from prose mentions
// of "Envoy Admin" elsewhere on a page.
var envoyAdminTitleRegex = regexp.MustCompile(`(?i)<title>\s*Envoy Admin\s*</title>`)

// EnvoyServerInfoFingerprinter actively probes /server_info and confirms
// Envoy via the hot_restart_version field or node.user_agent_name, extracting
// version and build metadata from the JSON response.
type EnvoyServerInfoFingerprinter struct{}

// EnvoyAdminFingerprinter passively detects the Envoy admin interface via the
// Server response header or the admin web UI title, without an active probe.
type EnvoyAdminFingerprinter struct{}

// envoyServerInfoResponse models the subset of the Envoy /server_info JSON
// response used for detection and version extraction.
type envoyServerInfoResponse struct {
	Version           string `json:"version"`
	State             string `json:"state"`
	HotRestartVersion string `json:"hot_restart_version"`
	Node              struct {
		UserAgentName string `json:"user_agent_name"`
	} `json:"node"`
}

// envoyVersionSegments holds the components parsed from an Envoy
// /server_info "version" field, e.g.
// "c93f9f6c1e5adddd10a3e3646c7e049c649ae177/1.9.0-dev/Clean/RELEASE/BoringSSL".
type envoyVersionSegments struct {
	Version    string // clean semver, pre-release suffix stripped — used for CPE
	RawVersion string // matched segment as-is, may include a suffix (e.g. "1.9.0-dev")
	BuildType  string // e.g. "RELEASE", "DEBUG"
	TLSLibrary string // e.g. "BoringSSL"
}

func init() {
	Register(&EnvoyServerInfoFingerprinter{})
	Register(&EnvoyAdminFingerprinter{})
}

// ── EnvoyServerInfoFingerprinter ──────────────────────────────────────────────

// Name returns the fingerprinter identifier.
func (f *EnvoyServerInfoFingerprinter) Name() string {
	return "envoy-admin-api"
}

// ProbeEndpoint returns the Envoy /server_info status endpoint path.
func (f *EnvoyServerInfoFingerprinter) ProbeEndpoint() string {
	return "/server_info"
}

// Match returns true when the probe response is a candidate for Envoy
// /server_info detection: only HTTP 200 is accepted, and either the Server
// header advertises envoy (case-insensitive) or the Content-Type is
// application/json.
func (f *EnvoyServerInfoFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode != http.StatusOK {
		return false
	}
	if strings.EqualFold(resp.Header.Get("Server"), "envoy") {
		return true
	}
	return strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "application/json")
}

// Fingerprint performs full detection against the /server_info JSON body.
//
// Confirmation requires at least one Envoy-unique signal:
//   - hot_restart_version present in the response — PRIMARY (unique to Envoy)
//   - node.user_agent_name == "envoy" — SECONDARY
//
// Version is extracted from the slash-delimited "version" field. The clean
// (suffix-stripped) version is used for Version/CPE since NVD CPEs do not
// include pre-release suffixes; the raw matched segment is preserved in
// metadata when it differs from the clean version.
func (f *EnvoyServerInfoFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter — only 200 is a valid /server_info response.
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	// Gate 2: internal body cap — defense-in-depth above the engine's limit.
	if len(body) > envoyMaxBodySize {
		return nil, nil
	}

	var info envoyServerInfoResponse
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, nil
	}

	isEnvoy := info.HotRestartVersion != "" || info.Node.UserAgentName == "envoy"
	if !isEnvoy {
		return nil, nil
	}

	segs := parseEnvoyVersionField(info.Version)

	metadata := map[string]any{}
	if info.State != "" {
		metadata["state"] = info.State
	}
	if info.HotRestartVersion != "" {
		metadata["hot_restart_version"] = info.HotRestartVersion
	}
	if segs.BuildType != "" {
		metadata["build_type"] = segs.BuildType
	}
	if segs.TLSLibrary != "" {
		metadata["tls_library"] = segs.TLSLibrary
	}
	if segs.RawVersion != "" && segs.RawVersion != segs.Version {
		metadata["version_raw"] = segs.RawVersion
	}

	return &FingerprintResult{
		Technology: "envoy",
		Version:    segs.Version,
		CPEs:       []string{buildEnvoyCPE(segs.Version)},
		Metadata:   metadata,
	}, nil
}

// parseEnvoyVersionField parses the slash-delimited Envoy "version" field,
// e.g. "{hash}/{semver}/{Clean|Modified}/{RELEASE|DEBUG}/{TLS}". It scans
// every segment for the first one matching envoyVersionRegex (handling both
// hash-prefixed and hash-less forms) and extracts the build type and TLS
// library from the two segments that follow it, when present.
func parseEnvoyVersionField(field string) envoyVersionSegments {
	var segs envoyVersionSegments
	if field == "" {
		return segs
	}

	parts := strings.Split(field, "/")
	for i, part := range parts {
		if !envoyVersionRegex.MatchString(part) {
			continue
		}
		segs.RawVersion = part
		segs.Version = stripEnvoyVersionSuffix(part)
		if i+2 < len(parts) {
			segs.BuildType = parts[i+2]
		}
		if i+3 < len(parts) {
			segs.TLSLibrary = parts[i+3]
		}
		break
	}
	return segs
}

// stripEnvoyVersionSuffix removes a pre-release suffix (e.g. "-dev", "-rc1")
// from a version segment for use in CPE output.
func stripEnvoyVersionSuffix(version string) string {
	if idx := strings.Index(version, "-"); idx != -1 {
		return version[:idx]
	}
	return version
}

// ── EnvoyAdminFingerprinter ───────────────────────────────────────────────────

// Name returns the fingerprinter identifier.
func (f *EnvoyAdminFingerprinter) Name() string {
	return "envoy-admin"
}

// Match returns true when the root response is a candidate for passive Envoy
// admin detection: status codes 200-499 are accepted (5xx server errors do
// not provide usable fingerprint data), and either the Server header
// advertises envoy (case-insensitive) or the Content-Type is text/html.
func (f *EnvoyAdminFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode > 499 {
		return false
	}
	if strings.EqualFold(resp.Header.Get("Server"), "envoy") {
		return true
	}
	return strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html")
}

// Fingerprint performs passive detection against the root response.
//
// Confirmation requires the admin UI title tag in the HTML body. The
// Server: envoy header alone is insufficient because Envoy data-plane
// proxies also set this header on regular proxied traffic; emitting
// envoy-admin based on the header alone would misclassify backend
// applications behind Envoy as exposed admin interfaces.
//
// No version is available from the title, so a wildcard CPE is emitted.
func (f *EnvoyAdminFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter — 5xx server errors are rejected.
	if resp.StatusCode < 200 || resp.StatusCode > 499 {
		return nil, nil
	}

	// Gate 2: internal body cap — defense-in-depth above the engine's limit.
	if len(body) > envoyMaxBodySize {
		return nil, nil
	}

	if !envoyAdminTitleRegex.Match(body) {
		return nil, nil
	}

	detectionMethod := "admin_ui"
	if strings.EqualFold(resp.Header.Get("Server"), "envoy") {
		detectionMethod = "server_header+admin_ui"
	}

	return &FingerprintResult{
		Technology: "envoy-admin",
		Version:    "",
		CPEs:       []string{buildEnvoyCPE("")},
		Metadata: map[string]any{
			"detection_method": detectionMethod,
		},
	}, nil
}

// buildEnvoyCPE constructs a CPE 2.3 string for Envoy proxy. Pre-release
// suffixes are stripped (NVD CPEs do not include them). Empty or invalid
// versions produce a wildcard CPE.
func buildEnvoyCPE(version string) string {
	if version == "" || !envoyVersionRegex.MatchString(version) {
		version = "*"
	}
	if version != "*" {
		version = stripEnvoyVersionSuffix(version)
	}
	return fmt.Sprintf("cpe:2.3:a:envoyproxy:envoy:%s:*:*:*:*:*:*:*", version)
}

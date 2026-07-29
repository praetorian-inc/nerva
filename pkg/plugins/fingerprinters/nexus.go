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
Package fingerprinters provides HTTP fingerprinting for Sonatype Nexus
Repository Manager.

# Detection Strategy

Nexus Repository Manager identifies itself via the "Server" response header
on every HTTP response, e.g.:

	Server: Nexus/3.63.0-01 (PRO)
	Server: Nexus/2.15.1-02 Noelios-Restlet-Engine/1.1.6

Detection uses two complementary approaches:

Primary (NexusAPIFingerprinter): Active probe of the unauthenticated REST
status endpoint /service/rest/v1/status, which returns HTTP 200 with an
empty body when the instance is healthy, or HTTP 503 with an empty body
when the instance is unhealthy. The Server header is present on both
responses and is the sole detection signal.

Secondary (NexusLoginFingerprinter): Passive detection from any response
carrying the Nexus Server header, or from the HTML login page served at the
root when the Server header has been stripped by a reverse proxy. The login
page <title> is distinctive per major version:

	Nexus 3: <title>Sonatype Nexus Repository</title>
	Nexus 2: <title>Sonatype Nexus</title>

# Version Detection

Extracted from the Server header when present:

	Nexus/{version}-{build} ({edition})

The build suffix (e.g. "-01") is not part of the semantic version and is
discarded. The captured version is validated against `^\d+\.\d+\.\d+$`
before use. Edition ("OSS" or "PRO") is extracted from the parenthesized
suffix and normalized to lowercase.

# CPE

cpe:2.3:a:sonatype:nexus_repository_manager:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"regexp"
	"strings"

	"net/http"
)

const nexusMaxBodySize = 1 << 20

// nexusServerPattern detects the Nexus Server header as a standalone signal.
// The `\b` word boundary rejects concatenated-word prefixes like
// "SonatypeNexusProxy/1.0". Hyphen-delimited names ("X-Nexus/1.0") still
// match because `-` is a non-word character; no known product ships such a
// header.
var nexusServerPattern = regexp.MustCompile(`(?i)\bNexus/`)

// nexusVersionPattern extracts the version from a Nexus Server header value.
// Matches "Nexus/3.63.0-01" or "Nexus/2.15.1-02", capturing only the
// three-component semantic version and discarding the build suffix. The
// trailing `(?:[\s(]|$)` boundary requires the version (plus optional build
// suffix) to be followed by whitespace, an opening parenthesis, or the end
// of the string, rejecting trailing garbage such as "Nexus/5.38.0abc" or a
// four-component version like "Nexus/3.63.0.1-01".
var nexusVersionPattern = regexp.MustCompile(`(?i)Nexus/(\d+\.\d+\.\d+)(?:-\d+)?(?:[\s(]|$)`)

// nexusVersionValidRegex validates the extracted version string before CPE
// use. Accepts only pure three-component numeric versions.
var nexusVersionValidRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// nexusEditionPattern extracts the edition ("OSS" or "PRO") from the
// parenthesized suffix of the Server header, e.g. "(PRO)" or "(OSS)".
var nexusEditionPattern = regexp.MustCompile(`(?i)\((OSS|PRO)\)`)

// nexusTitleV3Pattern matches the Nexus 3 login page title. Checked before
// nexusTitleV2Pattern since "Sonatype Nexus Repository" would otherwise also
// satisfy a loosely-anchored Nexus 2 pattern.
var nexusTitleV3Pattern = regexp.MustCompile(`(?i)<title[^>]*>\s*Sonatype Nexus Repository\s*</title>`)

// nexusTitleV2Pattern matches the Nexus 2 login page title. Only checked
// after nexusTitleV3Pattern fails to match, preventing Nexus 3 pages from
// triggering Nexus 2 detection.
var nexusTitleV2Pattern = regexp.MustCompile(`(?i)<title[^>]*>\s*Sonatype Nexus\s*</title>`)

// extractNexusServerInfo parses a Nexus Server header value and returns the
// version, edition ("oss"/"pro"), and generation ("2"/"3") detected. Any
// field returns "" when it cannot be determined.
//
// Generation is derived from the leading digit of the extracted version when
// available. When no valid version is present but the header advertises the
// Noelios-Restlet-Engine (used exclusively by Nexus 2), generation "2" is
// still reported.
func extractNexusServerInfo(serverHeader string) (version, edition, generation string) {
	if m := nexusVersionPattern.FindStringSubmatch(serverHeader); len(m) == 2 {
		v := m[1]
		if nexusVersionValidRegex.MatchString(v) {
			version = v
		}
	}

	if m := nexusEditionPattern.FindStringSubmatch(serverHeader); len(m) == 2 {
		edition = strings.ToLower(m[1])
	}

	switch {
	case len(version) > 0 && (version[0] == '2' || version[0] == '3'):
		generation = string(version[0])
	case strings.Contains(serverHeader, "Noelios-Restlet-Engine"):
		generation = "2"
	}

	return version, edition, generation
}

// buildNexusCPE constructs a CPE 2.3 string for Nexus Repository Manager.
// Empty or metacharacter-bearing versions are replaced with a wildcard to
// keep the CPE well-formed.
func buildNexusCPE(version string) string {
	v := version
	if v == "" || strings.ContainsAny(v, ":*?") {
		v = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:sonatype:nexus_repository_manager:%s:*:*:*:*:*:*:*", v)
}

// nexusMetadata builds the common metadata map shared by both fingerprinters.
func nexusMetadata(detectionMethod, edition, generation string) map[string]any {
	metadata := map[string]any{
		"vendor":           "Sonatype",
		"product":          "Nexus Repository Manager",
		"detection_method": detectionMethod,
	}
	if edition != "" {
		metadata["edition"] = edition
	}
	if generation != "" {
		metadata["nexus_major_version"] = generation
	}
	return metadata
}

// --- NexusAPIFingerprinter ---

// NexusAPIFingerprinter detects Nexus Repository Manager via an active probe
// of the unauthenticated REST status endpoint.
type NexusAPIFingerprinter struct{}

func init() {
	Register(&NexusAPIFingerprinter{})
	Register(&NexusLoginFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *NexusAPIFingerprinter) Name() string {
	return "nexus-repository"
}

// ProbeEndpoint returns the Nexus REST status endpoint. A plain GET returns
// HTTP 200 with an empty body when the instance is healthy; no write
// operations are performed and no authentication material is transmitted.
func (f *NexusAPIFingerprinter) ProbeEndpoint() string {
	return "/service/rest/v1/status"
}

// Match returns true when the response is HTTP 200 or HTTP 503 and the
// Server header contains the Nexus signature.
func (f *NexusAPIFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		return false
	}
	return nexusServerPattern.MatchString(resp.Header.Get("Server"))
}

// Fingerprint performs full Nexus detection from the status endpoint
// response, extracting version and edition from the Server header.
func (f *NexusAPIFingerprinter) Fingerprint(resp *http.Response, _ []byte) (*FingerprintResult, error) {
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		return nil, nil
	}

	serverHeader := resp.Header.Get("Server")
	if !nexusServerPattern.MatchString(serverHeader) {
		return nil, nil
	}

	version, edition, generation := extractNexusServerInfo(serverHeader)

	return &FingerprintResult{
		Technology: "nexus-repository",
		Version:    version,
		CPEs:       []string{buildNexusCPE(version)},
		Metadata:   nexusMetadata("server_header", edition, generation),
	}, nil
}

// --- NexusLoginFingerprinter ---

// NexusLoginFingerprinter detects Nexus Repository Manager passively, either
// from the Server header on any response or from the HTML login page title
// when the Server header has been stripped by a reverse proxy. Implements
// HTTPFingerprinter only (no active probe).
type NexusLoginFingerprinter struct{}

// Name returns the fingerprinter identifier.
func (f *NexusLoginFingerprinter) Name() string {
	return "nexus-repository-login"
}

// Match returns true when the response is a candidate for passive Nexus
// detection: any non-5xx response with the Nexus Server header, or any
// response advertising text/html content.
func (f *NexusLoginFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode >= 500 {
		return false
	}

	if nexusServerPattern.MatchString(resp.Header.Get("Server")) {
		return true
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs passive Nexus detection.
//
// Primary signal: Server header contains the Nexus signature — version and
// edition are extracted from it directly.
//
// Body fallback: when the Server header does not identify Nexus (stripped by
// a reverse proxy, or present without a parseable version), the HTML <title>
// is checked for the Nexus 3 or Nexus 2 login page markers. Nexus 3 is
// checked first since its title also contains the Nexus 2 title as a prefix.
func (f *NexusLoginFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode >= 500 {
		return nil, nil
	}

	if len(body) > nexusMaxBodySize {
		body = body[:nexusMaxBodySize]
	}

	serverHeader := resp.Header.Get("Server")
	if nexusServerPattern.MatchString(serverHeader) {
		version, edition, generation := extractNexusServerInfo(serverHeader)
		return &FingerprintResult{
			Technology: "nexus-repository-login",
			Version:    version,
			CPEs:       []string{buildNexusCPE(version)},
			Metadata:   nexusMetadata("server_header", edition, generation),
		}, nil
	}

	var generation string
	switch {
	case nexusTitleV3Pattern.Match(body):
		generation = "3"
	case nexusTitleV2Pattern.Match(body):
		generation = "2"
	default:
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "nexus-repository-login",
		Version:    "",
		CPEs:       []string{buildNexusCPE("")},
		Metadata:   nexusMetadata("html_title", "", generation),
	}, nil
}

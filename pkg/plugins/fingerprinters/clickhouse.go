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
Package fingerprinters provides HTTP fingerprinting for ClickHouse's HTTP
interface.

# What We Detect

  - ClickHouse instances via the presence of any X-ClickHouse-* response
    header (e.g., X-ClickHouse-Query-Id, X-ClickHouse-Summary,
    X-ClickHouse-Server-Display-Name, X-ClickHouse-Format,
    X-ClickHouse-Timezone, X-ClickHouse-Exception-Code). These headers are
    definitive — no other technology sets them — and are present on both
    successful (200) and error/auth-required (403 and other) responses.
  - The probe issues SELECT version() against the HTTP query endpoint. On an
    unauthenticated 200 response, the body is a bare version string (e.g.,
    "24.1.5.53\n") that is extracted and validated. On 403 (auth required)
    or other error responses, the technology is still detected via the
    X-ClickHouse-* header but no version is reported.

# What We Do NOT Detect

  - ClickHouse deployments fronted by a reverse proxy that strips
    X-ClickHouse-* headers
  - ClickHouse Native (TCP) protocol interface — handled by a separate plugin

# CPE

cpe:2.3:a:clickhouse:clickhouse:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// ClickHouseHTTPFingerprinter detects ClickHouse's HTTP interface via
// X-ClickHouse-* response headers and, when unauthenticated, the version
// string returned by SELECT version().
type ClickHouseHTTPFingerprinter struct{}

// clickhouseVersionRegex matches a bare version string of at least
// major.minor.patch, optionally followed by a revision component (e.g.,
// "24.1.5" or "24.1.5.53"). Anchored to reject partial matches such as
// "5.38abc" or "V5.38.0".
var clickhouseVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+(\.\d+)?$`)

func init() {
	Register(&ClickHouseHTTPFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *ClickHouseHTTPFingerprinter) Name() string {
	return "clickhouse-http"
}

// ProbeEndpoint returns the ClickHouse HTTP query endpoint used to request
// the server version. This endpoint may require authentication depending on
// server configuration; the X-ClickHouse-* headers are present regardless.
func (f *ClickHouseHTTPFingerprinter) ProbeEndpoint() string {
	return "/?query=SELECT+version()"
}

// Match returns true when any X-ClickHouse-* response header is present on a
// 200-499 status response. Header presence is checked case-insensitively
// since HTTP header names are not case sensitive.
func (f *ClickHouseHTTPFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode > 499 {
		return false
	}
	for key := range resp.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-clickhouse-") {
			return true
		}
	}
	return false
}

// Fingerprint extracts the ClickHouse version from the response body when
// available (unauthenticated 200 response to SELECT version()). On
// auth-required or error responses, ClickHouse is still detected via the
// X-ClickHouse-* header but Version is left empty.
func (f *ClickHouseHTTPFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	version := ""
	detectionMethod := "x-clickhouse-header"

	// 2 MiB body cap — defense-in-depth above the engine limit. Only affects
	// version extraction; header-based detection already occurred in Match.
	if resp.StatusCode == http.StatusOK && len(body) <= 2*1024*1024 {
		trimmed := strings.TrimSpace(string(body))
		if clickhouseVersionRegex.MatchString(trimmed) {
			version = trimmed
			detectionMethod = "version_query"
		}
	}

	// CPE injection defense — belt-and-suspenders guard.
	if strings.ContainsAny(version, ":*?") {
		version = ""
		detectionMethod = "x-clickhouse-header"
	}

	metadata := map[string]any{
		"vendor":           "ClickHouse",
		"product":          "ClickHouse",
		"detection_method": detectionMethod,
	}

	return &FingerprintResult{
		Technology: "clickhouse-http",
		Version:    version,
		CPEs:       []string{buildClickHouseHTTPCPE(version)},
		Metadata:   metadata,
	}, nil
}

// buildClickHouseHTTPCPE constructs a CPE 2.3 string for ClickHouse.
// When version is empty, a wildcard CPE is emitted to support asset inventory.
func buildClickHouseHTTPCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:clickhouse:clickhouse:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:clickhouse:clickhouse:%s:*:*:*:*:*:*:*", version)
}

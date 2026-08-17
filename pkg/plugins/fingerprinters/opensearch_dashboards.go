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

package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// OpenSearchDashboardsFingerprinter detects OpenSearch Dashboards, the
// Kibana-forked visualisation front-end for OpenSearch, via structural HTML
// markers in the served web UI.
type OpenSearchDashboardsFingerprinter struct{}

// openSearchDashboardsTitleRegex matches the OpenSearch Dashboards page title.
// Structural match — the <title> tag is a definitive page identity marker.
var openSearchDashboardsTitleRegex = regexp.MustCompile(`(?i)<title[^>]*>[^<]*opensearch dashboards[^<]*</title>`)

// openSearchDashboardsInjectedMetaRegex matches the <osd-injected-metadata>
// element that OpenSearch Dashboards injects into every page it serves.
// Analogous to Kibana's <kbn-injected-metadata>.
var openSearchDashboardsInjectedMetaRegex = regexp.MustCompile(`(?i)<osd-injected-metadata`)

func init() {
	Register(&OpenSearchDashboardsFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *OpenSearchDashboardsFingerprinter) Name() string {
	return "opensearch-dashboards"
}

// Match returns true when the response is a candidate for OpenSearch
// Dashboards detection. Dashboards serves an HTML web UI.
func (f *OpenSearchDashboardsFingerprinter) Match(resp *http.Response) bool {
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(contentType, "text/html")
}

// Fingerprint performs full detection and extracts technology information.
//
// Detection signals: <title>OpenSearch Dashboards</title> or the structural
// <osd-injected-metadata> element. Version is extracted from the osd-version
// response header when present.
func (f *OpenSearchDashboardsFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	hasTitle := openSearchDashboardsTitleRegex.Match(body)
	hasInjectedMeta := openSearchDashboardsInjectedMetaRegex.Match(body)

	if !hasTitle && !hasInjectedMeta {
		return nil, nil
	}

	version := ""
	if osdVersion := resp.Header.Get("osd-version"); osdVersion != "" {
		v := cleanVersionString(sanitizeHTTPHeaderValue(osdVersion))
		if !strings.ContainsAny(v, ":*?") && openSearchVersionValidateRegex.MatchString(v) {
			version = v
		}
	}

	return &FingerprintResult{
		Technology: "opensearch-dashboards",
		Version:    version,
		CPEs:       []string{buildOpenSearchDashboardsCPE(version)},
		Metadata: map[string]any{
			"vendor":  "Amazon",
			"product": "OpenSearch Dashboards",
		},
	}, nil
}

// buildOpenSearchDashboardsCPE generates a CPE (Common Platform Enumeration)
// string for OpenSearch Dashboards.
// CPE format: cpe:2.3:a:amazon:opensearch_dashboards:{version}:*:*:*:*:*:*:*
//
// NOTE: As of 2026-08, this CPE has no matching entry in the NVD CPE dictionary.
// Real Dashboards CVEs use varied CPEs (e.g. opensearch-project:security-dashboards-plugin).
// This best-effort CPE follows the parent product naming convention for asset inventory.
//
// When version is unknown, uses "*" for the version field to enable asset
// inventory use cases.
func buildOpenSearchDashboardsCPE(version string) string {
	if version == "" {
		version = "*" // Unknown version, but known product
	}
	return fmt.Sprintf("cpe:2.3:a:amazon:opensearch_dashboards:%s:*:*:*:*:*:*:*", version)
}

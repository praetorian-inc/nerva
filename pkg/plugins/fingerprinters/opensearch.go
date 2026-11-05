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
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// OpenSearchFingerprinter detects OpenSearch via root endpoint (/)
type OpenSearchFingerprinter struct{}

const (
	openSearchDistribution = "opensearch"
	openSearchTaglineHint  = "opensearch.org"
)

// openSearchRootResponse represents the JSON response from the OpenSearch root endpoint.
type openSearchRootResponse struct {
	Name        string            `json:"name"`
	ClusterName string            `json:"cluster_name"`
	ClusterUUID string            `json:"cluster_uuid"`
	Version     openSearchVersion `json:"version"`
	Tagline     string            `json:"tagline"`
}

// openSearchVersion represents the version object in the OpenSearch response.
type openSearchVersion struct {
	Distribution  string `json:"distribution"`
	Number        string `json:"number"`
	BuildType     string `json:"build_type"`
	BuildHash     string `json:"build_hash"`
	BuildDate     string `json:"build_date"`
	BuildSnapshot bool   `json:"build_snapshot"`
	LuceneVersion string `json:"lucene_version"`
}

// openSearchVersionValidateRegex is the anchored validation gate for the
// version.number field: exactly three dot-separated integer components.
var openSearchVersionValidateRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func init() {
	Register(&OpenSearchFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *OpenSearchFingerprinter) Name() string {
	return "opensearch"
}

// Match returns true when the response is a candidate for OpenSearch detection.
// OpenSearch returns JSON at the root endpoint, same as Elasticsearch.
func (f *OpenSearchFingerprinter) Match(resp *http.Response) bool {
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(contentType, "application/json")
}

// Fingerprint performs full detection and extracts technology information.
//
// Detection signals (in priority order):
//  1. version.distribution == "opensearch" (primary — most reliable, unique to OpenSearch)
//  2. tagline contains "opensearch.org" (secondary — fallback for older versions
//     that predate the distribution field)
func (f *OpenSearchFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var osResponse openSearchRootResponse
	if err := json.Unmarshal(body, &osResponse); err != nil {
		return nil, nil // Not valid JSON or not OpenSearch format
	}

	isOpenSearch := osResponse.Version.Distribution == openSearchDistribution ||
		strings.Contains(osResponse.Tagline, openSearchTaglineHint)
	if !isOpenSearch {
		return nil, nil // Not OpenSearch (could be Elasticsearch or other service)
	}

	version := cleanVersionString(osResponse.Version.Number)

	// CPE metacharacter guard — reject versions containing CPE-reserved
	// characters before they can be embedded in a CPE string.
	if strings.ContainsAny(version, ":*?") {
		version = ""
	}

	// Validate the version shape (N.N.N) before trusting it.
	if version != "" && !openSearchVersionValidateRegex.MatchString(version) {
		version = ""
	}

	return &FingerprintResult{
		Technology: "opensearch",
		Version:    version,
		CPEs:       []string{buildOpenSearchCPE(version)},
		Metadata: map[string]any{
			"cluster_name":   sanitizeHTTPHeaderValue(osResponse.ClusterName),
			"lucene_version": sanitizeHTTPHeaderValue(osResponse.Version.LuceneVersion),
		},
		Severity: plugins.SeverityHigh,
	}, nil
}

// buildOpenSearchCPE generates a CPE (Common Platform Enumeration) string for OpenSearch.
// CPE format: cpe:2.3:a:amazon:opensearch:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for the version field to enable asset
// inventory use cases.
func buildOpenSearchCPE(version string) string {
	if version == "" {
		version = "*" // Unknown version, but known product
	}
	return fmt.Sprintf("cpe:2.3:a:amazon:opensearch:%s:*:*:*:*:*:*:*", version)
}

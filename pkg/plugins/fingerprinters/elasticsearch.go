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
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// ElasticsearchFingerprinter detects Elasticsearch via root endpoint (/)
type ElasticsearchFingerprinter struct{}

const elasticsearchTagline = "You Know, for Search"

// elasticsearchRootResponse represents the JSON response from Elasticsearch root endpoint
type elasticsearchRootResponse struct {
	Name        string               `json:"name"`
	ClusterName string               `json:"cluster_name"`
	ClusterUUID string               `json:"cluster_uuid"`
	Version     elasticsearchVersion `json:"version"`
	Tagline     string               `json:"tagline"`
}

// elasticsearchVersion represents the version object in Elasticsearch response
type elasticsearchVersion struct {
	Number        string `json:"number"`
	BuildFlavor   string `json:"build_flavor"`
	BuildType     string `json:"build_type"`
	BuildHash     string `json:"build_hash"`
	BuildDate     string `json:"build_date"`
	BuildSnapshot bool   `json:"build_snapshot"`
	LuceneVersion string `json:"lucene_version"`
}

func init() {
	Register(&ElasticsearchFingerprinter{})
}

func (f *ElasticsearchFingerprinter) Name() string {
	return "elasticsearch"
}

func (f *ElasticsearchFingerprinter) Match(resp *http.Response) bool {
	// Elasticsearch returns JSON at root endpoint
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

func (f *ElasticsearchFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Parse JSON response
	var esResponse elasticsearchRootResponse
	if err := json.Unmarshal(body, &esResponse); err != nil {
		return nil, nil // Not valid JSON or not Elasticsearch format
	}

	// Primary detection: Check for Elasticsearch tagline (unique to Elasticsearch, not OpenSearch)
	if esResponse.Tagline != elasticsearchTagline {
		return nil, nil // Not Elasticsearch (could be OpenSearch or other service)
	}

	// Extract version from version.number field
	version := esResponse.Version.Number

	// Clean up version string (remove -SNAPSHOT suffix if present)
	version = cleanVersionString(version)

	return &FingerprintResult{
		Technology: "elasticsearch",
		Version:    version,
		CPEs:       []string{buildElasticsearchCPE(version)},
		Metadata: map[string]any{
			"cluster_name":   esResponse.ClusterName,
			"lucene_version": esResponse.Version.LuceneVersion,
		},
		Severity: plugins.SeverityHigh,
	}, nil
}

// cleanVersionString removes -SNAPSHOT suffix from version strings
func cleanVersionString(version string) string {
	// Handle SNAPSHOT builds: "8.11.3-SNAPSHOT" → "8.11.3"
	version = strings.TrimSuffix(version, "-SNAPSHOT")
	return version
}

// buildElasticsearchCPE generates a CPE (Common Platform Enumeration) string for Elasticsearch.
// CPE format: cpe:2.3:a:elastic:elasticsearch:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to enable asset inventory use cases.
func buildElasticsearchCPE(version string) string {
	// Elasticsearch product is always known when this is called, so always generate CPE
	if version == "" {
		version = "*" // Unknown version, but known product
	}
	return fmt.Sprintf("cpe:2.3:a:elastic:elasticsearch:%s:*:*:*:*:*:*:*", version)
}

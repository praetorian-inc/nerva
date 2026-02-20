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
)

// ArangoDBFingerprinter detects ArangoDB via /_api/version endpoint
type ArangoDBFingerprinter struct{}

// arangoVersionResponse represents the JSON response from ArangoDB /_api/version endpoint
type arangoVersionResponse struct {
	Server  string `json:"server"`
	Version string `json:"version"`
	License string `json:"license"`
}

func init() {
	Register(&ArangoDBFingerprinter{})
}

func (f *ArangoDBFingerprinter) Name() string {
	return "arangodb"
}

func (f *ArangoDBFingerprinter) ProbeEndpoint() string {
	return "/_api/version"
}

func (f *ArangoDBFingerprinter) Match(resp *http.Response) bool {
	// ArangoDB returns JSON at /_api/version endpoint
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

func (f *ArangoDBFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Parse JSON response
	var arangoResponse arangoVersionResponse
	if err := json.Unmarshal(body, &arangoResponse); err != nil {
		return nil, nil // Not valid JSON or not ArangoDB format
	}

	// Primary detection: Check for server field set to "arango"
	if arangoResponse.Server != "arango" {
		return nil, nil // Not ArangoDB
	}

	// Extract version from version field
	version := arangoResponse.Version

	return &FingerprintResult{
		Technology: "arangodb",
		Version:    version,
		CPEs:       []string{buildArangoDBCPE(version)},
		Metadata: map[string]any{
			"license": arangoResponse.License,
		},
	}, nil
}

// buildArangoDBCPE generates a CPE (Common Platform Enumeration) string for ArangoDB.
// CPE format: cpe:2.3:a:arangodb:arangodb:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to enable asset inventory use cases.
func buildArangoDBCPE(version string) string {
	// ArangoDB product is always known when this is called, so always generate CPE
	if version == "" {
		version = "*" // Unknown version, but known product
	}
	return fmt.Sprintf("cpe:2.3:a:arangodb:arangodb:%s:*:*:*:*:*:*:*", version)
}

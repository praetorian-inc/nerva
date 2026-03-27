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
	"sort"
	"strings"
)

// WeaviateFingerprinter detects Weaviate vector database via /v1/meta endpoint
type WeaviateFingerprinter struct{}

// weaviateMetaResponse represents the JSON response from Weaviate /v1/meta endpoint
type weaviateMetaResponse struct {
	Hostname string                 `json:"hostname"`
	Version  string                 `json:"version"`
	Modules  map[string]interface{} `json:"modules"`
	GitHash  string                 `json:"gitHash"`
}

// weaviateSemverPattern matches the leading X.Y.Z part of a version string.
// This allows detection of versions with suffixes (e.g., "1.25.0-rc1").
var weaviateSemverPattern = regexp.MustCompile(`^\d+\.\d+\.\d+`)

func init() {
	Register(&WeaviateFingerprinter{})
}

func (f *WeaviateFingerprinter) Name() string {
	return "weaviate"
}

func (f *WeaviateFingerprinter) ProbeEndpoint() string {
	return "/v1/meta"
}

func (f *WeaviateFingerprinter) Match(resp *http.Response) bool {
	// Weaviate API returns JSON
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

func (f *WeaviateFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Parse JSON response
	var meta weaviateMetaResponse
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, nil // Not valid JSON, not Weaviate format
	}

	// Validate: both hostname and version must be present in real Weaviate responses
	if meta.Hostname == "" || meta.Version == "" {
		return nil, nil
	}

	// Weaviate always returns a URL as hostname (e.g., "http://[::]:8080").
	// Reject bare hostnames to prevent false positives from generic APIs.
	if !strings.HasPrefix(meta.Hostname, "http://") && !strings.HasPrefix(meta.Hostname, "https://") {
		return nil, nil
	}

	// Validate: version must match semver pattern (prevents false positives)
	match := weaviateSemverPattern.FindString(meta.Version)
	if match == "" {
		return nil, nil
	}

	// Clean version: extract only X.Y.Z, stripping any suffix like -rc1
	cleanedVersion := match

	// Collect module names (sorted for deterministic output)
	var moduleNames []string
	for name := range meta.Modules {
		moduleNames = append(moduleNames, name)
	}
	sort.Strings(moduleNames)

	metadata := map[string]any{
		"hostname":        meta.Hostname,
		"anonymous_access": true,
	}
	if len(moduleNames) > 0 {
		metadata["modules"] = moduleNames
	}
	if meta.GitHash != "" {
		metadata["git_hash"] = meta.GitHash
	}

	return &FingerprintResult{
		Technology: "weaviate",
		Version:    cleanedVersion,
		CPEs:       []string{buildWeaviateCPE(cleanedVersion)},
		Metadata:   metadata,
	}, nil
}

// buildWeaviateCPE generates a CPE (Common Platform Enumeration) string for Weaviate.
// CPE format: cpe:2.3:a:weaviate:weaviate:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for the version field to enable asset inventory use cases.
func buildWeaviateCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:weaviate:weaviate:%s:*:*:*:*:*:*:*", version)
}

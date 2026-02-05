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

// CouchDBFingerprinter detects Apache CouchDB via root endpoint
type CouchDBFingerprinter struct{}

// couchdbRootResponse represents the JSON structure returned by GET /
type couchdbRootResponse struct {
	CouchDB string `json:"couchdb"`
	Version string `json:"version"`
	Vendor  struct {
		Name string `json:"name"`
	} `json:"vendor"`
}

func init() {
	Register(&CouchDBFingerprinter{})
}

func (f *CouchDBFingerprinter) Name() string {
	return "couchdb"
}

func (f *CouchDBFingerprinter) ProbeEndpoint() string {
	return "/"
}

func (f *CouchDBFingerprinter) Match(resp *http.Response) bool {
	// CouchDB API returns JSON
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

func (f *CouchDBFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Empty response check
	if len(body) == 0 {
		return nil, nil
	}

	// Parse JSON
	var parsed couchdbRootResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, nil // Not valid JSON
	}

	// Validate CouchDB marker (exact match required, case-sensitive)
	if parsed.CouchDB != "Welcome" {
		return nil, nil
	}

	// Validate vendor field exists (vendor.name should be present)
	if parsed.Vendor.Name == "" {
		return nil, nil
	}

	// CouchDB detected! Extract version (may be empty if configured to hide)
	version := parsed.Version

	return &FingerprintResult{
		Technology: "couchdb",
		Version:    version,
		CPEs:       []string{buildCouchDBCPE(version)},
		Metadata: map[string]any{
			"vendor": parsed.Vendor.Name,
		},
	}, nil
}

func buildCouchDBCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:apache:couchdb:%s:*:*:*:*:*:*:*", version)
}

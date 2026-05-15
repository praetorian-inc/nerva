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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
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

// CouchDBAdminPartyFingerprinter detects CouchDB "admin party" mode via /_all_dbs.
// In admin party mode (no admin password set), /_all_dbs returns 200 with a JSON array.
// When authentication is configured, /_all_dbs returns 401 Unauthorized.
type CouchDBAdminPartyFingerprinter struct{}

func init() {
	Register(&CouchDBFingerprinter{})
	Register(&CouchDBAdminPartyFingerprinter{})
}

func (f *CouchDBAdminPartyFingerprinter) Name() string {
	return "couchdb-auth-check"
}

func (f *CouchDBAdminPartyFingerprinter) ProbeEndpoint() string {
	return "/_all_dbs"
}

func (f *CouchDBAdminPartyFingerprinter) Match(resp *http.Response) bool {
	// Admin party: 200 with JSON array
	// Auth required: 401 Unauthorized
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		return false
	}
	// If Server header is present, require it to contain "CouchDB" to avoid
	// misattributing arbitrary JSON-array endpoints. Absent header (reverse proxy) passes through.
	if server := resp.Header.Get("Server"); server != "" && !strings.Contains(server, "CouchDB") {
		return false
	}
	return true
}

func (f *CouchDBAdminPartyFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if len(body) == 0 {
		return nil, nil
	}

	// /_all_dbs returns a JSON array of database names - verify it starts with '['
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, nil
	}

	// Verify it's valid JSON
	var dbs []string
	if err := json.Unmarshal(trimmed, &dbs); err != nil {
		return nil, nil
	}

	// /_all_dbs accessible without auth = admin party mode
	return &FingerprintResult{
		Technology: "couchdb",
		Severity:   plugins.SeverityHigh,
	}, nil
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

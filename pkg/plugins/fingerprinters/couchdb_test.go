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
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestCouchDBFingerprinter_Name(t *testing.T) {
	fp := &CouchDBFingerprinter{}
	assert.Equal(t, "couchdb", fp.Name())
}

func TestCouchDBFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &CouchDBFingerprinter{}
	assert.Equal(t, "/", fp.ProbeEndpoint())
}

func TestCouchDBFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{
			name:        "matches JSON content type",
			contentType: "application/json",
			expected:    true,
		},
		{
			name:        "matches JSON with charset",
			contentType: "application/json; charset=utf-8",
			expected:    true,
		},
		{
			name:        "does not match HTML",
			contentType: "text/html",
			expected:    false,
		},
		{
			name:        "does not match plain text",
			contentType: "text/plain",
			expected:    false,
		},
		{
			name:        "does not match empty content type",
			contentType: "",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CouchDBFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestCouchDBFingerprinter_Fingerprint_ValidCouchDB(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		expectedTech     string
		expectedVersion  string
		expectedCPE      string
		expectedMetadata map[string]any
	}{
		{
			name: "CouchDB 3.x with full response",
			body: `{
				"couchdb": "Welcome",
				"version": "3.4.2",
				"git_sha": "6e5ad2a5c",
				"uuid": "9ddf59457dbb8772316cf06fc5e5a2e4",
				"features": ["access-ready", "partitioned"],
				"vendor": {"name": "The Apache Software Foundation"}
			}`,
			expectedTech:    "couchdb",
			expectedVersion: "3.4.2",
			expectedCPE:     "cpe:2.3:a:apache:couchdb:3.4.2:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"vendor": "The Apache Software Foundation",
			},
		},
		{
			name: "CouchDB 2.x response",
			body: `{
				"couchdb": "Welcome",
				"version": "2.3.1",
				"git_sha": "c298091a4",
				"uuid": "85fb71bf700c17267fef77535820e371",
				"features": ["scheduler"],
				"vendor": {"name": "The Apache Software Foundation"}
			}`,
			expectedTech:    "couchdb",
			expectedVersion: "2.3.1",
			expectedCPE:     "cpe:2.3:a:apache:couchdb:2.3.1:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"vendor": "The Apache Software Foundation",
			},
		},
		{
			name: "CouchDB 1.x response",
			body: `{
				"couchdb": "Welcome",
				"version": "1.6.1",
				"uuid": "85fb71bf700c17267fef77535820e371",
				"vendor": {"name": "The Apache Software Foundation"}
			}`,
			expectedTech:    "couchdb",
			expectedVersion: "1.6.1",
			expectedCPE:     "cpe:2.3:a:apache:couchdb:1.6.1:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"vendor": "The Apache Software Foundation",
			},
		},
		{
			name: "CouchDB with missing version (admin hidden)",
			body: `{
				"couchdb": "Welcome",
				"vendor": {"name": "The Apache Software Foundation"}
			}`,
			expectedTech:    "couchdb",
			expectedVersion: "",
			expectedCPE:     "cpe:2.3:a:apache:couchdb:*:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"vendor": "The Apache Software Foundation",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CouchDBFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body: io.NopCloser(bytes.NewReader([]byte(tt.body))),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, tt.expectedTech, result.Technology)
			assert.Equal(t, tt.expectedVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.expectedCPE)

			for key, expectedValue := range tt.expectedMetadata {
				assert.Equal(t, expectedValue, result.Metadata[key], "metadata key: %s", key)
			}
		})
	}
}

func TestCouchDBFingerprinter_Fingerprint_InvalidJSON(t *testing.T) {
	fp := &CouchDBFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	body := []byte("not valid json")

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err) // Should return nil result, not error
}

func TestCouchDBFingerprinter_Fingerprint_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing couchdb field",
			body: `{
				"version": "3.4.2",
				"vendor": {"name": "The Apache Software Foundation"}
			}`,
		},
		{
			name: "wrong couchdb value (case-sensitive check)",
			body: `{
				"couchdb": "welcome",
				"version": "3.4.2",
				"vendor": {"name": "The Apache Software Foundation"}
			}`,
		},
		{
			name: "wrong couchdb value",
			body: `{
				"couchdb": "Hello",
				"version": "3.4.2",
				"vendor": {"name": "The Apache Software Foundation"}
			}`,
		},
		{
			name: "missing vendor field",
			body: `{
				"couchdb": "Welcome",
				"version": "3.4.2"
			}`,
		},
		{
			name: "missing vendor.name field",
			body: `{
				"couchdb": "Welcome",
				"version": "3.4.2",
				"vendor": {}
			}`,
		},
		{
			name: "empty couchdb field",
			body: `{
				"couchdb": "",
				"version": "3.4.2",
				"vendor": {"name": "The Apache Software Foundation"}
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CouchDBFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			assert.Nil(t, result)
			assert.Nil(t, err) // Should return nil result, not error
		})
	}
}

func TestCouchDBFingerprinter_Fingerprint_NotCouchDB(t *testing.T) {
	fp := &CouchDBFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	// Valid JSON but not CouchDB format
	body := []byte(`{"status": "ok", "version": "1.0.0"}`)

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestBuildCouchDBCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version 3.x",
			version:  "3.4.2",
			expected: "cpe:2.3:a:apache:couchdb:3.4.2:*:*:*:*:*:*:*",
		},
		{
			name:     "normal version 2.x",
			version:  "2.3.1",
			expected: "cpe:2.3:a:apache:couchdb:2.3.1:*:*:*:*:*:*:*",
		},
		{
			name:     "normal version 1.x",
			version:  "1.6.1",
			expected: "cpe:2.3:a:apache:couchdb:1.6.1:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version (wildcard)",
			version:  "",
			expected: "cpe:2.3:a:apache:couchdb:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildCouchDBCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// --- CouchDBAdminPartyFingerprinter tests ---

func TestCouchDBAdminPartyFingerprinter_Name(t *testing.T) {
	fp := &CouchDBAdminPartyFingerprinter{}
	assert.Equal(t, "couchdb-auth-check", fp.Name())
}

func TestCouchDBAdminPartyFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &CouchDBAdminPartyFingerprinter{}
	assert.Equal(t, "/_all_dbs", fp.ProbeEndpoint())
}

func TestCouchDBAdminPartyFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		expected    bool
	}{
		{
			name:        "200 with JSON content type → true (admin party)",
			statusCode:  200,
			contentType: "application/json",
			expected:    true,
		},
		{
			name:        "200 with JSON charset → true",
			statusCode:  200,
			contentType: "application/json; charset=utf-8",
			expected:    true,
		},
		{
			name:        "401 unauthorized → false (auth required)",
			statusCode:  401,
			contentType: "application/json",
			expected:    false,
		},
		{
			name:        "200 with non-JSON content type → false",
			statusCode:  200,
			contentType: "text/html",
			expected:    false,
		},
		{
			name:        "403 forbidden → false",
			statusCode:  403,
			contentType: "application/json",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CouchDBAdminPartyFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestCouchDBAdminPartyFingerprinter_Fingerprint(t *testing.T) {
	tests := []struct {
		name        string
		body        []byte
		wantNil     bool
		wantSev     string // non-empty when wantNil=false
		wantTech    string
	}{
		{
			name:     "valid JSON array → FingerprintResult with SeverityHigh",
			body:     []byte(`["_users","_replicator","mydb"]`),
			wantNil:  false,
			wantTech: "couchdb",
		},
		{
			name:    "empty body → nil",
			body:    []byte{},
			wantNil: true,
		},
		{
			name:    "non-array JSON object → nil",
			body:    []byte(`{"error":"unauthorized"}`),
			wantNil: true,
		},
		{
			name:    "invalid JSON → nil",
			body:    []byte(`not json`),
			wantNil: true,
		},
		{
			name:    "empty JSON array → FingerprintResult (valid admin party with no databases)",
			body:    []byte(`[]`),
			wantNil: false,
			wantTech: "couchdb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CouchDBAdminPartyFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body: io.NopCloser(bytes.NewReader(tt.body)),
			}

			result, err := fp.Fingerprint(resp, tt.body)

			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			assert.Equal(t, tt.wantTech, result.Technology)
		})
	}
}

// TestCouchDBAdminPartyFingerprinter_FingerprintSeverity validates that a successful
// Fingerprint call returns a result with Severity=SeverityHigh.
func TestCouchDBAdminPartyFingerprinter_FingerprintSeverity(t *testing.T) {
	fp := &CouchDBAdminPartyFingerprinter{}
	body := []byte(`["_users","_replicator","mydb"]`)
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, plugins.SeverityHigh, result.Severity, "Severity must be SeverityHigh for admin party")
}

// TestCouchDBAdminPartyFingerprinter_LargeArray verifies that a body with 100+ database names
// still returns a result.
func TestCouchDBAdminPartyFingerprinter_LargeArray(t *testing.T) {
	// Build a JSON array with 100 entries
	dbs := make([]string, 100)
	for i := range dbs {
		dbs[i] = fmt.Sprintf("\"db_%d\"", i)
	}
	bodyStr := "[" + joinStrings(dbs, ",") + "]"
	body := []byte(bodyStr)

	fp := &CouchDBAdminPartyFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result, "expected non-nil result for large array body")
	assert.Equal(t, "couchdb", result.Technology)
}

// joinStrings joins slice elements with a separator (avoids strings package import).
func joinStrings(strs []string, sep string) string {
	result := ""
	for i, s := range strs {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}

// TestCouchDBAdminPartyFingerprinter_WhitespaceBody verifies that a body with leading and
// trailing whitespace around a valid JSON array still matches.
func TestCouchDBAdminPartyFingerprinter_WhitespaceBody(t *testing.T) {
	body := []byte("  \n  [\"_users\", \"_replicator\"]  \n  ")

	fp := &CouchDBAdminPartyFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result, "expected non-nil result for whitespace-padded JSON array")
	assert.Equal(t, "couchdb", result.Technology)
}

// TestCouchDBAdminPartyFingerprinter_NestedJSON verifies that a body that is a JSON array but
// contains non-string elements returns nil (only string arrays represent /_all_dbs).
func TestCouchDBAdminPartyFingerprinter_NestedJSON(t *testing.T) {
	// JSON array with non-string elements (objects instead of strings)
	body := []byte(`[{"name":"db1"},{"name":"db2"}]`)

	fp := &CouchDBAdminPartyFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	assert.Nil(t, result, "expected nil result for non-string array elements")
}

func TestCouchDBFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &CouchDBFingerprinter{}
	Register(fp)

	body := []byte(`{
		"couchdb": "Welcome",
		"version": "3.4.2",
		"git_sha": "6e5ad2a5c",
		"uuid": "9ddf59457dbb8772316cf06fc5e5a2e4",
		"features": ["access-ready", "partitioned"],
		"vendor": {"name": "The Apache Software Foundation"}
	}`)

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1)
	assert.Equal(t, "couchdb", results[0].Technology)
	assert.Equal(t, "3.4.2", results[0].Version)
	assert.Contains(t, results[0].CPEs, "cpe:2.3:a:apache:couchdb:3.4.2:*:*:*:*:*:*:*")
}

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
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

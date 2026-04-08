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

func TestEtcdFingerprinter_Name(t *testing.T) {
	fp := &EtcdFingerprinter{}
	assert.Equal(t, "etcd", fp.Name())
}

func TestEtcdFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &EtcdFingerprinter{}
	assert.Equal(t, "/version", fp.ProbeEndpoint())
}

func TestEtcdFingerprinter_Match(t *testing.T) {
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
			fp := &EtcdFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestEtcdFingerprinter_Fingerprint_ValidEtcd(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		expectedTech    string
		expectedVersion string
		expectedCPE     string
		expectedCluster string
	}{
		{
			name: "etcd 3.5.9",
			body: `{
				"etcdserver": "3.5.9",
				"etcdcluster": "3.5.0"
			}`,
			expectedTech:    "etcd",
			expectedVersion: "3.5.9",
			expectedCPE:     "cpe:2.3:a:etcd-io:etcd:3.5.9:*:*:*:*:*:*:*",
			expectedCluster: "3.5.0",
		},
		{
			name: "etcd 3.4.27",
			body: `{
				"etcdserver": "3.4.27",
				"etcdcluster": "3.4.0"
			}`,
			expectedTech:    "etcd",
			expectedVersion: "3.4.27",
			expectedCPE:     "cpe:2.3:a:etcd-io:etcd:3.4.27:*:*:*:*:*:*:*",
			expectedCluster: "3.4.0",
		},
		{
			name: "etcd 3.3.25",
			body: `{
				"etcdserver": "3.3.25",
				"etcdcluster": "3.3.0"
			}`,
			expectedTech:    "etcd",
			expectedVersion: "3.3.25",
			expectedCPE:     "cpe:2.3:a:etcd-io:etcd:3.3.25:*:*:*:*:*:*:*",
			expectedCluster: "3.3.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &EtcdFingerprinter{}
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

			// Check cluster version in metadata
			if tt.expectedCluster != "" {
				assert.Equal(t, tt.expectedCluster, result.Metadata["cluster_version"])
			}

		})
	}
}

func TestEtcdFingerprinter_Fingerprint_InvalidJSON(t *testing.T) {
	fp := &EtcdFingerprinter{}
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

func TestEtcdFingerprinter_Fingerprint_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing etcdserver field",
			body: `{
				"etcdcluster": "3.5.0"
			}`,
		},
		{
			name: "empty etcdserver field",
			body: `{
				"etcdserver": "",
				"etcdcluster": "3.5.0"
			}`,
		},
		{
			name: "invalid version format",
			body: `{
				"etcdserver": "invalid",
				"etcdcluster": "3.5.0"
			}`,
		},
		{
			name: "version with suffix",
			body: `{
				"etcdserver": "3.5.9-beta",
				"etcdcluster": "3.5.0"
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &EtcdFingerprinter{}
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

func TestEtcdFingerprinter_Fingerprint_NotEtcd(t *testing.T) {
	fp := &EtcdFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	// Valid JSON but not etcd format
	body := []byte(`{"status": "ok", "version": "1.0.0"}`)

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestBuildEtcdCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "3.5.9",
			expected: "cpe:2.3:a:etcd-io:etcd:3.5.9:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:etcd-io:etcd:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildEtcdCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEtcdFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &EtcdFingerprinter{}
	Register(fp)

	body := []byte(`{
		"etcdserver": "3.5.9",
		"etcdcluster": "3.5.0"
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
	assert.Equal(t, "etcd", results[0].Technology)
	assert.Equal(t, "3.5.9", results[0].Version)
}

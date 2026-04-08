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

func TestKubernetesFingerprinter_Name(t *testing.T) {
	fp := &KubernetesFingerprinter{}
	assert.Equal(t, "kubernetes", fp.Name())
}

func TestKubernetesFingerprinter_Match(t *testing.T) {
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
			fp := &KubernetesFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestKubernetesFingerprinter_Fingerprint_ValidK8s(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		expectedTech     string
		expectedVersion  string
		expectedCPE      string
		expectedMetadata map[string]any
	}{
		{
			name: "vanilla kubernetes v1.29.0",
			body: `{
				"major": "1",
				"minor": "29",
				"gitVersion": "v1.29.0",
				"gitCommit": "abc123",
				"gitTreeState": "clean",
				"buildDate": "2023-12-13T08:22:20Z",
				"goVersion": "go1.21.5",
				"compiler": "gc",
				"platform": "linux/amd64"
			}`,
			expectedTech:    "kubernetes",
			expectedVersion: "1.29.0",
			expectedCPE:     "cpe:2.3:a:kubernetes:kubernetes:1.29.0:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"platform":   "linux/amd64",
				"go_version": "go1.21.5",
				"git_commit": "abc123",
			},
		},
		{
			name: "k3s distribution",
			body: `{
				"major": "1",
				"minor": "28",
				"gitVersion": "v1.28.3+k3s1",
				"gitCommit": "def456",
				"gitTreeState": "clean",
				"buildDate": "2023-11-01T00:00:00Z",
				"goVersion": "go1.21.3",
				"compiler": "gc",
				"platform": "linux/arm64"
			}`,
			expectedTech:    "kubernetes",
			expectedVersion: "1.28.3",
			expectedCPE:     "cpe:2.3:a:kubernetes:kubernetes:1.28.3:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"platform":   "linux/arm64",
				"go_version": "go1.21.3",
				"git_commit": "def456",
			},
		},
		{
			name: "GKE distribution",
			body: `{
				"major": "1",
				"minor": "27",
				"gitVersion": "v1.27.8-gke.1067004",
				"gitCommit": "ghi789",
				"gitTreeState": "clean",
				"buildDate": "2023-10-15T00:00:00Z",
				"goVersion": "go1.20.10",
				"compiler": "gc",
				"platform": "linux/amd64"
			}`,
			expectedTech:    "kubernetes",
			expectedVersion: "1.27.8",
			expectedCPE:     "cpe:2.3:a:kubernetes:kubernetes:1.27.8:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"platform":   "linux/amd64",
				"go_version": "go1.20.10",
				"git_commit": "ghi789",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &KubernetesFingerprinter{}
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

func TestKubernetesFingerprinter_Fingerprint_InvalidJSON(t *testing.T) {
	fp := &KubernetesFingerprinter{}
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

func TestKubernetesFingerprinter_Fingerprint_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing gitVersion",
			body: `{
				"major": "1",
				"minor": "29",
				"platform": "linux/amd64"
			}`,
		},
		{
			name: "missing platform",
			body: `{
				"major": "1",
				"minor": "29",
				"gitVersion": "v1.29.0"
			}`,
		},
		{
			name: "empty gitVersion",
			body: `{
				"major": "1",
				"minor": "29",
				"gitVersion": "",
				"platform": "linux/amd64"
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &KubernetesFingerprinter{}
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

func TestKubernetesFingerprinter_Fingerprint_NotK8s(t *testing.T) {
	fp := &KubernetesFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	// Valid JSON but not Kubernetes format
	body := []byte(`{"status": "ok", "version": "1.0.0"}`)

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestBuildK8sCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "1.29.0",
			expected: "cpe:2.3:a:kubernetes:kubernetes:1.29.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildK8sCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKubernetesFingerprinter_Fingerprint_GrafanaFalsePositive(t *testing.T) {
	fp := &KubernetesFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	// Grafana's /version endpoint returns a response that matches the k8sVersionResponse
	// struct but with a non-standard gitTreeState (not "clean", "dirty", or "archive").
	// The fingerprinter must NOT detect this as Kubernetes.
	body := []byte(`{
		"major": "1",
		"minor": "32",
		"gitVersion": "1.32.0+grafana-v11.5.2",
		"gitTreeState": "grafana v11.5.2",
		"goVersion": "go1.23.5",
		"compiler": "gc",
		"platform": "linux/arm64"
	}`)

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result, "Grafana /version response must not be detected as Kubernetes")
	assert.Nil(t, err)
}

func TestKubernetesFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &KubernetesFingerprinter{}
	Register(fp)

	body := []byte(`{
		"major": "1",
		"minor": "29",
		"gitVersion": "v1.29.0",
		"gitCommit": "abc123",
		"gitTreeState": "clean",
		"buildDate": "2023-12-13T08:22:20Z",
		"goVersion": "go1.21.5",
		"compiler": "gc",
		"platform": "linux/amd64"
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
	assert.Equal(t, "kubernetes", results[0].Technology)
	assert.Equal(t, "1.29.0", results[0].Version)
}

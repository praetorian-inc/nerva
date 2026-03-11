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

func TestArtifactoryFingerprinter_Name(t *testing.T) {
	fp := &ArtifactoryFingerprinter{}
	assert.Equal(t, "artifactory", fp.Name())
}

func TestArtifactoryFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &ArtifactoryFingerprinter{}
	assert.Equal(t, "/artifactory/api/system/ping", fp.ProbeEndpoint())
}

func TestArtifactoryFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		headers     map[string]string
		expected    bool
	}{
		{
			name:        "matches X-Artifactory-Id header with HTML",
			contentType: "text/html",
			headers:     map[string]string{"X-Artifactory-Id": "abc123"},
			expected:    true,
		},
		{
			name:        "matches X-Artifactory-Node-Id header",
			contentType: "text/plain",
			headers:     map[string]string{"X-Artifactory-Node-Id": "node1"},
			expected:    true,
		},
		{
			name:        "matches X-JFrog-Version header",
			contentType: "text/plain",
			headers:     map[string]string{"X-JFrog-Version": "Artifactory/7.136.0 83600900"},
			expected:    true,
		},
		{
			name:        "does not match HTML without Artifactory headers",
			contentType: "text/html",
			expected:    false,
		},
		{
			name:        "does not match plain text without headers",
			contentType: "text/plain",
			expected:    false,
		},
		{
			name:        "does not match empty headers",
			contentType: "",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ArtifactoryFingerprinter{}
			header := http.Header{
				"Content-Type": []string{tt.contentType},
			}
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{
				Header: header,
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestArtifactoryFingerprinter_Fingerprint_ValidArtifactory(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		headers          map[string]string
		expectedTech     string
		expectedVersion  string
		expectedCPE      string
		expectedMetadata map[string]any
	}{
		{
			name: "Cloud instance with X-JFrog-Version header",
			body: "OK",
			headers: map[string]string{
				"X-JFrog-Version":       "Artifactory/7.136.0 83600900",
				"X-Artifactory-Id":      "abc123",
				"X-Artifactory-Node-Id": "node1",
				"Content-Type":          "text/plain",
			},
			expectedTech:    "artifactory",
			expectedVersion: "7.136.0",
			expectedCPE:     "cpe:2.3:a:jfrog:artifactory:7.136.0:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"node_id": "node1",
			},
		},
		{
			name: "On-prem instance with version header only",
			body: "OK",
			headers: map[string]string{
				"X-JFrog-Version":  "Artifactory/7.77.3 77703900",
				"X-Artifactory-Id": "def456",
				"Content-Type":     "text/plain",
			},
			expectedTech:     "artifactory",
			expectedVersion:  "7.77.3",
			expectedCPE:      "cpe:2.3:a:jfrog:artifactory:7.77.3:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ArtifactoryFingerprinter{}
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{
				StatusCode: 200,
				Header:     header,
				Body:       io.NopCloser(bytes.NewReader([]byte(tt.body))),
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

func TestArtifactoryFingerprinter_Fingerprint_HeaderOnly(t *testing.T) {
	fp := &ArtifactoryFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type":     []string{"text/html"},
			"X-Artifactory-Id": []string{"abc123"},
		},
	}

	body := []byte("<html><body>Not JSON</body></html>")

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "artifactory", result.Technology)
	assert.Equal(t, "", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:jfrog:artifactory:*:*:*:*:*:*:*:*")
}

func TestParseXJFrogVersion(t *testing.T) {
	tests := []struct {
		name            string
		jfrogVersion    string
		expectedVersion string
		shouldDetect    bool
	}{
		{
			name:            "full version with revision",
			jfrogVersion:    "Artifactory/7.136.0 83600900",
			expectedVersion: "7.136.0",
			shouldDetect:    true,
		},
		{
			name:            "version without revision",
			jfrogVersion:    "Artifactory/7.77.3",
			expectedVersion: "7.77.3",
			shouldDetect:    true,
		},
		{
			name:            "empty version after prefix",
			jfrogVersion:    "Artifactory/",
			expectedVersion: "",
			shouldDetect:    false,
		},
		{
			name:            "empty header",
			jfrogVersion:    "",
			expectedVersion: "",
			shouldDetect:    false,
		},
		{
			name:            "wrong prefix",
			jfrogVersion:    "NotArtifactory/1.0",
			expectedVersion: "",
			shouldDetect:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ArtifactoryFingerprinter{}
			header := http.Header{}
			if tt.jfrogVersion != "" {
				header.Set("X-JFrog-Version", tt.jfrogVersion)
			}
			resp := &http.Response{
				Header: header,
			}

			result, err := fp.Fingerprint(resp, []byte("OK"))

			require.NoError(t, err)
			if tt.shouldDetect {
				require.NotNil(t, result)
				assert.Equal(t, "artifactory", result.Technology)
				assert.Equal(t, tt.expectedVersion, result.Version)
			} else {
				assert.Nil(t, result)
			}
		})
	}
}

func TestBuildArtifactoryCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "7.77.3",
			expected: "cpe:2.3:a:jfrog:artifactory:7.77.3:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:jfrog:artifactory:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildArtifactoryCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestArtifactoryFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &ArtifactoryFingerprinter{}
	Register(fp)

	body := []byte("OK")

	header := http.Header{}
	header.Set("Content-Type", "text/plain")
	header.Set("X-JFrog-Version", "Artifactory/7.77.3 77703900")
	header.Set("X-Artifactory-Id", "test-instance-id")
	header.Set("X-Artifactory-Node-Id", "test-node-1")

	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1)
	assert.Equal(t, "artifactory", results[0].Technology)
	assert.Equal(t, "7.77.3", results[0].Version)
	assert.Equal(t, "test-node-1", results[0].Metadata["node_id"])
}

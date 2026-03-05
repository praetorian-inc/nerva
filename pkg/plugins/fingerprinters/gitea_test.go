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

func TestGiteaFingerprinter_Name(t *testing.T) {
	fp := &GiteaFingerprinter{}
	assert.Equal(t, "gitea", fp.Name())
}

func TestGiteaFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &GiteaFingerprinter{}
	assert.Equal(t, "/api/v1/version", fp.ProbeEndpoint())
}

func TestGiteaFingerprinter_Match(t *testing.T) {
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
			fp := &GiteaFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestGiteaFingerprinter_Fingerprint_ValidGitea(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		expectedTech    string
		expectedVersion string
		expectedCPE     string
		expectedRawVer  string
		expectedIsFork  bool
		expectedForkVer string
	}{
		{
			name:            "gitea 1.21.0",
			body:            `{"version":"1.21.0"}`,
			expectedTech:    "gitea",
			expectedVersion: "1.21.0",
			expectedCPE:     "cpe:2.3:a:gitea:gitea:1.21.0:*:*:*:*:*:*:*",
			expectedRawVer:  "1.21.0",
			expectedIsFork:  false,
		},
		{
			name:            "gitea v1.21.0 with v prefix",
			body:            `{"version":"v1.21.0"}`,
			expectedTech:    "gitea",
			expectedVersion: "1.21.0",
			expectedCPE:     "cpe:2.3:a:gitea:gitea:1.21.0:*:*:*:*:*:*:*",
			expectedRawVer:  "v1.21.0",
			expectedIsFork:  false,
		},
		{
			name:            "gitea 1.26.0 with dev suffix",
			body:            `{"version":"1.26.0+dev-489-gc9a038bc4e"}`,
			expectedTech:    "gitea",
			expectedVersion: "1.26.0",
			expectedCPE:     "cpe:2.3:a:gitea:gitea:1.26.0:*:*:*:*:*:*:*",
			expectedRawVer:  "1.26.0+dev-489-gc9a038bc4e",
			expectedIsFork:  false,
		},
		{
			name:            "codeberg fork version",
			body:            `{"version":"14.0.0-103-5e0b41b3+gitea-1.22.0"}`,
			expectedTech:    "gitea",
			expectedVersion: "1.22.0",
			expectedCPE:     "cpe:2.3:a:gitea:gitea:1.22.0:*:*:*:*:*:*:*",
			expectedRawVer:  "14.0.0-103-5e0b41b3+gitea-1.22.0",
			expectedIsFork:  true,
			expectedForkVer: "14.0.0",
		},
		{
			name:            "forgejo fork version",
			body:            `{"version":"7.0.0+gitea-1.21.0"}`,
			expectedTech:    "gitea",
			expectedVersion: "1.21.0",
			expectedCPE:     "cpe:2.3:a:gitea:gitea:1.21.0:*:*:*:*:*:*:*",
			expectedRawVer:  "7.0.0+gitea-1.21.0",
			expectedIsFork:  true,
			expectedForkVer: "7.0.0",
		},
		{
			name:            "gitea 1.20.5",
			body:            `{"version":"1.20.5"}`,
			expectedTech:    "gitea",
			expectedVersion: "1.20.5",
			expectedCPE:     "cpe:2.3:a:gitea:gitea:1.20.5:*:*:*:*:*:*:*",
			expectedRawVer:  "1.20.5",
			expectedIsFork:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GiteaFingerprinter{}
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

			// Check raw_version in metadata
			if tt.expectedRawVer != "" {
				assert.Equal(t, tt.expectedRawVer, result.Metadata["raw_version"])
			}

			// Check fork metadata
			if tt.expectedIsFork {
				assert.Equal(t, true, result.Metadata["is_fork"])
				assert.Equal(t, tt.expectedForkVer, result.Metadata["fork_version"])
			} else {
				// For non-forks, these fields should not be present
				_, hasFork := result.Metadata["is_fork"]
				assert.False(t, hasFork, "is_fork should not be present for non-fork versions")
			}
		})
	}
}

func TestGiteaFingerprinter_Fingerprint_InvalidJSON(t *testing.T) {
	fp := &GiteaFingerprinter{}
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

func TestGiteaFingerprinter_Fingerprint_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing version field",
			body: `{"status": "ok"}`,
		},
		{
			name: "empty version field",
			body: `{"version":""}`,
		},
		{
			name: "invalid version format - no digits",
			body: `{"version":"invalid"}`,
		},
		{
			name: "invalid version format - only one digit",
			body: `{"version":"1"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GiteaFingerprinter{}
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

func TestGiteaFingerprinter_Fingerprint_CPEInjection(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "CPE injection attempt with colon",
			body: `{"version":"1.0.0:*:*"}`,
		},
		{
			name: "CPE injection with special characters",
			body: `{"version":"1.0.0;rm -rf /"}`,
		},
		{
			name: "command injection attempt",
			body: `{"version":"1.0.0$(whoami)"}`,
		},
		{
			name: "path traversal attempt",
			body: `{"version":"../../etc/passwd"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GiteaFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			// Should reject malicious versions
			assert.Nil(t, result)
			assert.Nil(t, err)
		})
	}
}

func TestGiteaFingerprinter_Fingerprint_NotGitea(t *testing.T) {
	fp := &GiteaFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	// Valid JSON but not Gitea format
	body := []byte(`{"status": "ok", "app": "other"}`)

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestBuildGiteaCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "1.21.0",
			expected: "cpe:2.3:a:gitea:gitea:1.21.0:*:*:*:*:*:*:*",
		},
		{
			name:     "version with suffix",
			version:  "1.26.0",
			expected: "cpe:2.3:a:gitea:gitea:1.26.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildGiteaCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGiteaFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &GiteaFingerprinter{}
	Register(fp)

	body := []byte(`{"version":"1.21.0"}`)

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1)
	assert.Equal(t, "gitea", results[0].Technology)
	assert.Equal(t, "1.21.0", results[0].Version)
}

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

func TestGitLabFingerprinter_Name(t *testing.T) {
	fp := &GitLabFingerprinter{}
	assert.Equal(t, "gitlab", fp.Name())
}

func TestGitLabFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &GitLabFingerprinter{}
	assert.Equal(t, "/api/v4/version", fp.ProbeEndpoint())
}

func TestGitLabFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		headers     map[string]string
		expected    bool
	}{
		{
			name:     "matches X-GitLab header",
			headers:  map[string]string{"X-GitLab-Meta": "some-value"},
			expected: true,
		},
		{
			name:     "matches HTML content type",
			headers:  map[string]string{"Content-Type": "text/html; charset=utf-8"},
			expected: true,
		},
		{
			name:     "matches JSON content type",
			headers:  map[string]string{"Content-Type": "application/json"},
			expected: true,
		},
		{
			name:     "does not match plain text",
			headers:  map[string]string{"Content-Type": "text/plain"},
			expected: false,
		},
		{
			name:     "does not match empty headers",
			headers:  map[string]string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GitLabFingerprinter{}
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{Header: header}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestGitLabFingerprinter_Fingerprint_HTMLMeta(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		expectedVersion string
		expectedEdition string
		expectResult    bool
	}{
		{
			name: "GitLab CE with meta generator tag",
			body: `<html><head>
<meta content="GitLab" property="og:site_name">
<meta name="generator" content="GitLab Community Edition 17.0.0">
</head></html>`,
			expectedVersion: "17.0.0",
			expectedEdition: "ce",
			expectResult:    true,
		},
		{
			name: "GitLab EE with meta generator tag",
			body: `<html><head>
<meta content="GitLab" property="og:site_name">
<meta name="generator" content="GitLab Enterprise Edition 16.11.2">
</head></html>`,
			expectedVersion: "16.11.2",
			expectedEdition: "ee",
			expectResult:    true,
		},
		{
			name: "GitLab og:site_name meta only (no version)",
			body: `<html><head>
<meta content="GitLab" property="og:site_name">
</head></html>`,
			expectedVersion: "",
			expectedEdition: "",
			expectResult:    true,
		},
		{
			name: "Meta tag with single quotes",
			body: `<html><head>
<meta content="GitLab" property="og:site_name">
<meta name='generator' content='GitLab Community Edition 15.10.0'>
</head></html>`,
			expectedVersion: "15.10.0",
			expectedEdition: "ce",
			expectResult:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GitLabFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{"text/html; charset=utf-8"},
				},
				Body: io.NopCloser(bytes.NewReader([]byte(tt.body))),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			require.NoError(t, err)
			if tt.expectResult {
				require.NotNil(t, result)
				assert.Equal(t, "gitlab", result.Technology)
				assert.Equal(t, tt.expectedVersion, result.Version)
				if tt.expectedEdition != "" {
					assert.Equal(t, tt.expectedEdition, result.Metadata["edition"])
				}
			} else {
				assert.Nil(t, result)
			}
		})
	}
}

func TestGitLabFingerprinter_Fingerprint_APIVersion(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		expectedVersion string
		expectedEdition string
		expectedCPE     string
	}{
		{
			name:            "standard version",
			body:            `{"version":"17.0.0","revision":"abc123"}`,
			expectedVersion: "17.0.0",
			expectedEdition: "",
			expectedCPE:     "cpe:2.3:a:gitlab:gitlab:17.0.0:*:*:*:*:*:*:*",
		},
		{
			name:            "version with EE suffix",
			body:            `{"version":"17.0.0-ee","revision":"abc123"}`,
			expectedVersion: "17.0.0",
			expectedEdition: "ee",
			expectedCPE:     "cpe:2.3:a:gitlab:gitlab:17.0.0:*:*:*:ee:*:*:*",
		},
		{
			name:            "version with CE suffix",
			body:            `{"version":"16.8.1-ce","revision":"def456"}`,
			expectedVersion: "16.8.1",
			expectedEdition: "ce",
			expectedCPE:     "cpe:2.3:a:gitlab:gitlab:16.8.1:*:*:*:ce:*:*:*",
		},
		{
			name:            "version with revision",
			body:            `{"version":"17.0.0-ee","revision":"8f5a3b2c"}`,
			expectedVersion: "17.0.0",
			expectedEdition: "ee",
			expectedCPE:     "cpe:2.3:a:gitlab:gitlab:17.0.0:*:*:*:ee:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GitLabFingerprinter{}
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
			assert.Equal(t, "gitlab", result.Technology)
			assert.Equal(t, tt.expectedVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.expectedCPE)
			if tt.expectedEdition != "" {
				assert.Equal(t, tt.expectedEdition, result.Metadata["edition"])
			}
		})
	}
}

func TestGitLabFingerprinter_Fingerprint_Headers(t *testing.T) {
	fp := &GitLabFingerprinter{}
	header := http.Header{}
	header.Set("X-GitLab-Meta", "some-value")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader([]byte(""))),
	}

	result, err := fp.Fingerprint(resp, []byte(""))

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "gitlab", result.Technology)
}

func TestGitLabFingerprinter_Fingerprint_InvalidJSON(t *testing.T) {
	fp := &GitLabFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("not valid json"))),
	}

	result, err := fp.Fingerprint(resp, []byte("not valid json"))

	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestGitLabFingerprinter_Fingerprint_NotGitLab(t *testing.T) {
	fp := &GitLabFingerprinter{}
	body := []byte(`<html><head><title>Some Other App</title></head></html>`)
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"text/html"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestGitLabFingerprinter_Fingerprint_CPEInjection(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "version with colon (CPE injection)",
			body: `{"version":"17.0.0:*:*","revision":"abc"}`,
		},
		{
			name: "version with semicolon",
			body: `{"version":"17.0.0;rm -rf /","revision":"abc"}`,
		},
		{
			name: "command injection attempt",
			body: `{"version":"17.0.0$(whoami)","revision":"abc"}`,
		},
		{
			name: "path traversal attempt",
			body: `{"version":"../../etc/passwd","revision":"abc"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GitLabFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body: io.NopCloser(bytes.NewReader([]byte(tt.body))),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			assert.Nil(t, result)
			assert.Nil(t, err)
		})
	}
}

func TestBuildGitLabCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		edition  string
		expected string
	}{
		{
			name:     "CE version",
			version:  "17.0.0",
			edition:  "ce",
			expected: "cpe:2.3:a:gitlab:gitlab:17.0.0:*:*:*:ce:*:*:*",
		},
		{
			name:     "EE version",
			version:  "16.8.1",
			edition:  "ee",
			expected: "cpe:2.3:a:gitlab:gitlab:16.8.1:*:*:*:ee:*:*:*",
		},
		{
			name:     "unknown edition",
			version:  "17.0.0",
			edition:  "",
			expected: "cpe:2.3:a:gitlab:gitlab:17.0.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			edition:  "",
			expected: "cpe:2.3:a:gitlab:gitlab:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildGitLabCPE(tt.version, tt.edition)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGitLabFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	fp := &GitLabFingerprinter{}
	Register(fp)

	body := []byte(`{"version":"17.0.0-ee","revision":"abc123"}`)
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1)
	assert.Equal(t, "gitlab", results[0].Technology)
	assert.Equal(t, "17.0.0", results[0].Version)
	assert.Equal(t, "ee", results[0].Metadata["edition"])
}

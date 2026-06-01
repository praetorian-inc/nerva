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
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDockerRegistryFingerprinter_Name(t *testing.T) {
	fp := &DockerRegistryFingerprinter{}
	assert.Equal(t, "docker-registry", fp.Name())
}

func TestDockerRegistryFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &DockerRegistryFingerprinter{}
	assert.Equal(t, "/v2/", fp.ProbeEndpoint())
}

func TestDockerRegistryFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name:     "matches registry/2.0 header",
			headers:  map[string]string{"Docker-Distribution-Api-Version": "registry/2.0"},
			expected: true,
		},
		{
			name:     "matches header case-insensitively (REGISTRY/2.0)",
			headers:  map[string]string{"Docker-Distribution-Api-Version": "REGISTRY/2.0"},
			expected: true,
		},
		{
			name:     "does not match when header is absent",
			headers:  map[string]string{},
			expected: false,
		},
		{
			name:     "does not match wrong version (registry/1.0)",
			headers:  map[string]string{"Docker-Distribution-Api-Version": "registry/1.0"},
			expected: false,
		},
		{
			name:     "does not match unrelated header",
			headers:  map[string]string{"Server": "nginx"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &DockerRegistryFingerprinter{}
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{Header: header}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestDockerRegistryFingerprinter_Fingerprint_Valid(t *testing.T) {
	fp := &DockerRegistryFingerprinter{}
	header := http.Header{}
	header.Set("Docker-Distribution-Api-Version", "registry/2.0")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader([]byte(`{}`))),
	}

	result, err := fp.Fingerprint(resp, []byte(`{}`))

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "docker-registry", result.Technology)
	assert.Equal(t, "2.0", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:docker:registry:2.0:*:*:*:*:*:*:*")
	assert.Equal(t, "registry/2.0", result.Metadata["api_version"])
}

func TestDockerRegistryFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
	}{
		{
			name:    "no Docker-Distribution-Api-Version header",
			headers: map[string]string{},
		},
		{
			name:    "wrong header value",
			headers: map[string]string{"Docker-Distribution-Api-Version": "registry/1.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &DockerRegistryFingerprinter{}
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{
				StatusCode: 200,
				Header:     header,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{}`))),
			}

			result, err := fp.Fingerprint(resp, []byte(`{}`))

			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

func TestDockerRegistryFingerprinter_Fingerprint_SetsSeverity(t *testing.T) {
	fp := &DockerRegistryFingerprinter{}
	header := http.Header{}
	header.Set("Docker-Distribution-Api-Version", "registry/2.0")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader([]byte(`{}`))),
	}

	result, err := fp.Fingerprint(resp, []byte(`{}`))

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, plugins.SeverityCritical, result.Severity)
}

func TestDockerRegistryFingerprinter_CheckMisconfigs(t *testing.T) {
	tests := []struct {
		name             string
		statusCode       int
		responseBody     string
		expectFinding    bool
		expectedID       string
		expectedSeverity plugins.Severity
	}{
		{
			name:             "catalog accessible with repositories list",
			statusCode:       200,
			responseBody:     `{"repositories":["repo1","repo2"]}`,
			expectFinding:    true,
			expectedID:       "docker-registry-unauthenticated-catalog",
			expectedSeverity: plugins.SeverityCritical,
		},
		{
			name:             "catalog accessible with empty repositories array",
			statusCode:       200,
			responseBody:     `{"repositories":[]}`,
			expectFinding:    true,
			expectedID:       "docker-registry-unauthenticated-catalog",
			expectedSeverity: plugins.SeverityCritical,
		},
		{
			name:          "auth required (401)",
			statusCode:    401,
			responseBody:  `{"errors":[{"code":"UNAUTHORIZED"}]}`,
			expectFinding: false,
		},
		{
			name:          "non-JSON response",
			statusCode:    200,
			responseBody:  `not json`,
			expectFinding: false,
		},
		{
			name:          "missing repositories field",
			statusCode:    200,
			responseBody:  `{"other_field":"value"}`,
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statusCode := tt.statusCode
			responseBody := tt.responseBody
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v2/_catalog" {
					w.WriteHeader(statusCode)
					_, _ = w.Write([]byte(responseBody))
					return
				}
				w.WriteHeader(404)
			}))
			defer ts.Close()

			fp := &DockerRegistryFingerprinter{}
			findings := fp.CheckMisconfigs(ts.Client(), ts.URL, "")

			if tt.expectFinding {
				require.NotNil(t, findings)
				require.Len(t, findings, 1)
				assert.Equal(t, tt.expectedID, findings[0].ID)
				assert.Equal(t, tt.expectedSeverity, findings[0].Severity)
			} else {
				assert.Nil(t, findings)
			}
		})
	}
}

func TestDockerRegistryFingerprinter_Fingerprint_CPEInjection(t *testing.T) {
	fp := &DockerRegistryFingerprinter{}
	header := http.Header{}
	header.Set("Docker-Distribution-Api-Version", "registry/2.0:*:*:evil")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader([]byte(`{}`))),
	}

	result, err := fp.Fingerprint(resp, []byte(`{}`))

	require.NoError(t, err)
	require.NotNil(t, result)
	// Injection payload must not appear in the version or CPE
	assert.Equal(t, "*", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:docker:registry:*:*:*:*:*:*:*:*")
}

func TestBuildDockerRegistryCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "2.0",
			expected: "cpe:2.3:a:docker:registry:2.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version uses wildcard",
			version:  "",
			expected: "cpe:2.3:a:docker:registry:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildDockerRegistryCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

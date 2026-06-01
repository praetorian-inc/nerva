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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJenkinsFingerprinter_Name(t *testing.T) {
	fp := &JenkinsFingerprinter{}
	assert.Equal(t, "jenkins", fp.Name())
}

func TestJenkinsFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name:     "matches X-Jenkins header",
			headers:  map[string]string{"X-Jenkins": "2.541.1"},
			expected: true,
		},
		{
			name:     "matches X-Hudson header",
			headers:  map[string]string{"X-Hudson": "1.395"},
			expected: true,
		},
		{
			name:     "matches both X-Jenkins and X-Hudson headers",
			headers:  map[string]string{"X-Jenkins": "2.541.1", "X-Hudson": "1.395"},
			expected: true,
		},
		{
			name:     "does not match when neither header present",
			headers:  map[string]string{},
			expected: false,
		},
		{
			name:     "does not match unrelated headers",
			headers:  map[string]string{"X-Some-Other-Header": "value"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &JenkinsFingerprinter{}
			header := http.Header{}
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

func TestJenkinsFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name             string
		headers          map[string]string
		expectedTech     string
		expectedVersion  string
		expectedCPE      string
		expectedMetadata map[string]any
	}{
		{
			name: "Full headers (X-Jenkins and X-Hudson)",
			headers: map[string]string{
				"X-Jenkins": "2.541.1",
				"X-Hudson":  "1.395",
			},
			expectedTech:    "jenkins",
			expectedVersion: "2.541.1",
			expectedCPE:     "cpe:2.3:a:jenkins:jenkins:2.541.1:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"hudson_version": "1.395",
			},
		},
		{
			name: "X-Jenkins only",
			headers: map[string]string{
				"X-Jenkins": "2.479.2.3",
			},
			expectedTech:     "jenkins",
			expectedVersion:  "2.479.2.3",
			expectedCPE:      "cpe:2.3:a:jenkins:jenkins:2.479.2.3:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{},
		},
		{
			name: "X-Hudson only",
			headers: map[string]string{
				"X-Hudson": "1.395",
			},
			expectedTech:    "jenkins",
			expectedVersion: "",
			expectedCPE:     "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"hudson_version": "1.395",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &JenkinsFingerprinter{}
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{
				StatusCode: 200,
				Header:     header,
				Body:       io.NopCloser(bytes.NewReader([]byte(""))),
			}

			result, err := fp.Fingerprint(resp, []byte(""))

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, tt.expectedTech, result.Technology)
			assert.Equal(t, tt.expectedVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.expectedCPE)

			if len(tt.expectedMetadata) > 0 {
				for key, expectedValue := range tt.expectedMetadata {
					assert.Equal(t, expectedValue, result.Metadata[key], "metadata key: %s", key)
				}
			} else {
				assert.Empty(t, result.Metadata)
			}
		})
	}
}

func TestJenkinsFingerprinter_Fingerprint_NoHeaders(t *testing.T) {
	fp := &JenkinsFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
	}

	result, err := fp.Fingerprint(resp, []byte(""))

	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestBuildJenkinsCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "2.541.1",
			expected: "cpe:2.3:a:jenkins:jenkins:2.541.1:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildJenkinsCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJenkinsFingerprinter_Fingerprint_CPEInjection(t *testing.T) {
	tests := []struct {
		name            string
		headers         map[string]string
		expectNil       bool
		expectedVersion string
		expectedCPE     string
	}{
		{
			name:      "injection in X-Jenkins with no X-Hudson — returns nil (no valid signal)",
			headers:   map[string]string{"X-Jenkins": "2.0:*:*:evil"},
			expectNil: true,
		},
		{
			name: "injection in X-Jenkins with valid X-Hudson — result has empty version and wildcard CPE",
			headers: map[string]string{
				"X-Jenkins": "2.0:*:*:evil",
				"X-Hudson":  "1.395",
			},
			expectNil:       false,
			expectedVersion: "",
			expectedCPE:     "cpe:2.3:a:jenkins:jenkins:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &JenkinsFingerprinter{}
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{
				StatusCode: 200,
				Header:     header,
				Body:       io.NopCloser(bytes.NewReader([]byte(""))),
			}

			result, err := fp.Fingerprint(resp, []byte(""))

			require.NoError(t, err)
			if tt.expectNil {
				assert.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			assert.Equal(t, tt.expectedVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.expectedCPE)
		})
	}
}

func TestJenkinsFingerprinter_Integration(t *testing.T) {
	fp := &JenkinsFingerprinter{}

	body := []byte("")

	header := http.Header{}
	header.Set("X-Jenkins", "2.541.1")
	header.Set("X-Hudson", "1.395")
	header.Set("X-Jenkins-Session", "f55df8ea")

	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "jenkins", result.Technology)
	assert.Equal(t, "2.541.1", result.Version)
	assert.Equal(t, "1.395", result.Metadata["hudson_version"])
}

func TestJenkinsFingerprinter_Fingerprint_SetsSeverity(t *testing.T) {
	fp := &JenkinsFingerprinter{}
	header := http.Header{}
	header.Set("X-Jenkins", "2.541.1")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader([]byte(""))),
	}

	result, err := fp.Fingerprint(resp, []byte(""))

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "high", string(result.Severity))
}

func TestJenkinsFingerprinter_CheckMisconfigs(t *testing.T) {
	tests := []struct {
		name             string
		statusCode       int
		responseBody     string
		expectFinding    bool
		expectedID       string
		expectedSeverity string
	}{
		{
			name:       "script console accessible with crumb.init",
			statusCode: 200,
			responseBody: `<html><body><textarea name="script"></textarea>` +
				`<script>crumb.init("Jenkins-Crumb", "abc123")</script></body></html>`,
			expectFinding:    true,
			expectedID:       "jenkins-script-console",
			expectedSeverity: "critical",
		},
		{
			name:       "script console accessible with textarea and script",
			statusCode: 200,
			responseBody: `<html><body><textarea name="script">println "hello"</textarea>` +
				`<input name="script" type="hidden"/></body></html>`,
			expectFinding:    true,
			expectedID:       "jenkins-script-console",
			expectedSeverity: "critical",
		},
		{
			name:          "script console auth required (403)",
			statusCode:    403,
			responseBody:  `<html><body>Access Denied</body></html>`,
			expectFinding: false,
		},
		{
			name:          "non-Jenkins page at /script (200 but no indicators)",
			statusCode:    200,
			responseBody:  `<html><body><p>Hello World</p></body></html>`,
			expectFinding: false,
		},
		{
			name:          "server error (500)",
			statusCode:    500,
			responseBody:  `Internal Server Error`,
			expectFinding: false,
		},
		{
			name:          "non-Jenkins page with generic textarea and script tags",
			statusCode:    200,
			responseBody:  `<html><body><textarea name="content">some text</textarea><script>alert(1)</script></body></html>`,
			expectFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statusCode := tt.statusCode
			responseBody := tt.responseBody
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/script" {
					w.WriteHeader(statusCode)
					_, _ = w.Write([]byte(responseBody))
					return
				}
				w.WriteHeader(404)
			}))
			defer ts.Close()

			fp := &JenkinsFingerprinter{}
			findings := fp.CheckMisconfigs(ts.Client(), ts.URL, "")

			if tt.expectFinding {
				require.NotNil(t, findings)
				require.Len(t, findings, 1)
				assert.Equal(t, tt.expectedID, findings[0].ID)
				assert.Equal(t, tt.expectedSeverity, string(findings[0].Severity))
			} else {
				assert.Nil(t, findings)
			}
		})
	}
}

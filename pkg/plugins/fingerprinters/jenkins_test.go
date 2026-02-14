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
				"hudsonVersion": "1.395",
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
				"hudsonVersion": "1.395",
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

func TestJenkinsFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &JenkinsFingerprinter{}
	Register(fp)

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

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1)
	assert.Equal(t, "jenkins", results[0].Technology)
	assert.Equal(t, "2.541.1", results[0].Version)
	assert.Equal(t, "1.395", results[0].Metadata["hudsonVersion"])
}

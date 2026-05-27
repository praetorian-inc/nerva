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

func TestSplunkFingerprinter_Name(t *testing.T) {
	fp := &SplunkFingerprinter{}
	assert.Equal(t, "splunk", fp.Name())
}

func TestSplunkFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name     string
		headers  http.Header
		expected bool
	}{
		{
			name: "matches X-Splunk-Version header",
			headers: http.Header{
				"X-Splunk-Version": []string{"9.1.2"},
			},
			expected: true,
		},
		{
			name: "matches Server Splunkd header",
			headers: http.Header{
				"Server": []string{"Splunkd"},
			},
			expected: true,
		},
		{
			name: "matches Server Splunkd with version",
			headers: http.Header{
				"Server": []string{"Splunkd/9.1.2"},
			},
			expected: true,
		},
		{
			name: "does not match Server nginx",
			headers: http.Header{
				"Server": []string{"nginx/1.21.0"},
			},
			expected: false,
		},
		{
			name: "does not match no relevant headers",
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			expected: false,
		},
		{
			name: "does not match X-Powered-By Splunk (wrong header)",
			headers: http.Header{
				"X-Powered-By": []string{"Splunk"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SplunkFingerprinter{}
			resp := &http.Response{
				Header: tt.headers,
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestSplunkFingerprinter_Fingerprint_XSplunkVersion(t *testing.T) {
	fp := &SplunkFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Splunk-Version": []string{"9.1.2"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(""))),
	}

	result, err := fp.Fingerprint(resp, []byte(""))

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "splunk", result.Technology)
	assert.Equal(t, "9.1.2", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:splunk:splunk:9.1.2:*:*:*:*:*:*:*")
}

func TestSplunkFingerprinter_Fingerprint_ServerHeader(t *testing.T) {
	tests := []struct {
		name            string
		serverHeader    string
		expectedVersion string
		expectedCPE     string
	}{
		{
			name:            "Server: Splunkd/9.1.2",
			serverHeader:    "Splunkd/9.1.2",
			expectedVersion: "9.1.2",
			expectedCPE:     "cpe:2.3:a:splunk:splunk:9.1.2:*:*:*:*:*:*:*",
		},
		{
			name:            "Server: Splunkd/8.2.6",
			serverHeader:    "Splunkd/8.2.6",
			expectedVersion: "8.2.6",
			expectedCPE:     "cpe:2.3:a:splunk:splunk:8.2.6:*:*:*:*:*:*:*",
		},
		{
			name:            "Server: Splunkd (no version)",
			serverHeader:    "Splunkd",
			expectedVersion: "",
			expectedCPE:     "cpe:2.3:a:splunk:splunk:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SplunkFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Server": []string{tt.serverHeader},
				},
				Body: io.NopCloser(bytes.NewReader([]byte(""))),
			}

			result, err := fp.Fingerprint(resp, []byte(""))

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "splunk", result.Technology)
			assert.Equal(t, tt.expectedVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.expectedCPE)

			if tt.serverHeader != "" {
				assert.Equal(t, tt.serverHeader, result.Metadata["server"])
			}
		})
	}
}

func TestSplunkFingerprinter_Fingerprint_NoVersion(t *testing.T) {
	fp := &SplunkFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Server": []string{"Splunkd"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(""))),
	}

	result, err := fp.Fingerprint(resp, []byte(""))

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "splunk", result.Technology)
	assert.Equal(t, "", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:splunk:splunk:*:*:*:*:*:*:*:*")
}

func TestSplunkFingerprinter_Fingerprint_NoMatch(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
	}{
		{
			name: "nginx server",
			headers: http.Header{
				"Server": []string{"nginx/1.21.0"},
			},
		},
		{
			name: "no relevant headers",
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SplunkFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     tt.headers,
				Body:       io.NopCloser(bytes.NewReader([]byte(""))),
			}

			result, err := fp.Fingerprint(resp, []byte(""))

			assert.Nil(t, result)
			assert.Nil(t, err)
		})
	}
}

func TestSplunkFingerprinter_Fingerprint_InvalidVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{
			name:    "version with colon (CPE injection attempt)",
			version: "9.1.2:malicious:*",
		},
		{
			name:    "version with asterisk",
			version: "9.1.*",
		},
		{
			name:    "version without dots",
			version: "912",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SplunkFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"X-Splunk-Version": []string{tt.version},
				},
				Body: io.NopCloser(bytes.NewReader([]byte(""))),
			}

			result, err := fp.Fingerprint(resp, []byte(""))

			assert.Nil(t, result)
			assert.Nil(t, err)
		})
	}
}

func TestBuildSplunkCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "9.1.2",
			expected: "cpe:2.3:a:splunk:splunk:9.1.2:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:splunk:splunk:*:*:*:*:*:*:*:*",
		},
		{
			name:     "version 8.2.6",
			version:  "8.2.6",
			expected: "cpe:2.3:a:splunk:splunk:8.2.6:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildSplunkCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSplunkFingerprinter_Integration(t *testing.T) {
	fp := &SplunkFingerprinter{}

	body := []byte("")
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"X-Splunk-Version": []string{"9.1.2"},
			"Server":           []string{"Splunkd/9.1.2"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "splunk", result.Technology)
	assert.Equal(t, "9.1.2", result.Version)
}

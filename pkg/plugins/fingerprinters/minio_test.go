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

func TestMinIOFingerprinter_Name(t *testing.T) {
	fp := &MinIOFingerprinter{}
	assert.Equal(t, "minio", fp.Name())
}

func TestMinIOFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &MinIOFingerprinter{}
	assert.Equal(t, "/minio/health/live", fp.ProbeEndpoint())
}

func TestMinIOFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name      string
		serverHdr string
		expected  bool
	}{
		{
			name:      "matches Server header with MinIO",
			serverHdr: "MinIO",
			expected:  true,
		},
		{
			name:      "matches Server header with minio (lowercase)",
			serverHdr: "minio",
			expected:  true,
		},
		{
			name:      "matches Server header with MinIO version",
			serverHdr: "MinIO/RELEASE.2024-01-01T00-00-00Z",
			expected:  true,
		},
		{
			name:      "does not match Apache server",
			serverHdr: "Apache",
			expected:  false,
		},
		{
			name:      "does not match nginx server",
			serverHdr: "nginx",
			expected:  false,
		},
		{
			name:      "does not match empty server header",
			serverHdr: "",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MinIOFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     http.Header{},
			}
			if tt.serverHdr != "" {
				resp.Header.Set("Server", tt.serverHdr)
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestMinIOFingerprinter_Fingerprint_ValidMinIO(t *testing.T) {
	tests := []struct {
		name            string
		serverHeader    string
		expectedTech    string
		expectedVersion string
		expectedCPE     string
	}{
		{
			name:            "MinIO with version",
			serverHeader:    "MinIO/RELEASE.2024-01-01T00-00-00Z",
			expectedTech:    "minio",
			expectedVersion: "RELEASE.2024-01-01T00-00-00Z",
			expectedCPE:     "cpe:2.3:a:minio:minio:RELEASE.2024-01-01T00-00-00Z:*:*:*:*:*:*:*",
		},
		{
			name:            "MinIO with older version format",
			serverHeader:    "MinIO/RELEASE.2023-03-13T19-46-17Z",
			expectedTech:    "minio",
			expectedVersion: "RELEASE.2023-03-13T19-46-17Z",
			expectedCPE:     "cpe:2.3:a:minio:minio:RELEASE.2023-03-13T19-46-17Z:*:*:*:*:*:*:*",
		},
		{
			name:            "MinIO without version (modern)",
			serverHeader:    "MinIO",
			expectedTech:    "minio",
			expectedVersion: "*",
			expectedCPE:     "cpe:2.3:a:minio:minio:*:*:*:*:*:*:*:*",
		},
		{
			name:            "minio lowercase without version",
			serverHeader:    "minio",
			expectedTech:    "minio",
			expectedVersion: "*",
			expectedCPE:     "cpe:2.3:a:minio:minio:*:*:*:*:*:*:*:*",
		},
		{
			name:            "malicious Server header (no version extraction)",
			serverHeader:    "MinIO/evil:*:*:*:*:*:*:*",
			expectedTech:    "minio",
			expectedVersion: "*",
			expectedCPE:     "cpe:2.3:a:minio:minio:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MinIOFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Server": []string{tt.serverHeader},
				},
				Body: io.NopCloser(bytes.NewReader([]byte{})),
			}

			result, err := fp.Fingerprint(resp, []byte{})

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, tt.expectedTech, result.Technology)
			assert.Equal(t, tt.expectedVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.expectedCPE)

			// Check metadata includes raw server header
			assert.Equal(t, tt.serverHeader, result.Metadata["server_header"])
		})
	}
}

func TestMinIOFingerprinter_Fingerprint_NotMinIO(t *testing.T) {
	tests := []struct {
		name         string
		serverHeader string
	}{
		{
			name:         "Apache server",
			serverHeader: "Apache/2.4.41",
		},
		{
			name:         "nginx server",
			serverHeader: "nginx/1.21.0",
		},
		{
			name:         "empty server header",
			serverHeader: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MinIOFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     http.Header{},
			}
			if tt.serverHeader != "" {
				resp.Header.Set("Server", tt.serverHeader)
			}

			result, err := fp.Fingerprint(resp, []byte{})

			assert.Nil(t, result)
			assert.Nil(t, err)
		})
	}
}

func TestMinIOFingerprinter_Fingerprint_EmptyServerHeader(t *testing.T) {
	fp := &MinIOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader([]byte{})),
	}

	result, err := fp.Fingerprint(resp, []byte{})

	// Without Server header saying MinIO, should return nil
	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestBuildMinioCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "RELEASE.2024-01-01T00-00-00Z",
			expected: "cpe:2.3:a:minio:minio:RELEASE.2024-01-01T00-00-00Z:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version (wildcard)",
			version:  "",
			expected: "cpe:2.3:a:minio:minio:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildMinioCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMinIOFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &MinIOFingerprinter{}
	Register(fp)

	body := []byte{}

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Server": []string{"MinIO/RELEASE.2024-01-01T00-00-00Z"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1)
	assert.Equal(t, "minio", results[0].Technology)
	assert.Equal(t, "RELEASE.2024-01-01T00-00-00Z", results[0].Version)
}

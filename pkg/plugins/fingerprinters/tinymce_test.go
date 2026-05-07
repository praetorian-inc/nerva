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

func TestTinyMCEFingerprinter_Name(t *testing.T) {
	fp := &TinyMCEFingerprinter{}
	assert.Equal(t, "tinymce", fp.Name())
}

func TestTinyMCEFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{
			name:        "matches text/html content-type",
			contentType: "text/html; charset=utf-8",
			expected:    true,
		},
		{
			name:        "matches bare text/html",
			contentType: "text/html",
			expected:    true,
		},
		{
			name:        "does not match application/json",
			contentType: "application/json",
			expected:    false,
		},
		{
			name:        "does not match empty content-type",
			contentType: "",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TinyMCEFingerprinter{}
			header := http.Header{}
			if tt.contentType != "" {
				header.Set("Content-Type", tt.contentType)
			}
			resp := &http.Response{Header: header}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestTinyMCEFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		expectedVersion string
		expectedCPE     string
	}{
		{
			name:            "CDN URL with major version",
			body:            `<script src="https://cdn.tiny.cloud/1/no-api-key/tinymce/7/tinymce.min.js"></script>`,
			expectedVersion: "7",
			expectedCPE:     "cpe:2.3:a:tinymce:tinymce:7:*:*:*:*:*:*:*",
		},
		{
			name:            "CDN URL with version 6",
			body:            `<script src="https://cdn.tiny.cloud/1/abc123/tinymce/6/tinymce.min.js" referrerpolicy="origin"></script>`,
			expectedVersion: "6",
			expectedCPE:     "cpe:2.3:a:tinymce:tinymce:6:*:*:*:*:*:*:*",
		},
		{
			name:            "local path without version",
			body:            `<script src="/js/tinymce/tinymce.min.js"></script>`,
			expectedVersion: "",
			expectedCPE:     "cpe:2.3:a:tinymce:tinymce:*:*:*:*:*:*:*:*",
		},
		{
			name:            "multiple script refs - first with version wins",
			body:            `<script src="/assets/tinymce.js"></script><script src="https://cdn.tiny.cloud/1/key/tinymce/7/tinymce.min.js"></script>`,
			expectedVersion: "7",
			expectedCPE:     "cpe:2.3:a:tinymce:tinymce:7:*:*:*:*:*:*:*",
		},
		{
			name:            "path-based version tinymce-5.7.1",
			body:            `<script src="/vendor/tinymce-5.7.1/tinymce.min.js"></script>`,
			expectedVersion: "5.7.1",
			expectedCPE:     "cpe:2.3:a:tinymce:tinymce:5.7.1:*:*:*:*:*:*:*",
		},
		{
			name:            "path-based version tinymce/5.7.1",
			body:            `<script src="/lib/tinymce/5.7.1/tinymce.min.js"></script>`,
			expectedVersion: "5.7.1",
			expectedCPE:     "cpe:2.3:a:tinymce:tinymce:5.7.1:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TinyMCEFingerprinter{}
			header := http.Header{}
			header.Set("Content-Type", "text/html; charset=utf-8")
			resp := &http.Response{
				StatusCode: 200,
				Header:     header,
				Body:       io.NopCloser(bytes.NewReader([]byte(tt.body))),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "tinymce", result.Technology)
			assert.Equal(t, tt.expectedVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.expectedCPE)
		})
	}
}

func TestTinyMCEFingerprinter_Fingerprint_NoMatch(t *testing.T) {
	fp := &TinyMCEFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader([]byte("<html><body>No editor here</body></html>"))),
	}

	result, err := fp.Fingerprint(resp, []byte("<html><body>No editor here</body></html>"))

	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestBuildTinyMCECPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "full semver version",
			version:  "5.7.1",
			expected: "cpe:2.3:a:tinymce:tinymce:5.7.1:*:*:*:*:*:*:*",
		},
		{
			name:     "major-only version",
			version:  "7",
			expected: "cpe:2.3:a:tinymce:tinymce:7:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:tinymce:tinymce:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildTinyMCECPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// --- TinyMCEActiveFingerprinter tests ---

func TestTinyMCEActiveFingerprinter_Name(t *testing.T) {
	fp := &TinyMCEActiveFingerprinter{}
	assert.Equal(t, "tinymce-active", fp.Name())
}

func TestTinyMCEActiveFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &TinyMCEActiveFingerprinter{}
	assert.Equal(t, "/Scripts/tinymce/tinymce.min.js", fp.ProbeEndpoint())
}

func TestTinyMCEActiveFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		expected   bool
	}{
		{
			name:       "matches 200 OK",
			statusCode: http.StatusOK,
			expected:   true,
		},
		{
			name:       "does not match 404",
			statusCode: http.StatusNotFound,
			expected:   false,
		},
		{
			name:       "does not match 403",
			statusCode: http.StatusForbidden,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TinyMCEActiveFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: http.Header{}}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestTinyMCEActiveFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		expectedVersion string
		expectedCPE     string
	}{
		{
			name:            "majorVersion and minorVersion with double quotes (equals sign style)",
			body:            `var a={majorVersion="5",minorVersion="7.1",revision="0"};`,
			expectedVersion: "5.7.1",
			expectedCPE:     "cpe:2.3:a:tinymce:tinymce:5.7.1:*:*:*:*:*:*:*",
		},
		{
			name:            "majorVersion and minorVersion with single quotes (colon style)",
			body:            `{majorVersion:'6',minorVersion:'8.1',revision:'0'}`,
			expectedVersion: "6.8.1",
			expectedCPE:     "cpe:2.3:a:tinymce:tinymce:6.8.1:*:*:*:*:*:*:*",
		},
		{
			name:            "majorVersion and minorVersion with double quotes (colon style - production format)",
			body:            `{majorVersion:"5",minorVersion:"7.1",revision:"0"}`,
			expectedVersion: "5.7.1",
			expectedCPE:     "cpe:2.3:a:tinymce:tinymce:5.7.1:*:*:*:*:*:*:*",
		},
		{
			name:            "semver fallback in first 5000 bytes",
			body:            `/* TinyMCE 5.10.2 */var t={};`,
			expectedVersion: "5.10.2",
			expectedCPE:     "cpe:2.3:a:tinymce:tinymce:5.10.2:*:*:*:*:*:*:*",
		},
		{
			name:            "no version found in body",
			body:            `var tinymce={};`,
			expectedVersion: "",
			expectedCPE:     "cpe:2.3:a:tinymce:tinymce:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TinyMCEActiveFingerprinter{}
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewReader([]byte(tt.body))),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "tinymce", result.Technology)
			assert.Equal(t, tt.expectedVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.expectedCPE)
		})
	}
}

// --- TinyMCEAltPathFingerprinter tests ---

func TestTinyMCEAltPathFingerprinter_Name(t *testing.T) {
	fp := &TinyMCEAltPathFingerprinter{}
	assert.Equal(t, "tinymce-alt-path", fp.Name())
}

func TestTinyMCEAltPathFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &TinyMCEAltPathFingerprinter{}
	assert.Equal(t, "/tinymce/tinymce.min.js", fp.ProbeEndpoint())
}

func TestTinyMCEAltPathFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		expected   bool
	}{
		{
			name:       "matches 200 OK",
			statusCode: http.StatusOK,
			expected:   true,
		},
		{
			name:       "does not match 404",
			statusCode: http.StatusNotFound,
			expected:   false,
		},
		{
			name:       "does not match 500",
			statusCode: http.StatusInternalServerError,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TinyMCEAltPathFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: http.Header{}}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestTinyMCEAltPathFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		expectedVersion string
		expectedCPE     string
	}{
		{
			name:            "majorVersion and minorVersion with double quotes (equals sign style)",
			body:            `var a={majorVersion="5",minorVersion="7.1",revision="0"};`,
			expectedVersion: "5.7.1",
			expectedCPE:     "cpe:2.3:a:tinymce:tinymce:5.7.1:*:*:*:*:*:*:*",
		},
		{
			name:            "majorVersion and minorVersion with single quotes (colon style)",
			body:            `{majorVersion:'6',minorVersion:'8.1',revision:'0'}`,
			expectedVersion: "6.8.1",
			expectedCPE:     "cpe:2.3:a:tinymce:tinymce:6.8.1:*:*:*:*:*:*:*",
		},
		{
			name:            "majorVersion and minorVersion with double quotes (colon style - production format)",
			body:            `{majorVersion:"5",minorVersion:"7.1",revision:"0"}`,
			expectedVersion: "5.7.1",
			expectedCPE:     "cpe:2.3:a:tinymce:tinymce:5.7.1:*:*:*:*:*:*:*",
		},
		{
			name:            "semver fallback in first 5000 bytes",
			body:            `/* TinyMCE 5.10.2 */var t={};`,
			expectedVersion: "5.10.2",
			expectedCPE:     "cpe:2.3:a:tinymce:tinymce:5.10.2:*:*:*:*:*:*:*",
		},
		{
			name:            "no version found in body",
			body:            `var tinymce={};`,
			expectedVersion: "",
			expectedCPE:     "cpe:2.3:a:tinymce:tinymce:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TinyMCEAltPathFingerprinter{}
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(bytes.NewReader([]byte(tt.body))),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "tinymce", result.Technology)
			assert.Equal(t, tt.expectedVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.expectedCPE)
		})
	}
}

func TestTinyMCEFingerprinter_Integration(t *testing.T) {
	// Save and restore global registry to avoid test pollution
	original := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = original })
	httpFingerprinters = nil

	fp := &TinyMCEFingerprinter{}
	Register(fp)

	body := []byte(`<!DOCTYPE html><html><head>
<script src="https://cdn.tiny.cloud/1/no-api-key/tinymce/7/tinymce.min.js" referrerpolicy="origin"></script>
</head><body><textarea id="editor"></textarea></body></html>`)

	header := http.Header{}
	header.Set("Content-Type", "text/html; charset=utf-8")

	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1)
	assert.Equal(t, "tinymce", results[0].Technology)
	assert.Equal(t, "7", results[0].Version)
	assert.Contains(t, results[0].CPEs, "cpe:2.3:a:tinymce:tinymce:7:*:*:*:*:*:*:*")
}

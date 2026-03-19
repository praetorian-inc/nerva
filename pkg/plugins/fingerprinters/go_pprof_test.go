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

func TestGoPprofFingerprinter_Name(t *testing.T) {
	fp := &GoPprofFingerprinter{}
	assert.Equal(t, "go_pprof", fp.Name())
}

func TestGoPprofFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &GoPprofFingerprinter{}
	assert.Equal(t, "/debug/pprof/", fp.ProbeEndpoint())
}

func TestGoPprofFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		statusCode int
		expected   bool
	}{
		{
			name:       "matches 200 with text/html (probe response candidate)",
			headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
			statusCode: 200,
			expected:   true,
		},
		{
			name:       "matches 200 with text/html without charset",
			headers:    map[string]string{"Content-Type": "text/html"},
			statusCode: 200,
			expected:   true,
		},
		{
			name:       "does not match 404",
			headers:    map[string]string{"Content-Type": "text/html"},
			statusCode: 404,
			expected:   false,
		},
		{
			name:       "does not match 200 with application/json",
			headers:    map[string]string{"Content-Type": "application/json"},
			statusCode: 200,
			expected:   false,
		},
		{
			name:       "does not match 200 with no content-type",
			headers:    map[string]string{},
			statusCode: 200,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GoPprofFingerprinter{}
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     header,
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestGoPprofFingerprinter_Fingerprint_PprofPage(t *testing.T) {
	body := []byte(`<html>
<head>
<title>/debug/pprof/</title>
</head>
<body>
/debug/pprof/<br>
<br>
Types of profiles available:
<table>
<tr><td align=right>0<td><a href="goroutine?debug=2">goroutine</a>
<tr><td align=right>0<td><a href="heap?debug=1">heap</a>
<tr><td align=right>0<td><a href="threadcreate?debug=1">threadcreate</a>
<tr><td align=right>0<td><a href="block?debug=1">block</a>
<tr><td align=right>0<td><a href="allocs?debug=1">allocs</a>
<tr><td align=right>0<td><a href="mutex?debug=1">mutex</a>
</table>
<a href="goroutine?debug=2">full goroutine stack dump</a>
</body>
</html>`)

	fp := &GoPprofFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html; charset=utf-8")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "go_pprof", result.Technology)
	assert.NotEmpty(t, result.CPEs)
	assert.Contains(t, result.CPEs[0], "cpe:2.3:a:golang:go:")

	// Check that exposedProfiles metadata contains expected profiles
	if profiles, ok := result.Metadata["exposed_profiles"]; ok {
		profileList := profiles.([]string)
		assert.Contains(t, profileList, "goroutine")
		assert.Contains(t, profileList, "heap")
		assert.Contains(t, profileList, "threadcreate")
		assert.Contains(t, profileList, "block")
		assert.Contains(t, profileList, "allocs")
		assert.Contains(t, profileList, "mutex")
	}
}

func TestGoPprofFingerprinter_Fingerprint_WithVersion(t *testing.T) {
	body := []byte(`<html>
<head>
<title>/debug/pprof/</title>
</head>
<body>
/debug/pprof/<br>
<br>
Types of profiles available:
<table>
<tr><td align=right>0<td><a href="goroutine?debug=2">goroutine</a>
<tr><td align=right>0<td><a href="heap?debug=1">heap</a>
</table>
<p>
Profile Coverage: go1.21.5
</p>
</body>
</html>`)

	fp := &GoPprofFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html; charset=utf-8")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "go_pprof", result.Technology)
	assert.Equal(t, "1.21.5", result.Version)
	assert.Contains(t, result.CPEs[0], "cpe:2.3:a:golang:go:1.21.5:")
}

func TestGoPprofFingerprinter_Fingerprint_NoMatch(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		body    []byte
		status  int
	}{
		{
			name:    "generic HTML page",
			headers: map[string]string{"Content-Type": "text/html"},
			body:    []byte(`<html><body><h1>Welcome</h1></body></html>`),
			status:  200,
		},
		{
			name:    "JSON response",
			headers: map[string]string{"Content-Type": "application/json"},
			body:    []byte(`{"status":"ok"}`),
			status:  200,
		},
		{
			name:    "empty body",
			headers: map[string]string{"Content-Type": "text/html"},
			body:    []byte(``),
			status:  200,
		},
		{
			name:    "pprof-like but missing key indicator",
			headers: map[string]string{"Content-Type": "text/html"},
			body:    []byte(`<html><body>Some profiles: <a href="profile">profile</a></body></html>`),
			status:  200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GoPprofFingerprinter{}
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{
				StatusCode: tt.status,
				Header:     header,
				Body:       io.NopCloser(bytes.NewReader(tt.body)),
			}

			result, err := fp.Fingerprint(resp, tt.body)

			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

func TestBuildGoPprofCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "version 1.21.5",
			version:  "1.21.5",
			expected: "cpe:2.3:a:golang:go:1.21.5:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version uses wildcard",
			version:  "",
			expected: "cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildGoPprofCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGoPprofFingerprinter_Integration(t *testing.T) {
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	// Register explicitly for the test
	fp := &GoPprofFingerprinter{}
	Register(fp)

	body := []byte(`<html>
<head>
<title>/debug/pprof/</title>
</head>
<body>
/debug/pprof/<br>
<br>
Types of profiles available:
<table>
<tr><td align=right>0<td><a href="goroutine?debug=2">goroutine</a>
<tr><td align=right>0<td><a href="heap?debug=1">heap</a>
</table>
</body>
</html>`)

	header := http.Header{}
	header.Set("Content-Type", "text/html; charset=utf-8")

	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1)
	assert.Equal(t, "go_pprof", results[0].Technology)
}

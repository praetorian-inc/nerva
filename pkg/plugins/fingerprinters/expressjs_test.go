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

func TestExpressFingerprinter_Name(t *testing.T) {
	fp := &ExpressFingerprinter{}
	assert.Equal(t, "expressjs", fp.Name())
}

func TestExpressFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &ExpressFingerprinter{}
	assert.Equal(t, "/nerva-fp-nonexistent-path", fp.ProbeEndpoint())
}

func TestExpressFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		statusCode int
		expected   bool
	}{
		{
			name:       "matches X-Powered-By: Express header",
			headers:    map[string]string{"X-Powered-By": "Express"},
			statusCode: 200,
			expected:   true,
		},
		{
			name:       "matches X-Powered-By: Express header on 404",
			headers:    map[string]string{"X-Powered-By": "Express"},
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "matches 404 with text/html content type (probe response candidate)",
			headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "matches 404 with text/html content type without charset",
			headers:    map[string]string{"Content-Type": "text/html"},
			statusCode: 404,
			expected:   true,
		},
		{
			name:       "does not match 404 with non-html content type",
			headers:    map[string]string{"Content-Type": "application/json"},
			statusCode: 404,
			expected:   false,
		},
		{
			name:       "does not match 200 with no Express headers",
			headers:    map[string]string{"Content-Type": "text/html"},
			statusCode: 200,
			expected:   false,
		},
		{
			name:       "does not match when no relevant headers present",
			headers:    map[string]string{"Server": "nginx"},
			statusCode: 200,
			expected:   false,
		},
		{
			name:       "does not match X-Powered-By with other value",
			headers:    map[string]string{"X-Powered-By": "PHP/8.0"},
			statusCode: 200,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ExpressFingerprinter{}
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

func TestExpressFingerprinter_Fingerprint_XPoweredBy(t *testing.T) {
	fp := &ExpressFingerprinter{}
	header := http.Header{}
	header.Set("X-Powered-By", "Express")
	header.Set("Content-Type", "text/html; charset=utf-8")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader([]byte("<html>Hello World</html>"))),
	}

	result, err := fp.Fingerprint(resp, []byte("<html>Hello World</html>"))

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "expressjs", result.Technology)
	assert.Equal(t, "Express", result.Metadata["poweredBy"])
	assert.NotEmpty(t, result.CPEs)
	assert.Contains(t, result.CPEs[0], "cpe:2.3:a:expressjs:express:")
}

func TestExpressFingerprinter_Fingerprint_ErrorPage(t *testing.T) {
	body := []byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /nerva-fp-nonexistent-path</pre>
</body>
</html>`)

	fp := &ExpressFingerprinter{}
	header := http.Header{}
	header.Set("X-Powered-By", "Express")
	header.Set("Content-Type", "text/html; charset=utf-8")
	resp := &http.Response{
		StatusCode: 404,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "expressjs", result.Technology)
	assert.NotEmpty(t, result.CPEs)
}

func TestExpressFingerprinter_Fingerprint_ErrorPageOnlyBodySignal(t *testing.T) {
	// Test detection via body "Cannot GET /" pattern without X-Powered-By header
	// This simulates when only the probe response body confirms Express
	body := []byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /nerva-fp-nonexistent-path</pre>
</body>
</html>`)

	fp := &ExpressFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html; charset=utf-8")
	resp := &http.Response{
		StatusCode: 404,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "expressjs", result.Technology)
}

func TestExpressFingerprinter_Fingerprint_DevMode(t *testing.T) {
	// Express dev mode returns stack traces in error responses
	body := []byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>NotFoundError: Not Found<br> &nbsp; &nbsp;at /app/node_modules/express/lib/router/index.js:12:15<br> &nbsp; &nbsp;at Function.handle (/app/node_modules/express@4.21.0/lib/router/index.js:234:3)</pre>
</body>
</html>`)

	fp := &ExpressFingerprinter{}
	header := http.Header{}
	header.Set("X-Powered-By", "Express")
	header.Set("Content-Type", "text/html; charset=utf-8")
	resp := &http.Response{
		StatusCode: 500,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "expressjs", result.Technology)
	assert.Equal(t, true, result.Metadata["devMode"])
}

func TestExpressFingerprinter_Fingerprint_VersionExtraction(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		headers         map[string]string
		expectedVersion string
	}{
		{
			name: "version from express@ in stack trace",
			body: `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>NotFoundError: Not Found<br>    at Function.handle (/app/node_modules/express@4.21.0/lib/router/index.js:234:3)</pre>
</body>
</html>`,
			headers: map[string]string{
				"X-Powered-By": "Express",
				"Content-Type": "text/html; charset=utf-8",
			},
			expectedVersion: "4.21.0",
		},
		{
			name: "no version available",
			body: `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /nerva-fp-nonexistent-path</pre>
</body>
</html>`,
			headers: map[string]string{
				"X-Powered-By": "Express",
				"Content-Type": "text/html; charset=utf-8",
			},
			expectedVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ExpressFingerprinter{}
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{
				StatusCode: 404,
				Header:     header,
				Body:       io.NopCloser(bytes.NewReader([]byte(tt.body))),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, tt.expectedVersion, result.Version)
		})
	}
}

func TestExpressFingerprinter_Fingerprint_NoMatch(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		body    []byte
		status  int
	}{
		{
			name:    "generic 404 not Express",
			headers: map[string]string{"Content-Type": "text/html"},
			body:    []byte(`<html><body><h1>404 Not Found</h1></body></html>`),
			status:  404,
		},
		{
			name:    "nginx 404 page",
			headers: map[string]string{"Server": "nginx", "Content-Type": "text/html"},
			body:    []byte(`<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1></body></html>`),
			status:  404,
		},
		{
			name:    "200 OK with no Express indicators",
			headers: map[string]string{"Content-Type": "text/html"},
			body:    []byte(`<html><body>Hello</body></html>`),
			status:  200,
		},
		{
			name:    "JSON 404 response",
			headers: map[string]string{"Content-Type": "application/json"},
			body:    []byte(`{"error":"not found"}`),
			status:  404,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ExpressFingerprinter{}
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

func TestBuildExpressCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "version 4.21.0",
			version:  "4.21.0",
			expected: "cpe:2.3:a:expressjs:express:4.21.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version uses wildcard",
			version:  "",
			expected: "cpe:2.3:a:expressjs:express:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildExpressCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExpressFingerprinter_Integration(t *testing.T) {
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	// Register explicitly for the test
	fp := &ExpressFingerprinter{}
	Register(fp)

	body := []byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /nerva-fp-nonexistent-path</pre>
</body>
</html>`)

	header := http.Header{}
	header.Set("X-Powered-By", "Express")
	header.Set("Content-Type", "text/html; charset=utf-8")

	resp := &http.Response{
		StatusCode: 404,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1)
	assert.Equal(t, "expressjs", results[0].Technology)
	assert.Equal(t, "Express", results[0].Metadata["poweredBy"])
}

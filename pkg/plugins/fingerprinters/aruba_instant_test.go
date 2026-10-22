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
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ HTTPFingerprinter = (*ArubaInstantFingerprinter)(nil)

func TestArubaInstantFingerprinter_Name(t *testing.T) {
	fp := &ArubaInstantFingerprinter{}
	assert.Equal(t, "aruba-instant", fp.Name())
}

func TestArubaInstantFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		statusCode int
		expected   bool
	}{
		{
			name:       "matches HTML content type",
			headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
			statusCode: 200,
			expected:   true,
		},
		{
			name:       "matches HTML with 401",
			headers:    map[string]string{"Content-Type": "text/html"},
			statusCode: 401,
			expected:   true,
		},
		{
			name:       "rejects 500 server error",
			headers:    map[string]string{"Content-Type": "text/html"},
			statusCode: 500,
			expected:   false,
		},
		{
			name:       "rejects JSON content type",
			headers:    map[string]string{"Content-Type": "application/json"},
			statusCode: 200,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ArubaInstantFingerprinter{}
			assert.Equal(t, tt.expected, fp.Match(newHTMLHeadersResp(tt.statusCode, tt.headers)))
		})
	}
}

func TestArubaInstantFingerprinter_Fingerprint(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		headers    map[string]string
		body       string
		wantNil    bool
		wantTech   string
		wantCPE    string
	}{
		{
			name:       "identifies Instant login with swarm.cgi and Instant title",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body: `<html>
<head><title>Aruba Instant</title>
<script src="jscripts/third_party/raphael-treemap.min.js"></script>
</head>
<body>
<form action="/swarm.cgi" method="post">Login</form>
</body>
</html>`,
			wantTech: "aruba-instant",
			wantCPE:  "cpe:2.3:o:arubanetworks:instant:*:*:*:*:*:*:*:*",
		},
		{
			name:       "identifies Instant Access Point title with Instant JS",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body: `<html>
<head><title>Instant Access Point</title></head>
<body>
<script src="jscripts/third_party/highcharts.src.js"></script>
<p>instant.arubanetworks.com</p>
</body>
</html>`,
			wantTech: "aruba-instant",
			wantCPE:  "cpe:2.3:o:arubanetworks:instant:*:*:*:*:*:*:*:*",
		},
		{
			name:       "two exclusive Instant signals without brand token still identify",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body: `<html><body>
<form action="/swarm.cgi" method="post"></form>
<script src="jscripts/third_party/raphael-treemap.min.js"></script>
</body></html>`,
			wantTech: "aruba-instant",
			wantCPE:  "cpe:2.3:o:arubanetworks:instant:*:*:*:*:*:*:*:*",
		},
		{
			name:       "generic HTML does not emit Instant identity",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>Welcome</title></head><body>Hello World</body></html>`,
			wantNil:    true,
		},
		{
			name:       "Apache default page does not emit Instant identity",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>Apache2 Ubuntu Default Page</title></head><body><h1>It works!</h1></body></html>`,
			wantNil:    true,
		},
		{
			name:       "empty body does not emit Instant identity",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       "",
			wantNil:    true,
		},
		{
			name:       "single exclusive Instant signal without Aruba corroboration is rejected",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><body><form action="/swarm.cgi" method="post"></form></body></html>`,
			wantNil:    true,
		},
		{
			name:       "Aruba brand mention without Instant exclusive signal is rejected",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>Best APs 2024</title></head><body><p>Aruba Networks makes campus Wi-Fi.</p></body></html>`,
			wantNil:    true,
		},
		{
			name:       "Aruba AirWave management UI is not Instant",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>AirWave Management Platform</title></head><body>Aruba AirWave login</body></html>`,
			wantNil:    true,
		},
		{
			name:       "link to instant.arubanetworks.com without Instant title or UI JS is rejected",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>Campus Wi-Fi</title></head><body><a href="https://instant.arubanetworks.com/swarm.cgi">Aruba captive portal</a></body></html>`,
			wantNil:    true,
		},
		{
			name:       "favicon aruba-networks page without Instant markers is rejected",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><link rel="icon" href="/favicon.ico"></head><body>aruba-networks</body></html>`,
			wantNil:    true,
		},
		{
			name:       "500 with Instant body is rejected",
			statusCode: 500,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>Aruba Instant</title></head><body><form action="/swarm.cgi"></form></body></html>`,
			wantNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ArubaInstantFingerprinter{}
			result, err := fp.Fingerprint(newHTMLHeadersResp(tt.statusCode, tt.headers), []byte(tt.body))
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			assert.Equal(t, tt.wantTech, result.Technology)
			require.NotEmpty(t, result.CPEs)
			assert.Equal(t, tt.wantCPE, result.CPEs[0])
		})
	}
}

func newHTMLHeadersResp(status int, headers map[string]string) *http.Response {
	header := http.Header{}
	for k, v := range headers {
		header.Set(k, v)
	}
	return &http.Response{StatusCode: status, Header: header}
}

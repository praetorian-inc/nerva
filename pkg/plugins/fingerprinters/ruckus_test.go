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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ HTTPFingerprinter = (*RuckusFingerprinter)(nil)

func TestRuckusFingerprinter_Name(t *testing.T) {
	fp := &RuckusFingerprinter{}
	assert.Equal(t, "ruckus", fp.Name())
}

func TestRuckusFingerprinter_Match(t *testing.T) {
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
			fp := &RuckusFingerprinter{}
			assert.Equal(t, tt.expected, fp.Match(newHTMLHeadersResp(tt.statusCode, tt.headers)))
		})
	}
}

func TestRuckusFingerprinter_Fingerprint(t *testing.T) {
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
			name:       "identifies Unleashed login panel",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body: `<html>
<head><title>Unleashed Login</title>
<link href="css/font-awesome.min.css?200.15" rel="stylesheet">
</head>
<body>
<form action="/admin/login.jsp">Login</form>
</body>
</html>`,
			wantTech: "ruckus",
			wantCPE:  "cpe:2.3:o:ruckuswireless:unleashed_firmware:*:*:*:*:*:*:*:*",
		},
		{
			name:       "identifies ZoneDirector admin login",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body: `<html>
<head><title>Ruckus Wireless Admin</title></head>
<body>
<form action="/admin/login.jsp" method="post">
<input name="username"><input name="password">
</form>
<p>ZoneDirector</p>
</body>
</html>`,
			wantTech: "ruckus",
			wantCPE:  "cpe:2.3:o:ruckuswireless:zonedirector_firmware:*:*:*:*:*:*:*:*",
		},
		{
			name:       "identifies SmartZone management UI",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body: `<html>
<head><title>Ruckus SmartZone</title></head>
<body>
<a href="/wsg/login">SmartZone Login</a>
</body>
</html>`,
			wantTech: "ruckus",
			wantCPE:  "cpe:2.3:a:ruckuswireless:smartzone:*:*:*:*:*:*:*:*",
		},
		{
			name:       "identifies Ruckus Wireless Admin title without ZoneDirector token",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body: `<html>
<head><title>Ruckus Wireless Admin</title></head>
<body>
<form action="/admin/login.jsp" method="post"></form>
</body>
</html>`,
			wantTech: "ruckus",
			wantCPE:  "cpe:2.3:o:ruckuswireless:zonedirector_firmware:*:*:*:*:*:*:*:*",
		},
		{
			name:       "generic HTML does not emit Ruckus identity",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>Welcome</title></head><body>Hello World</body></html>`,
			wantNil:    true,
		},
		{
			name:       "Apache default page does not emit Ruckus identity",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>Apache2 Ubuntu Default Page</title></head><body><h1>It works!</h1></body></html>`,
			wantNil:    true,
		},
		{
			name:       "empty body does not emit Ruckus identity",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       "",
			wantNil:    true,
		},
		{
			name:       "zonedirector without Ruckus corroboration is rejected",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>Admin</title></head><body><p>ZoneDirector</p></body></html>`,
			wantNil:    true,
		},
		{
			name:       "Ruckus brand mention without exclusive management signal is rejected",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>Best APs 2024</title></head><body><p>Ruckus Wireless makes indoor APs.</p></body></html>`,
			wantNil:    true,
		},
		{
			name:       "generic JSP login path without Ruckus markers is rejected",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>Admin</title></head><body><form action="/admin/login.jsp"></form></body></html>`,
			wantNil:    true,
		},
		{
			name:       "500 with Unleashed body is rejected",
			statusCode: 500,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>Unleashed Login</title></head></html>`,
			wantNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &RuckusFingerprinter{}
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

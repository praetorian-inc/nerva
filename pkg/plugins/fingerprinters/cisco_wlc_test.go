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

var _ HTTPFingerprinter = (*CiscoWLCFingerprinter)(nil)

func TestCiscoWLCFingerprinter_Name(t *testing.T) {
	fp := &CiscoWLCFingerprinter{}
	assert.Equal(t, "cisco-wlc", fp.Name())
}

func TestCiscoWLCFingerprinter_Match(t *testing.T) {
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
			fp := &CiscoWLCFingerprinter{}
			assert.Equal(t, tt.expected, fp.Match(newHTMLHeadersResp(tt.statusCode, tt.headers)))
		})
	}
}

func TestCiscoWLCFingerprinter_Fingerprint(t *testing.T) {
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
			name:       "identifies AireOS WLC login with Wireless LAN Controller title",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body: `<html>
<head><title>Cisco Wireless LAN Controller</title></head>
<body>
<script>window.location='/screens/frameset.html';</script>
<p>Cisco Systems</p>
</body>
</html>`,
			wantTech: "cisco-wlc",
			wantCPE:  "cpe:2.3:o:cisco:wireless_lan_controller_software:*:*:*:*:*:*:*:*",
		},
		{
			name:       "identifies Aironet access point management UI",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body: `<html>
<head><title>Cisco Aironet Access Point</title></head>
<body>
<p>Cisco Aironet 2800 Series Access Point</p>
</body>
</html>`,
			wantTech: "cisco-aironet",
			wantCPE:  "cpe:2.3:o:cisco:aironet_access_point_software:*:*:*:*:*:*:*:*",
		},
		{
			name:       "identifies AireOS WLC via frameset path without WLC title",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body: `<html>
<head><title>Login</title></head>
<body>
<script>window.location='/screens/frameset.html';</script>
<p>Cisco Systems</p>
</body>
</html>`,
			wantTech: "cisco-wlc",
			wantCPE:  "cpe:2.3:o:cisco:wireless_lan_controller_software:*:*:*:*:*:*:*:*",
		},
		{
			name:       "generic HTML does not emit WLC identity",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>Welcome</title></head><body>Hello World</body></html>`,
			wantNil:    true,
		},
		{
			name:       "Apache default page does not emit WLC identity",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>Apache2 Ubuntu Default Page</title></head><body><h1>It works!</h1></body></html>`,
			wantNil:    true,
		},
		{
			name:       "empty body does not emit WLC identity",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       "",
			wantNil:    true,
		},
		{
			name:       "frameset path without Cisco corroboration is rejected",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><body><script>window.location='/screens/frameset.html';</script></body></html>`,
			wantNil:    true,
		},
		{
			name:       "Cisco brand mention without WLC exclusive signal is rejected",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>Cisco Systems Login</title></head><body><p>Please log in.</p></body></html>`,
			wantNil:    true,
		},
		{
			name:       "ASA CSCOE WebVPN portal is not WLC",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body: `<html>
<head><title>SSL VPN Service</title></head>
<body>
<script>if(self != top) top.location.href="/+CSCOE+/logon.html";</script>
<p>Cisco Systems, Inc. Network Access</p>
</body>
</html>`,
			wantNil: true,
		},
		{
			name:       "blog post mentioning wireless LAN controller is rejected",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>Best Controllers 2024</title></head><body><p>Cisco makes a Wireless LAN Controller.</p></body></html>`,
			wantNil:    true,
		},
		{
			name:       "500 with WLC body is rejected",
			statusCode: 500,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       `<html><head><title>Cisco Wireless LAN Controller</title></head></html>`,
			wantNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CiscoWLCFingerprinter{}
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

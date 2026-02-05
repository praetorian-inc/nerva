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
)

func TestGlobalProtectFingerprinter_Name(t *testing.T) {
	f := &GlobalProtectFingerprinter{}
	if name := f.Name(); name != "globalprotect" {
		t.Errorf("Name() = %q, expected %q", name, "globalprotect")
	}
}

func TestGlobalProtectFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &GlobalProtectFingerprinter{}
	if endpoint := f.ProbeEndpoint(); endpoint != "/global-protect/prelogin.esp" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", endpoint, "/global-protect/prelogin.esp")
	}
}

func TestGlobalProtectFingerprinter_Match(t *testing.T) {
	f := &GlobalProtectFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "matches with X-Private-Pan-Sslvpn header",
			statusCode: 200,
			headers: http.Header{
				"X-Private-Pan-Sslvpn": []string{"auth-ok"},
			},
			want: true,
		},
		{
			name:       "matches with PAN-OS Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"PAN-OS 10.2.3"},
			},
			want: true,
		},
		{
			name:       "matches with Palo Alto Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Palo Alto Networks"},
			},
			want: true,
		},
		{
			name:       "does not match 404 response",
			statusCode: 404,
			headers:    http.Header{},
			want:       false,
		},
		{
			name:       "does not match 301 redirect",
			statusCode: 301,
			headers:    http.Header{},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     tt.headers,
			}
			if got := f.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGlobalProtectFingerprinter_Fingerprint(t *testing.T) {
	f := &GlobalProtectFingerprinter{}

	tests := []struct {
		name          string
		statusCode    int
		headers       http.Header
		body          string
		wantResult    bool
		wantTech      string
		wantVersion   string
		wantCPEPrefix string
	}{
		{
			name:       "detects GlobalProtect from prelogin-response XML",
			statusCode: 200,
			headers:    http.Header{},
			body: `<?xml version="1.0" encoding="UTF-8"?>
<prelogin-response>
<status>Success</status>
<sw-version>10.2.3</sw-version>
</prelogin-response>`,
			wantResult:    true,
			wantTech:      "palo-alto-globalprotect",
			wantVersion:   "10.2.3",
			wantCPEPrefix: "cpe:2.3:o:paloaltonetworks:pan-os:10.2.3",
		},
		{
			name:       "detects GlobalProtect from prelogin-response with hotfix version",
			statusCode: 200,
			headers:    http.Header{},
			body: `<?xml version="1.0" encoding="UTF-8"?>
<prelogin-response>
<status>Success</status>
<sw-version>10.1.9-h1</sw-version>
</prelogin-response>`,
			wantResult:    true,
			wantTech:      "palo-alto-globalprotect",
			wantVersion:   "10.1.9-h1",
			wantCPEPrefix: "cpe:2.3:o:paloaltonetworks:pan-os:10.1.9-h1",
		},
		{
			name:       "detects GlobalProtect from global-protect keyword in body",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>GlobalProtect Portal</body></html>`,
			wantResult: true,
			wantTech:   "palo-alto-globalprotect",
		},
		{
			name:       "detects GlobalProtect from PAN_FORM keyword",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><form name="PAN_FORM" method="POST"></form></html>`,
			wantResult: true,
			wantTech:   "palo-alto-globalprotect",
		},
		{
			name:       "detects GlobalProtect from palo alto keyword",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>Powered by Palo Alto Networks</body></html>`,
			wantResult: true,
			wantTech:   "palo-alto-globalprotect",
		},
		{
			name:       "extracts version from Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"PAN-OS 11.0.1"},
			},
			body:          `<html></html>`,
			wantResult:    true,
			wantTech:      "palo-alto-globalprotect",
			wantVersion:   "11.0.1",
			wantCPEPrefix: "cpe:2.3:o:paloaltonetworks:pan-os:11.0.1",
		},
		{
			name:       "does not detect from 404 response",
			statusCode: 404,
			headers:    http.Header{},
			body:       `<html><body>Not Found - global-protect</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not detect from 301 redirect",
			statusCode: 301,
			headers:    http.Header{},
			body:       `<html><body>Redirecting to GlobalProtect</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not detect non-GlobalProtect content",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>Welcome to our website</body></html>`,
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     tt.headers,
			}
			result, err := f.Fingerprint(resp, []byte(tt.body))

			if err != nil {
				t.Errorf("Fingerprint() error = %v", err)
				return
			}

			if tt.wantResult && result == nil {
				t.Error("Fingerprint() returned nil, expected result")
				return
			}

			if !tt.wantResult && result != nil {
				t.Errorf("Fingerprint() returned result, expected nil")
				return
			}

			if result != nil {
				if result.Technology != tt.wantTech {
					t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
				}
				if tt.wantVersion != "" && result.Version != tt.wantVersion {
					t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
				}
				if tt.wantCPEPrefix != "" && len(result.CPEs) > 0 {
					if result.CPEs[0][:len(tt.wantCPEPrefix)] != tt.wantCPEPrefix {
						t.Errorf("CPE = %q, want prefix %q", result.CPEs[0], tt.wantCPEPrefix)
					}
				}
			}
		})
	}
}

func TestBuildGlobalProtectCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "10.2.3",
			want:    "cpe:2.3:o:paloaltonetworks:pan-os:10.2.3:*:*:*:*:*:*:*",
		},
		{
			version: "10.1.9-h1",
			want:    "cpe:2.3:o:paloaltonetworks:pan-os:10.1.9-h1:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := buildGlobalProtectCPE(tt.version); got != tt.want {
				t.Errorf("buildGlobalProtectCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}

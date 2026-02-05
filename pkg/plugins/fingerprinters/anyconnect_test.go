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

func TestAnyConnectFingerprinter_Name(t *testing.T) {
	f := &AnyConnectFingerprinter{}
	if name := f.Name(); name != "anyconnect" {
		t.Errorf("Name() = %q, expected %q", name, "anyconnect")
	}
}

func TestAnyConnectFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &AnyConnectFingerprinter{}
	if endpoint := f.ProbeEndpoint(); endpoint != "/+CSCOE+/logon.html" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", endpoint, "/+CSCOE+/logon.html")
	}
}

func TestAnyConnectFingerprinter_Match(t *testing.T) {
	f := &AnyConnectFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "matches with X-ASA-Version header",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			want: true,
		},
		{
			name:       "matches with X-Transcend-Version header",
			statusCode: 200,
			headers: http.Header{
				"X-Transcend-Version": []string{"9.16"},
			},
			want: true,
		},
		{
			name:       "matches with Cisco Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Cisco ASA"},
			},
			want: true,
		},
		{
			name:       "matches with webvpn cookie",
			statusCode: 200,
			headers: http.Header{
				"Set-Cookie": []string{"webvpnlogin=1; path=/"},
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

func TestAnyConnectFingerprinter_Fingerprint(t *testing.T) {
	f := &AnyConnectFingerprinter{}

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
			name:       "detects AnyConnect from body with webvpn keyword",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>Welcome to WebVPN Portal</body></html>`,
			wantResult: true,
			wantTech:   "cisco-anyconnect",
		},
		{
			name:       "detects AnyConnect from body with CSCOE",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><script src="/+CSCOE+/scripts.js"></script></html>`,
			wantResult: true,
			wantTech:   "cisco-anyconnect",
		},
		{
			name:       "detects AnyConnect from body with anyconnect keyword",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>Please install AnyConnect VPN client</body></html>`,
			wantResult: true,
			wantTech:   "cisco-anyconnect",
		},
		{
			name:       "extracts version from X-ASA-Version header",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			body:          `<html></html>`,
			wantResult:    true,
			wantTech:      "cisco-anyconnect",
			wantVersion:   "9.16(4)",
			wantCPEPrefix: "cpe:2.3:a:cisco:adaptive_security_appliance_software:9.16(4)",
		},
		{
			name:       "extracts version from X-Transcend-Version header",
			statusCode: 200,
			headers: http.Header{
				"X-Transcend-Version": []string{"9.18.1"},
			},
			body:          `<html></html>`,
			wantResult:    true,
			wantTech:      "cisco-anyconnect",
			wantVersion:   "9.18.1",
			wantCPEPrefix: "cpe:2.3:a:cisco:adaptive_security_appliance_software:9.18.1",
		},
		{
			name:       "does not detect from 404 response",
			statusCode: 404,
			headers:    http.Header{},
			body:       `<html><body>Not Found - CSCOE</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not detect from 301 redirect",
			statusCode: 301,
			headers:    http.Header{},
			body:       `<html><body>Redirecting to webvpn</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not detect non-AnyConnect content",
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

func TestBuildAnyConnectCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "9.16(4)",
			want:    "cpe:2.3:a:cisco:adaptive_security_appliance_software:9.16(4):*:*:*:*:*:*:*",
		},
		{
			version: "9.18.1",
			want:    "cpe:2.3:a:cisco:adaptive_security_appliance_software:9.18.1:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:a:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := buildAnyConnectCPE(tt.version); got != tt.want {
				t.Errorf("buildAnyConnectCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}

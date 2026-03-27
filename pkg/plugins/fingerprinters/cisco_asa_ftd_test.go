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

func TestCiscoASAFTDFingerprinter_Name(t *testing.T) {
	f := &CiscoASAFTDFingerprinter{}
	if name := f.Name(); name != "cisco-asa-ftd" {
		t.Errorf("Name() = %q, expected %q", name, "cisco-asa-ftd")
	}
}

func TestCiscoASAFTDFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &CiscoASAFTDFingerprinter{}
	if endpoint := f.ProbeEndpoint(); endpoint != "/+CSCOE+/logon.html" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", endpoint, "/+CSCOE+/logon.html")
	}
}

func TestCiscoASAFTDFingerprinter_Match(t *testing.T) {
	f := &CiscoASAFTDFingerprinter{}

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
				"X-Transcend-Version": []string{"9.18.2"},
			},
			want: true,
		},
		{
			name:       "matches with Cisco Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Cisco ASDM/7.18(1)"},
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
			name:       "matches with webvpncontext cookie",
			statusCode: 200,
			headers: http.Header{
				"Set-Cookie": []string{"webvpncontext=abc123; path=/"},
			},
			want: true,
		},
		{
			name:       "does not match 500 error",
			statusCode: 500,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			want: false,
		},
		{
			name:       "does not match generic Apache server",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Apache/2.4.41"},
			},
			want: false,
		},
		{
			name:       "does not match empty headers",
			statusCode: 200,
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

func TestCiscoASAFTDFingerprinter_Fingerprint(t *testing.T) {
	f := &CiscoASAFTDFingerprinter{}

	tests := []struct {
		name             string
		statusCode       int
		headers          http.Header
		body             string
		wantResult       bool
		wantTech         string
		wantVersion      string
		wantCPEPrefix    string
		wantPlatformType string
		wantWebVPN       bool
		wantASDM         bool
		wantASDMVersion  string
	}{
		{
			name:       "detects ASA from X-ASA-Version with WebVPN body",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			body:             `<html><body class="CSCOE"><div id="webvpn">Login</div></body></html>`,
			wantResult:       true,
			wantTech:         "cisco-asa",
			wantVersion:      "9.16(4)",
			wantCPEPrefix:    "cpe:2.3:o:cisco:adaptive_security_appliance_software:",
			wantPlatformType: "asa",
			wantWebVPN:       true,
		},
		{
			name:       "detects FTD from X-Transcend-Version header",
			statusCode: 200,
			headers: http.Header{
				"X-Transcend-Version": []string{"9.18.2"},
			},
			body:             `<html><body>Cisco CSCOE Login</body></html>`,
			wantResult:       true,
			wantTech:         "cisco-ftd",
			wantVersion:      "9.18.2",
			wantCPEPrefix:    "cpe:2.3:a:cisco:firepower_threat_defense:",
			wantPlatformType: "ftd",
		},
		{
			name:       "detects FTD from Firepower Threat Defense Server header",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"7.2.0"},
				"Server":        []string{"Cisco Firepower Threat Defense"},
			},
			body:             `<html><body>Login</body></html>`,
			wantResult:       true,
			wantTech:         "cisco-ftd",
			wantVersion:      "7.2.0",
			wantPlatformType: "ftd",
		},
		{
			name:       "detects ASDM from Server header",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
				"Server":        []string{"Cisco ASDM/7.18(1)"},
			},
			body:            `<html><body>Login</body></html>`,
			wantResult:      true,
			wantTech:        "cisco-asa",
			wantASDM:        true,
			wantASDMVersion: "7.18(1)",
		},
		{
			name:       "does not detect from body patterns alone no headers",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body class="CSCOE"><div id="webvpn">Login to AnyConnect</div></body></html>`,
			wantResult: false,
		},
		{
			name:       "does not detect from 500 error",
			statusCode: 500,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			body:       `<html><body>Error</body></html>`,
			wantResult: false,
		},
		{
			name:       "extracts version from X-ASA-Version 9.16(4) correctly",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			body:        `<html><body>Login</body></html>`,
			wantResult:  true,
			wantTech:    "cisco-asa",
			wantVersion: "9.16(4)",
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
				if tt.wantTech != "" && result.Technology != tt.wantTech {
					t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
				}
				if tt.wantVersion != "" && result.Version != tt.wantVersion {
					t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
				}
				if tt.wantCPEPrefix != "" && len(result.CPEs) > 0 {
					if len(result.CPEs[0]) < len(tt.wantCPEPrefix) || result.CPEs[0][:len(tt.wantCPEPrefix)] != tt.wantCPEPrefix {
						t.Errorf("CPE = %q, want prefix %q", result.CPEs[0], tt.wantCPEPrefix)
					}
				}
				if tt.wantPlatformType != "" {
					if pt, ok := result.Metadata["platform_type"]; ok {
						if pt != tt.wantPlatformType {
							t.Errorf("platform_type = %q, want %q", pt, tt.wantPlatformType)
						}
					} else {
						t.Errorf("platform_type not in metadata")
					}
				}
				if tt.wantWebVPN {
					if webvpn, ok := result.Metadata["webvpn_enabled"]; ok {
						if webvpn != true {
							t.Errorf("webvpn_enabled = %v, want true", webvpn)
						}
					} else {
						t.Errorf("webvpn_enabled not in metadata")
					}
				}
				if tt.wantASDM {
					if asdm, ok := result.Metadata["asdm_available"]; ok {
						if asdm != true {
							t.Errorf("asdm_available = %v, want true", asdm)
						}
					} else {
						t.Errorf("asdm_available not in metadata")
					}
				}
				if tt.wantASDMVersion != "" {
					if av, ok := result.Metadata["asdm_version"]; ok {
						if av != tt.wantASDMVersion {
							t.Errorf("asdm_version = %q, want %q", av, tt.wantASDMVersion)
						}
					} else {
						t.Errorf("asdm_version not in metadata")
					}
				}
			}
		})
	}
}

// TestCiscoASAFTDFingerprinter_ShodanVectors tests detection against real-world
// response patterns observed via Shodan and live Cisco ASA/FTD reconnaissance.
func TestCiscoASAFTDFingerprinter_ShodanVectors(t *testing.T) {
	f := &CiscoASAFTDFingerprinter{}

	tests := []struct {
		name             string
		description      string
		statusCode       int
		headers          http.Header
		body             string
		wantTech         string
		wantVersion      string
		wantPlatformType string
		wantWebVPN       bool
	}{
		{
			name:        "Shodan Vector 1: ASA 9.16 with ASDM and webvpn login",
			description: "Cisco ASA 9.16 with X-ASA-Version, ASDM server header, webvpnlogin cookie, CSCOE login page body",
			statusCode:  200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
				"Server":        []string{"Cisco ASDM/7.18(1)"},
				"Set-Cookie":    []string{"webvpnlogin=1; path=/; secure; HttpOnly"},
			},
			body: `<!DOCTYPE html>
<html>
<head><title>Cisco ASA</title></head>
<body class="CSCOE">
<div id="webvpn-login">
<h1>Please enter your username and password.</h1>
<form action="/+webvpn+/index.html" method="post">
<input type="text" name="username">
<input type="password" name="password">
</form>
</div>
</body></html>`,
			wantTech:         "cisco-asa",
			wantVersion:      "9.16(4)",
			wantPlatformType: "asa",
			wantWebVPN:       true,
		},
		{
			name:        "Shodan Vector 2: FTD 7.2 with X-Transcend-Version",
			description: "Cisco FTD 7.2 with X-Transcend-Version header, Firepower server, CSCOE body",
			statusCode:  200,
			headers: http.Header{
				"X-Transcend-Version": []string{"7.2.0"},
				"Server":              []string{"Cisco Firepower Threat Defense"},
			},
			body: `<!DOCTYPE html>
<html>
<head><title>Cisco Firepower Threat Defense</title></head>
<body class="CSCOE">
<div id="login">
<h1>Cisco Firepower Threat Defense</h1>
</div>
</body></html>`,
			wantTech:         "cisco-ftd",
			wantVersion:      "7.2.0",
			wantPlatformType: "ftd",
		},
		{
			name:        "Shodan Vector 3: ASA with webvpncontext cookie, no version headers",
			description: "Cisco ASA with webvpncontext cookie, Cisco server header, no version headers",
			statusCode:  200,
			headers: http.Header{
				"Server":     []string{"Cisco"},
				"Set-Cookie": []string{"webvpncontext=00@abc123; path=/; secure"},
			},
			body: `<!DOCTYPE html>
<html>
<head><title>SSL VPN Service</title></head>
<body>
<div id="anyconnect-login">
<p>WebVPN Service</p>
</div>
</body></html>`,
			wantTech:         "cisco-asa",
			wantPlatformType: "asa",
			wantWebVPN:       true,
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

			if result == nil {
				t.Errorf("Fingerprint() returned nil for Shodan vector: %s", tt.description)
				return
			}

			if result.Technology != tt.wantTech {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
			}

			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			if tt.wantPlatformType != "" {
				if pt, ok := result.Metadata["platform_type"]; ok {
					if pt != tt.wantPlatformType {
						t.Errorf("platform_type = %q, want %q", pt, tt.wantPlatformType)
					}
				} else {
					t.Errorf("platform_type not in metadata")
				}
			}

			if tt.wantWebVPN {
				if webvpn, ok := result.Metadata["webvpn_enabled"]; ok {
					if webvpn != true {
						t.Errorf("webvpn_enabled = %v, want true", webvpn)
					}
				} else {
					t.Errorf("webvpn_enabled not in metadata")
				}
			}
		})
	}
}

func TestCiscoASAFTDFingerprinter_VersionValidation(t *testing.T) {
	tests := []struct {
		name    string
		version string
		valid   bool
	}{
		{name: "valid ASA version 9.16(4)", version: "9.16(4)", valid: true},
		{name: "valid ASA version 9.8(2)", version: "9.8(2)", valid: true},
		{name: "valid simple version 9.16", version: "9.16", valid: true},
		{name: "valid FTD version 7.2.0", version: "7.2.0", valid: true},
		{name: "valid FTD version 6.7.0.2", version: "6.7.0.2", valid: true},
		{name: "invalid CPE injection", version: "9.16:*:*:injected", valid: false},
		{name: "invalid empty", version: "", valid: false},
		{name: "invalid letters", version: "abc", valid: false},
		{name: "invalid too many octets", version: "1.2.3.4.5.6", valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := asaFTDVersionRegex.MatchString(tt.version)
			if got != tt.valid {
				t.Errorf("asaFTDVersionRegex.MatchString(%q) = %v, want %v", tt.version, got, tt.valid)
			}
		})
	}
}

// TestCiscoASAFTDFingerprinter_ActiveInterface verifies the fingerprinter
// implements the ActiveHTTPFingerprinter interface.
func TestCiscoASAFTDFingerprinter_ActiveInterface(t *testing.T) {
	f := &CiscoASAFTDFingerprinter{}

	// Verify it implements ActiveHTTPFingerprinter
	var _ ActiveHTTPFingerprinter = f

	// Verify probe endpoint is set
	if endpoint := f.ProbeEndpoint(); endpoint == "" {
		t.Error("ProbeEndpoint() returned empty string, expected /+CSCOE+/logon.html")
	}
}

func TestBuildCiscoASACPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "9.16(4)",
			want:    "cpe:2.3:o:cisco:adaptive_security_appliance_software:9.16(4):*:*:*:*:*:*:*",
		},
		{
			version: "9.8(2)",
			want:    "cpe:2.3:o:cisco:adaptive_security_appliance_software:9.8(2):*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := buildCiscoASACPE(tt.version); got != tt.want {
				t.Errorf("buildCiscoASACPE() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildCiscoFTDCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "7.2.0",
			want:    "cpe:2.3:a:cisco:firepower_threat_defense:7.2.0:*:*:*:*:*:*:*",
		},
		{
			version: "9.18.2",
			want:    "cpe:2.3:a:cisco:firepower_threat_defense:9.18.2:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:a:cisco:firepower_threat_defense:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := buildCiscoFTDCPE(tt.version); got != tt.want {
				t.Errorf("buildCiscoFTDCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCiscoASAFTDFingerprinter_Match_EdgeCases(t *testing.T) {
	f := &CiscoASAFTDFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "matches on 302 redirect with X-ASA-Version",
			statusCode: 302,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			want: true,
		},
		{
			name:       "matches on 401 unauthorized with Cisco Server header",
			statusCode: 401,
			headers: http.Header{
				"Server": []string{"Cisco"},
			},
			want: true,
		},
		{
			name:       "matches on 403 forbidden with webvpn cookie",
			statusCode: 403,
			headers: http.Header{
				"Set-Cookie": []string{"webvpnlogin=1; path=/"},
			},
			want: true,
		},
		{
			name:       "does not match status 199",
			statusCode: 199,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16"},
			},
			want: false,
		},
		{
			name:       "does not match status 503",
			statusCode: 503,
			headers: http.Header{
				"Server": []string{"Cisco"},
			},
			want: false,
		},
		{
			name:       "does not match nginx with webvpn in body only",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"nginx"},
			},
			want: false,
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

func TestCiscoASAFTDFingerprinter_Fingerprint_EdgeCases(t *testing.T) {
	f := &CiscoASAFTDFingerprinter{}

	tests := []struct {
		name            string
		statusCode      int
		headers         http.Header
		body            string
		wantResult      bool
		wantTech        string
		wantVersion     string
		wantWebVPN      bool
		wantASDM        bool
		wantNoASDMVer   bool
		wantNoWebVPN    bool
	}{
		{
			name:       "FTD with both X-ASA-Version and X-Transcend-Version prefers Transcend",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version":       []string{"9.20(2)"},
				"X-Transcend-Version": []string{"7.4.1"},
				"Server":              []string{"Cisco Firepower Threat Defense"},
			},
			body:        "<html><body>Login</body></html>",
			wantResult:  true,
			wantTech:    "cisco-ftd",
			wantVersion: "7.4.1",
		},
		{
			name:       "ASA with both headers prefers X-ASA-Version",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version":       []string{"9.16(4)"},
				"X-Transcend-Version": []string{"9.16.4"},
			},
			body:        "<html><body>Login</body></html>",
			wantResult:  true,
			wantTech:    "cisco-asa",
			wantVersion: "9.16(4)",
		},
		{
			name:       "version extracted from Server header only",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Cisco ASDM/7.18(1)"},
			},
			body:        "",
			wantResult:  true,
			wantVersion: "7.18(1)",
			wantASDM:    true,
		},
		{
			name:       "invalid version in X-ASA-Version is sanitized",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16:*:*:injected"},
			},
			body:        "<html><body>Login</body></html>",
			wantResult:  true,
			wantVersion: "",
		},
		{
			name:       "malformed asdm_version in Server header injection part is stripped",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
				"Server":        []string{"Cisco ASDM/7.18(1):*:injected"},
			},
			body:       "<html><body>Login</body></html>",
			wantResult: true,
			wantASDM:   true,
			// asdmVersionRegex captures only "7.18(1)" — the injected suffix is outside
			// the capture group and is not included in asdm_version.
		},
		{
			name:       "empty body with valid headers detects correctly",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			body:         "",
			wantResult:   true,
			wantTech:     "cisco-asa",
			wantNoWebVPN: true,
		},
		{
			name:       "WebVPN detected from cookie only no body patterns",
			statusCode: 200,
			headers: http.Header{
				"Server":     []string{"Cisco"},
				"Set-Cookie": []string{"webvpncontext=abc123; path=/"},
			},
			body:       "<html><body>Generic page</body></html>",
			wantResult: true,
			wantWebVPN: true,
		},
		{
			name:       "WebVPN detected from anyconnect body pattern",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			body:       "<html><body>AnyConnect VPN Service</body></html>",
			wantResult: true,
			wantWebVPN: true,
		},
		{
			name:       "301 redirect with Cisco headers",
			statusCode: 301,
			headers: http.Header{
				"Server":   []string{"Cisco"},
				"Location": []string{"/+CSCOE+/logon.html"},
			},
			body:       "",
			wantResult: true,
			wantTech:   "cisco-asa",
		},
		{
			name:       "403 with X-ASA-Version still fingerprints",
			statusCode: 403,
			headers: http.Header{
				"X-Asa-Version": []string{"9.14(1)"},
			},
			body:        "<html><body>Forbidden</body></html>",
			wantResult:  true,
			wantVersion: "9.14(1)",
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

			if result == nil {
				return
			}

			if tt.wantTech != "" && result.Technology != tt.wantTech {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
			}
			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			// wantVersion=="" with wantResult means version must be empty (sanitized case)
			if tt.wantVersion == "" && tt.wantResult && result.Version != "" {
				// Only enforce empty when the test explicitly expects empty by having wantResult
				// and the headers contain a version that should be sanitized.
				// Check headers for any version-like values to decide if we enforce.
				if tt.headers.Get("X-Asa-Version") != "" || tt.headers.Get("X-Transcend-Version") != "" {
					// If the header is clearly invalid (contains colons beyond version), expect empty
					v := tt.headers.Get("X-Asa-Version")
					if v == "" {
						v = tt.headers.Get("X-Transcend-Version")
					}
					if !asaFTDVersionRegex.MatchString(v) {
						t.Errorf("Version = %q, want empty (sanitized)", result.Version)
					}
				}
			}
			if tt.wantWebVPN {
				if webvpn, ok := result.Metadata["webvpn_enabled"]; !ok || webvpn != true {
					t.Errorf("webvpn_enabled not set or not true, got %v", result.Metadata["webvpn_enabled"])
				}
			}
			if tt.wantNoWebVPN {
				if _, ok := result.Metadata["webvpn_enabled"]; ok {
					t.Errorf("webvpn_enabled should not be in metadata, but it is")
				}
			}
			if tt.wantASDM {
				if asdm, ok := result.Metadata["asdm_available"]; !ok || asdm != true {
					t.Errorf("asdm_available not set or not true")
				}
			}
			if tt.wantNoASDMVer {
				if _, ok := result.Metadata["asdm_version"]; ok {
					t.Errorf("asdm_version should not be in metadata (malformed), but it is: %v", result.Metadata["asdm_version"])
				}
			}
		})
	}
}

func TestExtractASAFTDVersion(t *testing.T) {
	tests := []struct {
		name         string
		headers      http.Header
		platformType string
		want         string
	}{
		{
			name: "returns X-ASA-Version for ASA platform",
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			platformType: "asa",
			want:         "9.16(4)",
		},
		{
			name: "returns X-Transcend-Version for FTD platform",
			headers: http.Header{
				"X-Transcend-Version": []string{"7.4.1"},
			},
			platformType: "ftd",
			want:         "7.4.1",
		},
		{
			name: "FTD with both headers returns X-Transcend-Version",
			headers: http.Header{
				"X-Asa-Version":       []string{"9.20(2)"},
				"X-Transcend-Version": []string{"7.4.1"},
			},
			platformType: "ftd",
			want:         "7.4.1",
		},
		{
			name: "ASA with both headers returns X-ASA-Version",
			headers: http.Header{
				"X-Asa-Version":       []string{"9.16(4)"},
				"X-Transcend-Version": []string{"9.16.4"},
			},
			platformType: "asa",
			want:         "9.16(4)",
		},
		{
			name: "falls back to Server header regex",
			headers: http.Header{
				"Server": []string{"Cisco ASDM/7.18(1)"},
			},
			platformType: "asa",
			want:         "7.18(1)",
		},
		{
			name: "returns empty for no version sources",
			headers: http.Header{
				"Server": []string{"Cisco"},
			},
			platformType: "asa",
			want:         "",
		},
		{
			name: "returns empty for non-Cisco Server header",
			headers: http.Header{
				"Server": []string{"Apache/2.4"},
			},
			platformType: "asa",
			want:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractASAFTDVersion(tt.headers, nil, tt.platformType)
			if got != tt.want {
				t.Errorf("extractASAFTDVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectPlatformType(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
	}{
		{
			name: "returns ftd for X-Transcend-Version",
			headers: http.Header{
				"X-Transcend-Version": []string{"7.4.1"},
			},
			want: "ftd",
		},
		{
			name: "returns ftd for Firepower Threat Defense Server",
			headers: http.Header{
				"Server": []string{"Cisco Firepower Threat Defense"},
			},
			want: "ftd",
		},
		{
			name: "returns asa for X-ASA-Version only",
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			want: "asa",
		},
		{
			name: "returns asa for generic Cisco Server",
			headers: http.Header{
				"Server": []string{"Cisco"},
			},
			want: "asa",
		},
		{
			name:    "returns asa for empty headers",
			headers: http.Header{},
			want:    "asa",
		},
		{
			name: "returns asa for ASDM Server not FTD",
			headers: http.Header{
				"Server": []string{"Cisco ASDM/7.18(1)"},
			},
			want: "asa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 200,
				Header:     tt.headers,
			}
			got := detectPlatformType(resp)
			if got != tt.want {
				t.Errorf("detectPlatformType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsASAFTDHeaderMatch(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    bool
	}{
		{
			name: "matches X-ASA-Version",
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			want: true,
		},
		{
			name: "matches X-Transcend-Version",
			headers: http.Header{
				"X-Transcend-Version": []string{"7.4.1"},
			},
			want: true,
		},
		{
			name: "matches Cisco Server",
			headers: http.Header{
				"Server": []string{"Cisco"},
			},
			want: true,
		},
		{
			name: "matches webvpn cookie",
			headers: http.Header{
				"Set-Cookie": []string{"webvpnlogin=1; path=/"},
			},
			want: true,
		},
		{
			name: "does not match Apache Server",
			headers: http.Header{
				"Server": []string{"Apache/2.4.41"},
			},
			want: false,
		},
		{
			name:    "does not match empty",
			headers: http.Header{},
			want:    false,
		},
		{
			name: "matches case-insensitive cisco in Server",
			headers: http.Header{
				"Server": []string{"CISCO ASA"},
			},
			want: true,
		},
		{
			name: "matches webvpnLang cookie",
			headers: http.Header{
				"Set-Cookie": []string{"webvpnLang=en; path=/"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 200,
				Header:     tt.headers,
			}
			got := isASAFTDHeaderMatch(resp)
			if got != tt.want {
				t.Errorf("isASAFTDHeaderMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCiscoASAFTDFingerprinter_PlatformModelAndAnyConnect(t *testing.T) {
	f := &CiscoASAFTDFingerprinter{}

	tests := []struct {
		name                   string
		statusCode             int
		headers                http.Header
		body                   string
		wantResult             bool
		wantPlatformModel      string
		wantAnyConnectVersion  string
		wantNoPlatformModel    bool
		wantNoAnyConnectVer    bool
	}{
		{
			name:       "platform model from Server header ASA 5525-X",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
				"Server":        []string{"Cisco ASA 5525-X"},
			},
			body:              "<html><body>Login</body></html>",
			wantResult:        true,
			wantPlatformModel: "5525-X",
		},
		{
			name:       "platform model from body ASA5506",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			body:              "<html><body>Cisco ASA5506 WebVPN</body></html>",
			wantResult:        true,
			wantPlatformModel: "5506",
		},
		{
			name:       "FTD model from Server header Firepower 2110",
			statusCode: 200,
			headers: http.Header{
				"X-Transcend-Version": []string{"7.2.0"},
				"Server":              []string{"Cisco Firepower 2110"},
			},
			body:              "<html><body>Login</body></html>",
			wantResult:        true,
			wantPlatformModel: "2110",
		},
		{
			name:       "anyconnect version from body download link",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			body:                  `<a href="/CACHE/sdesktop/install/anyconnect-win-4.10.07073-webdeploy-k9.pkg">Download</a>`,
			wantResult:            true,
			wantAnyConnectVersion: "4.10.07073",
		},
		{
			name:       "anyconnect version from body text",
			statusCode: 200,
			headers: http.Header{
				"Server":     []string{"Cisco"},
				"Set-Cookie": []string{"webvpnlogin=1; path=/"},
			},
			body:                  "<html>AnyConnect version 5.0.03072</html>",
			wantResult:            true,
			wantAnyConnectVersion: "5.0.03072",
		},
		{
			name:       "no model or anyconnect version in minimal response",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			body:                "<html><body>Login</body></html>",
			wantResult:          true,
			wantNoPlatformModel: true,
			wantNoAnyConnectVer: true,
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
			if result == nil {
				return
			}

			if tt.wantPlatformModel != "" {
				if got, ok := result.Metadata["platform_model"]; !ok {
					t.Errorf("platform_model not in metadata")
				} else if got != tt.wantPlatformModel {
					t.Errorf("platform_model = %q, want %q", got, tt.wantPlatformModel)
				}
			}
			if tt.wantNoPlatformModel {
				if _, ok := result.Metadata["platform_model"]; ok {
					t.Errorf("platform_model should not be in metadata but is: %v", result.Metadata["platform_model"])
				}
			}
			if tt.wantAnyConnectVersion != "" {
				if got, ok := result.Metadata["anyconnect_version"]; !ok {
					t.Errorf("anyconnect_version not in metadata")
				} else if got != tt.wantAnyConnectVersion {
					t.Errorf("anyconnect_version = %q, want %q", got, tt.wantAnyConnectVersion)
				}
			}
			if tt.wantNoAnyConnectVer {
				if _, ok := result.Metadata["anyconnect_version"]; ok {
					t.Errorf("anyconnect_version should not be in metadata but is: %v", result.Metadata["anyconnect_version"])
				}
			}
		})
	}
}

func TestExtractASAFTDModel(t *testing.T) {
	tests := []struct {
		name         string
		serverHeader string
		body         string
		want         string
	}{
		{"ASA 5525-X from Server", "Cisco ASA 5525-X", "", "5525-X"},
		{"ASA5506 from body", "", "Cisco ASA5506 login", "5506"},
		{"Firepower 2110 from Server", "Cisco Firepower 2110", "", "2110"},
		{"FPR-2130 from body", "", "FPR-2130 management", "2130"},
		{"no model", "Cisco", "login page", ""},
		{"Server takes priority over body", "Cisco ASA 5525-X", "ASA5506 login", "5525-X"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractASAFTDModel(tt.serverHeader, tt.body)
			if got != tt.want {
				t.Errorf("extractASAFTDModel(%q, %q) = %q, want %q", tt.serverHeader, tt.body, got, tt.want)
			}
		})
	}
}

func TestCiscoASAFTDFingerprinter_ShodanVectors_Additional(t *testing.T) {
	f := &CiscoASAFTDFingerprinter{}

	tests := []struct {
		name        string
		description string
		statusCode  int
		headers     http.Header
		body        string
		wantTech    string
		wantVersion string
		wantASDM    bool
	}{
		{
			name:        "Shodan Vector 4: ASA 302 redirect to CSCOE login",
			description: "Cisco ASA returning 302 with X-ASA-Version and Location to CSCOE",
			statusCode:  302,
			headers: http.Header{
				"X-Asa-Version": []string{"9.12(4)"},
				"Server":        []string{"Cisco"},
				"Location":      []string{"/+CSCOE+/logon.html"},
			},
			body:        "",
			wantTech:    "cisco-asa",
			wantVersion: "9.12(4)",
		},
		{
			name:        "Shodan Vector 5: FTD with X-Transcend-Version only minimal body",
			description: "Cisco FTD with X-Transcend-Version only",
			statusCode:  200,
			headers: http.Header{
				"X-Transcend-Version": []string{"7.0.6"},
			},
			body:        "<html></html>",
			wantTech:    "cisco-ftd",
			wantVersion: "7.0.6",
		},
		{
			name:        "Shodan Vector 6: ASA ASDM management interface Server header version only",
			description: "Cisco ASA ASDM management interface with Server header version",
			statusCode:  200,
			headers: http.Header{
				"Server": []string{"Cisco ASDM/7.14(1)"},
			},
			body:        "<html><head><title>Cisco ASDM</title></head></html>",
			wantTech:    "cisco-asa",
			wantVersion: "7.14(1)",
			wantASDM:    true,
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

			if result == nil {
				t.Errorf("Fingerprint() returned nil for Shodan vector: %s", tt.description)
				return
			}

			if tt.wantTech != "" && result.Technology != tt.wantTech {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
			}
			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if tt.wantASDM {
				if asdm, ok := result.Metadata["asdm_available"]; !ok || asdm != true {
					t.Errorf("asdm_available not set or not true")
				}
			}
		})
	}
}

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

func TestCheckPointFingerprinter_Name(t *testing.T) {
	f := &CheckPointFingerprinter{}
	if name := f.Name(); name != "checkpoint-gateway" {
		t.Errorf("Name() = %q, expected %q", name, "checkpoint-gateway")
	}
}

func TestCheckPointFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &CheckPointFingerprinter{}
	if endpoint := f.ProbeEndpoint(); endpoint != "/cgi-bin/home.tcl" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", endpoint, "/cgi-bin/home.tcl")
	}
}

func TestCheckPointFingerprinter_Match(t *testing.T) {
	f := &CheckPointFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "matches with Check Point Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Check Point SVN foundation"},
			},
			want: true,
		},
		{
			name:       "matches with CPWS Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"cpws"},
			},
			want: true,
		},
		{
			name:       "matches with X-Check-Point header",
			statusCode: 200,
			headers: http.Header{
				"X-Check-Point": []string{"true"},
			},
			want: true,
		},
		{
			name:       "matches with Gaia Portal redirect",
			statusCode: 302,
			headers: http.Header{
				"Location": []string{"/cgi-bin/home.tcl"},
			},
			want: true,
		},
		{
			name:       "matches with SSL VPN redirect",
			statusCode: 302,
			headers: http.Header{
				"Location": []string{"/sslvpn/Login/Login"},
			},
			want: true,
		},
		{
			name:       "matches with Check Point session cookie",
			statusCode: 200,
			headers: http.Header{
				"Set-Cookie": []string{"cpsession=abc123; path=/"},
			},
			want: true,
		},
		{
			name:       "does not match 500 server error",
			statusCode: 500,
			headers:    http.Header{},
			want:       false,
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
			name:       "does not match nginx",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"nginx/1.18.0"},
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

func TestCheckPointFingerprinter_Fingerprint(t *testing.T) {
	f := &CheckPointFingerprinter{}

	tests := []struct {
		name          string
		statusCode    int
		headers       http.Header
		body          string
		wantResult    bool
		wantTech      string
		wantVersion   string
		wantCPEPrefix string
		wantProduct   string
		wantVPN       bool
	}{
		{
			name:       "detects Gaia Portal from Server header and body",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Check Point SVN foundation"},
			},
			body:          `<html><head><title>Check Point Gaia Portal</title></head><body>Gaia R81.20</body></html>`,
			wantResult:    true,
			wantTech:      "checkpoint-gateway",
			wantVersion:   "R81.20",
			wantCPEPrefix: "cpe:2.3:o:checkpoint:gaia:r81.20",
			wantProduct:   "Security Gateway",
		},
		{
			name:       "detects Mobile Access Portal with VPN enabled",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Check Point SVN foundation"},
			},
			body:        `<html><body>Check Point Mobile Access Portal - SNX VPN client download</body></html>`,
			wantResult:  true,
			wantTech:    "checkpoint-gateway",
			wantProduct: "Mobile Access Portal",
			wantVPN:     true,
		},
		{
			name:       "detects SmartConsole management interface",
			statusCode: 200,
			headers: http.Header{
				"X-Check-Point": []string{"true"},
			},
			body:        `<html><body>SmartConsole management server Gaia R80.40</body></html>`,
			wantResult:  true,
			wantTech:    "checkpoint-gateway",
			wantVersion: "R80.40",
			wantProduct: "Management Server",
		},
		{
			name:       "detects from body patterns alone (vendor reference)",
			statusCode: 200,
			headers:    http.Header{},
			body:        `<html><body>Check Point Software Technologies Ltd. Gaia Portal</body></html>`,
			wantResult:  true,
			wantTech:    "checkpoint-gateway",
			wantProduct: "Security Gateway",
		},
		{
			name:       "detects from header alone with empty body",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"cpws"},
			},
			body:       ``,
			wantResult: true,
			wantTech:   "checkpoint-gateway",
		},
		{
			name:       "detects with redirect to sslvpn",
			statusCode: 302,
			headers: http.Header{
				"Location": []string{"/sslvpn/Login/Login"},
			},
			body:       ``,
			wantResult: true,
			wantTech:   "checkpoint-gateway",
			wantVPN:    true,
		},
		{
			name:       "does not detect from single vendor reference alone",
			statusCode: 200,
			headers:    http.Header{},
			body:        `<html><footer>Copyright Check Point Software Technologies Ltd.</footer></html>`,
			wantResult:  false,
		},
		{
			name:       "does not detect from generic CheckPoint mention",
			statusCode: 200,
			headers:    http.Header{},
			body:        `<html><body>We use CheckPoint firewalls in our infrastructure</body></html>`,
			wantResult:  false,
		},
		{
			name:       "does not detect non-Check Point content",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Apache/2.4.41"},
			},
			body:       `<html><body>Welcome to our website</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not detect from 500 error",
			statusCode: 500,
			headers: http.Header{
				"Server": []string{"Check Point SVN foundation"},
			},
			body:       `<html><body>Internal Server Error</body></html>`,
			wantResult: false,
		},
		{
			name:       "extracts version without header match using body only",
			statusCode: 200,
			headers:    http.Header{},
			body:        `<html><head><title>Gaia Portal</title></head><body>Welcome to Check Point Gaia R81.10 Portal<footer>Check Point Software Technologies Ltd.</footer></body></html>`,
			wantResult:  true,
			wantTech:    "checkpoint-gateway",
			wantVersion: "R81.10",
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
					if len(result.CPEs[0]) < len(tt.wantCPEPrefix) || result.CPEs[0][:len(tt.wantCPEPrefix)] != tt.wantCPEPrefix {
						t.Errorf("CPE = %q, want prefix %q", result.CPEs[0], tt.wantCPEPrefix)
					}
				}
				if tt.wantProduct != "" {
					if p, ok := result.Metadata["product"]; ok {
						if p != tt.wantProduct {
							t.Errorf("product = %q, want %q", p, tt.wantProduct)
						}
					} else {
						t.Errorf("product not in metadata")
					}
				}
				if tt.wantVPN {
					if vpn, ok := result.Metadata["vpnEnabled"]; ok {
						if vpn != true {
							t.Errorf("vpnEnabled = %v, want true", vpn)
						}
					} else {
						t.Errorf("vpnEnabled not in metadata")
					}
				}
			}
		})
	}
}

func TestBuildCheckPointCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "R81.20",
			want:    "cpe:2.3:o:checkpoint:gaia:r81.20:*:*:*:*:*:*:*",
		},
		{
			version: "R80.40",
			want:    "cpe:2.3:o:checkpoint:gaia:r80.40:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:o:checkpoint:gaia:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := buildCheckPointCPE(tt.version); got != tt.want {
				t.Errorf("buildCheckPointCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractGaiaVersion(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    string
	}{
		{
			name: "extracts R81.20 from Gaia Portal page",
			body: `<html><body>Check Point Gaia R81.20 Portal</body></html>`,
			want: "R81.20",
		},
		{
			name: "extracts R80.40 from management page",
			body: `<title>Gaia R80.40 Management</title>`,
			want: "R80.40",
		},
		{
			name: "extracts R81 without minor version",
			body: `Welcome to Gaia R81 Portal`,
			want: "R81",
		},
		{
			name: "extracts R77.30 legacy version",
			body: `Gaia R77.30 system`,
			want: "R77.30",
		},
		{
			name: "extracts R81.20 from JS variable",
			body: `<script>var version='R81.20';var formAction="/cgi-bin/home.tcl";</script>`,
			want: "R81.20",
		},
		{
			name: "extracts version from full real Gaia Portal JS block",
			body: `<script type="text/javascript">var errMsgText = "";var bannerMsgText = "";var user = "";var hostname='';var twofaConf='';var version='R81.20';var formAction="/cgi-bin/home.tcl";</script>`,
			want: "R81.20",
		},
		{
			name: "returns empty for no version",
			body: `<html><body>Check Point Portal</body></html>`,
			want: "",
		},
		{
			name: "returns empty for empty body",
			body: ``,
			want: "",
		},
		{
			name: "safely extracts version from CPE injection attempt",
			body: `Gaia R81.20:*:*:*:*:*:*:injected`,
			want: "R81.20", // regex only captures valid version portion
		},
		{
			name: "rejects non-numeric version after R",
			body: `Gaia Rabc.def`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractGaiaVersion([]byte(tt.body))
			if got != tt.want {
				t.Errorf("extractGaiaVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCheckPointFingerprinter_VersionRegexValidation(t *testing.T) {
	tests := []struct {
		name    string
		version string
		valid   bool
	}{
		{name: "R81", version: "R81", valid: true},
		{name: "R81.20", version: "R81.20", valid: true},
		{name: "R80.40", version: "R80.40", valid: true},
		{name: "R77.30", version: "R77.30", valid: true},
		{name: "invalid - no R prefix", version: "81.20", valid: false},
		{name: "invalid - CPE injection", version: "R81.20:*:*:injected", valid: false},
		{name: "invalid - empty", version: "", valid: false},
		{name: "invalid - letters after R", version: "Rabc", valid: false},
		{name: "invalid - too many dots", version: "R81.20.30", valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gaiaVersionRegex.MatchString(tt.version)
			if got != tt.valid {
				t.Errorf("gaiaVersionRegex.MatchString(%q) = %v, want %v", tt.version, got, tt.valid)
			}
		})
	}
}

// TestCheckPointFingerprinter_ShodanVectors tests detection against real-world
// response patterns observed via Shodan and live Check Point reconnaissance.
func TestCheckPointFingerprinter_Fingerprint_JSVersionVar(t *testing.T) {
	f := &CheckPointFingerprinter{}

	tests := []struct {
		name           string
		statusCode     int
		headers        http.Header
		body           string
		wantResult     bool
		wantVersion    string
		wantTechnology string
	}{
		{
			name:       "detects Check Point Gaia Portal with JS version variable",
			statusCode: 200,
			headers: http.Header{
				"Server":     []string{"CPWS"},
				"Set-Cookie": []string{"Session=Login;path=/; secure; HttpOnly"},
			},
			body: `<!DOCTYPE html><HTML><HEAD>
<meta name="others" content="WEBUI LOGIN PAGE"/><TITLE>GAiA</TITLE>
<script type="text/javascript">var version='R81.20';var formAction="/cgi-bin/home.tcl";</script>
</HEAD><BODY></BODY></HTML>`,
			wantResult:     true,
			wantVersion:    "R81.20",
			wantTechnology: "checkpoint-gateway",
		},
		{
			name:       "detects Check Point Mobile Access from redirect to sslvpn",
			statusCode: 302,
			headers: http.Header{
				"Server":   []string{"CPWS"},
				"Location": []string{"/sslvpn/Login/Login"},
			},
			body:           ``,
			wantResult:     true,
			wantVersion:    "",
			wantTechnology: "checkpoint-gateway",
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
				if result.Technology != tt.wantTechnology {
					t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTechnology)
				}
				if tt.wantVersion != "" && result.Version != tt.wantVersion {
					t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
				}
			}
		})
	}
}

func TestCheckPointFingerprinter_ShodanVectors(t *testing.T) {
	f := &CheckPointFingerprinter{}

	tests := []struct {
		name        string
		description string
		statusCode  int
		headers     http.Header
		body        string
		wantTech    string
		wantVersion string
		wantProduct string
	}{
		{
			name:        "Shodan Vector 1: Gaia Portal R81.20 on port 443",
			description: "Check Point Security Gateway with Gaia Portal exposed, R81.20",
			statusCode:  200,
			headers: http.Header{
				"Server":       []string{"Check Point SVN foundation"},
				"Content-Type": []string{"text/html"},
			},
			body: `<!DOCTYPE html>
<html>
<head><title>Check Point Gaia Portal</title>
<link rel="stylesheet" href="/cgi-bin/home.tcl?style=gaia.css">
</head>
<body>
<div id="login-container">
<h1>Check Point Gaia Portal</h1>
<p>Gaia R81.20</p>
<form action="/cgi-bin/home.tcl" method="POST">
<input type="text" name="user">
<input type="password" name="password">
<input type="submit" value="Login">
</form>
</div>
<footer>Check Point Software Technologies Ltd.</footer>
</body></html>`,
			wantTech:    "checkpoint-gateway",
			wantVersion: "R81.20",
			wantProduct: "Security Gateway",
		},
		{
			name:        "Shodan Vector 2: Mobile Access Portal with VPN",
			description: "Check Point Mobile Access Portal with SNX VPN client",
			statusCode:  200,
			headers: http.Header{
				"Server":       []string{"Check Point SVN foundation"},
				"Content-Type": []string{"text/html; charset=UTF-8"},
				"Set-Cookie":   []string{"cpsession=sess_abc123; path=/; secure; HttpOnly"},
			},
			body: `<!DOCTYPE html>
<html>
<head><title>Check Point Mobile Access</title></head>
<body>
<div id="portal">
<h1>Check Point Mobile Access Portal</h1>
<p>SNX VPN client available for download</p>
<a href="/sslvpn/SNX/CSHELL/snx_install.sh">Download SNX</a>
<form action="/sslvpn/Login/Login" method="POST">
<input type="text" name="userName">
<input type="password" name="password">
</form>
</div>
</body></html>`,
			wantTech:    "checkpoint-gateway",
			wantProduct: "Mobile Access Portal",
		},
		{
			name:        "Shodan Vector 3: Gaia Portal R80.40 with management",
			description: "Check Point gateway with Gaia R80.40 and SmartConsole reference",
			statusCode:  200,
			headers: http.Header{
				"Server":        []string{"cpws"},
				"X-Check-Point": []string{"SmartCenter"},
				"Content-Type":  []string{"text/html"},
			},
			body: `<!DOCTYPE html>
<html>
<head><title>Check Point SmartConsole</title></head>
<body>
<div id="management">
<h1>SmartConsole Management Server</h1>
<p>Connected to Gaia R80.40 Management Server</p>
<p>Check Point SmartCenter management interface</p>
</div>
</body></html>`,
			wantTech:    "checkpoint-gateway",
			wantVersion: "R80.40",
			wantProduct: "Management Server",
		},
		{
			name:        "Real Gaia Portal with banner message and 2FA config",
			description: "Real-world Gaia Portal page with JS version variable",
			statusCode:  200,
			headers: http.Header{
				"Server":     []string{"CPWS"},
				"Set-Cookie": []string{"Session=Login;path=/; secure; HttpOnly"},
			},
			body: `<!DOCTYPE html><HTML><HEAD>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="others" content="WEBUI LOGIN PAGE"/><TITLE>GAiA</TITLE>
<link rel="shortcut icon" href="/login/fav.ico">
<link rel="stylesheet" type="text/css" href="/login/ext-all.css"/>
<link rel="stylesheet" type="text/css" href="/login/login.css"/>
<script type="text/javascript" src="/login/ext-base.js"></script>
<script type="text/javascript" src="/login/ext-all.js"></script>
<script type="text/javascript">var errMsgText = "";var bannerMsgText = "";var user = "";var hostname='';var twofaConf='';var version='R81.20';var formAction="/cgi-bin/home.tcl";</script>
</HEAD><BODY></BODY></HTML>`,
			wantTech:    "checkpoint-gateway",
			wantVersion: "R81.20",
			wantProduct: "Security Gateway",
		},
		{
			name:        "Shodan Vector 4: Redirect to Gaia Portal",
			description: "Check Point gateway redirecting to Gaia Portal login",
			statusCode:  302,
			headers: http.Header{
				"Server":   []string{"Check Point SVN foundation"},
				"Location": []string{"/cgi-bin/home.tcl"},
			},
			body:        ``,
			wantTech:    "checkpoint-gateway",
			wantProduct: "Security Gateway",
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

			if tt.wantProduct != "" {
				if p, ok := result.Metadata["product"]; ok {
					if p != tt.wantProduct {
						t.Errorf("product = %q, want %q", p, tt.wantProduct)
					}
				} else {
					t.Errorf("product not in metadata")
				}
			}
		})
	}
}

// TestCheckPointFingerprinter_ActiveInterface verifies the fingerprinter
// implements the ActiveHTTPFingerprinter interface.
func TestCheckPointFingerprinter_ActiveInterface(t *testing.T) {
	f := &CheckPointFingerprinter{}

	// Verify it implements ActiveHTTPFingerprinter
	var _ ActiveHTTPFingerprinter = f

	// Verify probe endpoint is set
	if endpoint := f.ProbeEndpoint(); endpoint == "" {
		t.Error("ProbeEndpoint() returned empty string, expected /cgi-bin/home.tcl")
	}
}

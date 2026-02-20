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

func TestBigIPFingerprinter_Name(t *testing.T) {
	f := &BigIPFingerprinter{}
	if name := f.Name(); name != "bigip" {
		t.Errorf("Name() = %q, expected %q", name, "bigip")
	}
}

func TestBigIPFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &BigIPFingerprinter{}
	if endpoint := f.ProbeEndpoint(); endpoint != "/mgmt/tm/sys/version" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", endpoint, "/mgmt/tm/sys/version")
	}
}

func TestBigIPFingerprinter_Match(t *testing.T) {
	f := &BigIPFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "matches with Server: BigIP header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"BigIP"},
			},
			want: true,
		},
		{
			name:       "matches with Server: BIG-IP header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"BIG-IP"},
			},
			want: true,
		},
		{
			name:       "matches with Server: big-ip header (case insensitive)",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"big-ip"},
			},
			want: true,
		},
		{
			name:       "matches with BIGipServer cookie",
			statusCode: 200,
			headers: http.Header{
				"Set-Cookie": []string{"BIGipServerPool=rd5o00000000000000000000ffffff00c0a80a0a; path=/; Httponly; Secure"},
			},
			want: true,
		},
		{
			name:       "does not match 500 response",
			statusCode: 500,
			headers:    http.Header{},
			want:       false,
		},
		{
			name:       "does not match generic 200 with no F5 indicators",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"nginx"},
			},
			want: false,
		},
		{
			name:       "matches 401 with WWW-Authenticate realm containing iControl",
			statusCode: 401,
			headers: http.Header{
				"Www-Authenticate": []string{`Basic realm="iControl REST Authentication"`},
			},
			want: true,
		},
		{
			name:       "matches 401 with WWW-Authenticate realm containing Enterprise Manager",
			statusCode: 401,
			headers: http.Header{
				"Www-Authenticate": []string{`Basic realm="Enterprise Manager"`},
			},
			want: true,
		},
		{
			name:       "matches with F5-Login-Page header",
			statusCode: 200,
			headers: http.Header{
				"F5-Login-Page": []string{"true"},
			},
			want: true,
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

func TestBigIPFingerprinter_Fingerprint(t *testing.T) {
	f := &BigIPFingerprinter{}

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
			name:       "detects from iControl REST JSON with version extraction",
			statusCode: 200,
			headers:    http.Header{},
			body: `{
  "kind": "tm:sys:version:versionstats",
  "selfLink": "https://localhost/mgmt/tm/sys/version?ver=17.1.3",
  "entries": {
    "https://localhost/mgmt/tm/sys/version/0": {
      "nestedStats": {
        "entries": {
          "Build": { "description": "0.20.11" },
          "Date": { "description": "Sun Oct 12 12:43:02 PDT 2025" },
          "Edition": { "description": "Engineering Hotfix" },
          "Product": { "description": "BIG-IP" },
          "Title": { "description": "Main Package" },
          "Version": { "description": "13.0.0" }
        }
      }
    }
  }
}`,
			wantResult:    true,
			wantTech:      "f5-bigip",
			wantVersion:   "13.0.0",
			wantCPEPrefix: "cpe:2.3:a:f5:big-ip_local_traffic_manager:13.0.0",
		},
		{
			name:       "detects from TMUI login page HTML with <title>BIG-IP</title>",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<!DOCTYPE html><html><head><title>BIG-IP Configuration Utility</title></head><body><div id="app"></div></body></html>`,
			wantResult: true,
			wantTech:   "f5-bigip",
		},
		{
			name:       "detects from F5 Networks in body",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<!DOCTYPE html><html><body><footer>Copyright &copy; 2025 F5 Networks. All rights reserved.</footer></body></html>`,
			wantResult: true,
			wantTech:   "f5-bigip",
		},
		{
			name:       "extracts version from HTML body",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<!DOCTYPE html><html><head><title>BIG-IP</title></head><body><div class="version">BIG-IP 14.1.2 Build 0.0.37</div></body></html>`,
			wantResult: true,
			wantTech:   "f5-bigip",
			wantVersion:   "14.1.2",
			wantCPEPrefix: "cpe:2.3:a:f5:big-ip_local_traffic_manager:14.1.2",
		},
		{
			name:       "does not detect from non-BIG-IP content",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<!DOCTYPE html><html><body>Welcome to our website</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not detect from 500 response",
			statusCode: 500,
			headers:    http.Header{},
			body:       `<!DOCTYPE html><html><body>Internal Server Error - BIG-IP</body></html>`,
			wantResult: false,
		},
		{
			name:       "detects from Server header with empty body",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"BigIP"},
			},
			body:       `<!DOCTYPE html><html><body></body></html>`,
			wantResult: true,
			wantTech:   "f5-bigip",
		},
		{
			name:       "detects from BIGipServer cookie (load balancer mode, no version)",
			statusCode: 200,
			headers: http.Header{
				"Set-Cookie": []string{"BIGipServerPool=rd5o00000000000000000000ffffff00c0a80a0a; path=/; Httponly; Secure"},
			},
			body:       `<!DOCTYPE html><html><body><h1>Application</h1></body></html>`,
			wantResult: true,
			wantTech:   "f5-bigip",
		},
		{
			name:       "detects from support@f5.com in auth error page",
			statusCode: 401,
			headers: http.Header{
				"Www-Authenticate": []string{`Basic realm="Enterprise Manager"`},
			},
			body:       `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE html><html><head><title>Authentication required!</title><link rev="made" href="mailto:support@f5.com" /></head><body><p>Authentication required</p></body></html>`,
			wantResult: true,
			wantTech:   "f5-bigip",
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

func TestParseIControlVersion(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantVersion string
		wantBuild   string
	}{
		{
			name: "valid iControl JSON with version + build",
			body: `{
  "kind": "tm:sys:version:versionstats",
  "entries": {
    "https://localhost/mgmt/tm/sys/version/0": {
      "nestedStats": {
        "entries": {
          "Build": { "description": "0.20.11" },
          "Version": { "description": "13.0.0" }
        }
      }
    }
  }
}`,
			wantVersion: "13.0.0",
			wantBuild:   "0.20.11",
		},
		{
			name:        "invalid JSON (not iControl format)",
			body:        `{"status": "ok"}`,
			wantVersion: "",
			wantBuild:   "",
		},
		{
			name: "missing kind field",
			body: `{
  "entries": {
    "https://localhost/mgmt/tm/sys/version/0": {
      "nestedStats": {
        "entries": {
          "Version": { "description": "13.0.0" }
        }
      }
    }
  }
}`,
			wantVersion: "",
			wantBuild:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVersion, gotBuild := parseIControlVersion([]byte(tt.body))
			if gotVersion != tt.wantVersion {
				t.Errorf("parseIControlVersion() version = %v, want %v", gotVersion, tt.wantVersion)
			}
			if gotBuild != tt.wantBuild {
				t.Errorf("parseIControlVersion() build = %v, want %v", gotBuild, tt.wantBuild)
			}
		})
	}
}

func TestBuildBigIPCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "13.0.0",
			want:    "cpe:2.3:a:f5:big-ip_local_traffic_manager:13.0.0:*:*:*:*:*:*:*",
		},
		{
			version: "14.1.2",
			want:    "cpe:2.3:a:f5:big-ip_local_traffic_manager:14.1.2:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:a:f5:big-ip_local_traffic_manager:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := buildBigIPCPE(tt.version); got != tt.want {
				t.Errorf("buildBigIPCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestBigIPFingerprinter_ShodanVectors tests detection against real-world
// response patterns observed via Shodan reconnaissance.
func TestBigIPFingerprinter_ShodanVectors(t *testing.T) {
	f := &BigIPFingerprinter{}

	tests := []struct {
		name        string
		description string
		statusCode  int
		headers     http.Header
		body        string
		wantTech    string
		wantVersion string
	}{
		{
			name:        "Shodan Vector 1: iControl REST /mgmt/tm/sys/version JSON response with version 13.0.0",
			description: "iControl REST API version endpoint response",
			statusCode:  200,
			headers: http.Header{
				"Content-Type": []string{"application/json; charset=UTF-8"},
			},
			body: `{
  "kind": "tm:sys:version:versionstats",
  "selfLink": "https://localhost/mgmt/tm/sys/version?ver=17.1.3",
  "entries": {
    "https://localhost/mgmt/tm/sys/version/0": {
      "nestedStats": {
        "entries": {
          "Build": {
            "description": "0.20.11"
          },
          "Date": {
            "description": "Sun Oct 12 12:43:02 PDT 2025"
          },
          "Edition": {
            "description": "Engineering Hotfix"
          },
          "Product": {
            "description": "BIG-IP"
          },
          "Title": {
            "description": "Main Package"
          },
          "Version": {
            "description": "13.0.0"
          }
        }
      }
    }
  }
}`,
			wantTech:    "f5-bigip",
			wantVersion: "13.0.0",
		},
		{
			name:        "Shodan Vector 2: TMUI login page redirect with BIG-IP title",
			description: "BIG-IP Configuration Utility login page",
			statusCode:  302,
			headers: http.Header{
				"Server":   []string{"BigIP"},
				"Location": []string{"/tmui/login.jsp"},
			},
			body: `<!DOCTYPE html>
<html lang="en">
<head>
    <title>BIG-IP&reg;&nbsp;- Redirect</title>
</head>
<body>
<script>window.location="/tmui/login.jsp";</script>
</body>
</html>`,
			wantTech:    "f5-bigip",
			wantVersion: "",
		},
		{
			name:        "Shodan Vector 3: Load balancer with Server: BigIP header and BIGipServer cookie",
			description: "F5 BIG-IP acting as load balancer in front of application",
			statusCode:  200,
			headers: http.Header{
				"Server":     []string{"BigIP"},
				"Set-Cookie": []string{"BIGipServerPool_app=rd5o00000000000000000000ffffff00c0a80a0a; path=/"},
			},
			body: `<!DOCTYPE html>
<html>
<head><title>Application</title></head>
<body><h1>Welcome</h1></body>
</html>`,
			wantTech:    "f5-bigip",
			wantVersion: "",
		},
		{
			name:        "Shodan Vector 4: Management interface returning 401 with iControl auth requirement",
			description: "iControl REST API authentication required",
			statusCode:  401,
			headers: http.Header{
				"Server":           []string{"BIG-IP"},
				"Www-Authenticate": []string{`Basic realm="iControl REST Authentication"`},
				"Content-Type":     []string{"application/json; charset=UTF-8"},
			},
			body: `{
  "code": 401,
  "message": "Authorization required",
  "errorStack": []
}`,
			wantTech:    "f5-bigip",
			wantVersion: "",
		},
		{
			name:        "Shodan Vector 5: Management interface with Apache server and Enterprise Manager realm",
			description: "BIG-IP with Apache server header and Enterprise Manager auth realm",
			statusCode:  401,
			headers: http.Header{
				"Server":           []string{"Apache"},
				"Www-Authenticate": []string{`Basic realm="Enterprise Manager"`},
			},
			body: `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE html><html><head><title>Authentication required!</title><link rev="made" href="mailto:support@f5.com" /></head><body><p>Authentication required</p></body></html>`,
			wantTech:    "f5-bigip",
			wantVersion: "",
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
		})
	}
}

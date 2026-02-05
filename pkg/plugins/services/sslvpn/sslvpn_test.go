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

package sslvpn

import (
	"net/http"
	"testing"
)

// TestDetectAnyConnect tests Cisco AnyConnect detection logic
func TestDetectAnyConnect(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		headers  http.Header
		expected bool
	}{
		{
			name:     "webvpn keyword in body",
			body:     []byte(`<html><head><title>WebVPN Login</title></head></html>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "CSCOE marker in body",
			body:     []byte(`<form action="/+CSCOE+/logon.html" method="post">`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "CSCOT marker in body",
			body:     []byte(`<script src="/+CSCOT+/translation.js"></script>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "CSCOU marker in body",
			body:     []byte(`<a href="/+CSCOU+/portal.html">Portal</a>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "anyconnect keyword in body",
			body:     []byte(`<html>AnyConnect VPN Service</html>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "cisco vpn in body",
			body:     []byte(`<html>Cisco VPN Portal</html>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "asa keyword in body (word boundary)",
			body:     []byte(`<html>ASA Clientless SSL VPN</html>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "firepower in body",
			body:     []byte(`<html>Firepower Threat Defense</html>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "adaptivesecurityappliance in body",
			body:     []byte(`<html>AdaptiveSecurityAppliance Login</html>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "sdesktop marker in body",
			body:     []byte(`<html>sdesktop installer</html>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name: "X-ASA-Version header present",
			body: []byte(`<html>Generic page</html>`),
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(2)"},
			},
			expected: true,
		},
		{
			name: "X-Transcend-Version header present",
			body: []byte(`<html>Generic page</html>`),
			headers: http.Header{
				"X-Transcend-Version": []string{"9.14(1)"},
			},
			expected: true,
		},
		{
			name: "Cisco in Server header",
			body: []byte(`<html>Generic page</html>`),
			headers: http.Header{
				"Server": []string{"Cisco/ASA"},
			},
			expected: true,
		},
		{
			name:     "empty body no headers",
			body:     []byte{},
			headers:  http.Header{},
			expected: false,
		},
		{
			name:     "unrelated content",
			body:     []byte(`<html><head><title>Welcome</title></head><body>Hello World</body></html>`),
			headers:  http.Header{},
			expected: false,
		},
		{
			name:     "asa as part of another word (should not match)",
			body:     []byte(`<html>Invasive procedure</html>`),
			headers:  http.Header{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectAnyConnect(tt.body, tt.headers)
			if result != tt.expected {
				t.Errorf("detectAnyConnect() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestDetectAnyConnectCookies tests cookie-based AnyConnect detection
func TestDetectAnyConnectCookies(t *testing.T) {
	tests := []struct {
		name     string
		headers  http.Header
		expected bool
	}{
		{
			name: "webvpn cookie",
			headers: http.Header{
				"Set-Cookie": []string{"webvpn=abc123; path=/"},
			},
			expected: true,
		},
		{
			name: "webvpnlogin cookie",
			headers: http.Header{
				"Set-Cookie": []string{"webvpnlogin=xyz789; path=/; HttpOnly"},
			},
			expected: true,
		},
		{
			name: "webvpncontext cookie",
			headers: http.Header{
				"Set-Cookie": []string{"webvpncontext=session123; path=/"},
			},
			expected: true,
		},
		{
			name: "webvpnLang cookie",
			headers: http.Header{
				"Set-Cookie": []string{"webvpnLang=en; path=/"},
			},
			expected: true,
		},
		{
			name: "webvpnSharePoint cookie",
			headers: http.Header{
				"Set-Cookie": []string{"webvpnSharePoint=true; path=/"},
			},
			expected: true,
		},
		{
			name: "multiple cookies with webvpn",
			headers: http.Header{
				"Set-Cookie": []string{"session=abc", "webvpn=def", "other=ghi"},
			},
			expected: true,
		},
		{
			name: "no webvpn cookies",
			headers: http.Header{
				"Set-Cookie": []string{"session=abc123; path=/", "PHPSESSID=xyz"},
			},
			expected: false,
		},
		{
			name:     "no cookies",
			headers:  http.Header{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectAnyConnectCookies(tt.headers)
			if result != tt.expected {
				t.Errorf("detectAnyConnectCookies() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestDetectGlobalProtect tests Palo Alto GlobalProtect detection logic
func TestDetectGlobalProtect(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		headers  http.Header
		expected bool
	}{
		{
			name:     "global-protect in body",
			body:     []byte(`<html><form action="/global-protect/login.esp"></form></html>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "GlobalProtect keyword",
			body:     []byte(`<html>GlobalProtect Portal</html>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "PAN_FORM marker",
			body:     []byte(`<form id="PAN_FORM" method="post">`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "palo alto in body",
			body:     []byte(`<html>Palo Alto Networks</html>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "pan-os in body",
			body:     []byte(`<html>PAN-OS Portal</html>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "prelogin-response XML tag",
			body:     []byte(`<?xml version="1.0"?><prelogin-response><status>success</status></prelogin-response>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "saml-auth-method XML tag",
			body:     []byte(`<saml-auth-method>POST</saml-auth-method>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "saml-auth-status in body",
			body:     []byte(`<html>saml-auth-status: pending</html>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "portal XML tag",
			body:     []byte(`<?xml version="1.0"?><portal><name>Corp VPN</name></portal>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name:     "portal-prelogin in body",
			body:     []byte(`<html>portal-prelogin configuration</html>`),
			headers:  http.Header{},
			expected: true,
		},
		{
			name: "palo alto in server header",
			body: []byte(`<html>Generic</html>`),
			headers: http.Header{
				"Server": []string{"Palo Alto Networks"},
			},
			expected: true,
		},
		{
			name: "pan-os in server header",
			body: []byte(`<html>Generic</html>`),
			headers: http.Header{
				"Server": []string{"PAN-OS"},
			},
			expected: true,
		},
		{
			name: "X-Private-Pan-Sslvpn header",
			body: []byte(`<html>Generic</html>`),
			headers: http.Header{
				"X-Private-Pan-Sslvpn": []string{"1"},
			},
			expected: true,
		},
		{
			name:     "empty body no headers",
			body:     []byte{},
			headers:  http.Header{},
			expected: false,
		},
		{
			name:     "unrelated content",
			body:     []byte(`<html><head><title>Welcome</title></head><body>Hello World</body></html>`),
			headers:  http.Header{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectGlobalProtect(tt.body, tt.headers)
			if result != tt.expected {
				t.Errorf("detectGlobalProtect() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestExtractAnyConnectVersion tests Cisco ASA version extraction
func TestExtractAnyConnectVersion(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		headers  http.Header
		expected string
	}{
		{
			name: "X-ASA-Version header",
			body: []byte{},
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(2)"},
			},
			expected: "9.16(2)",
		},
		{
			name: "X-Transcend-Version header",
			body: []byte{},
			headers: http.Header{
				"X-Transcend-Version": []string{"9.14(1)"},
			},
			expected: "9.14(1)",
		},
		{
			name: "X-ASA-Version takes priority over X-Transcend-Version",
			body: []byte{},
			headers: http.Header{
				"X-Asa-Version":       []string{"9.16(2)"},
				"X-Transcend-Version": []string{"9.14(1)"},
			},
			expected: "9.16(2)",
		},
		{
			name: "version in server header",
			body: []byte{},
			headers: http.Header{
				"Server": []string{"ASA version 9.14(1)"},
			},
			expected: "9.14(1)",
		},
		{
			name:     "version in body",
			body:     []byte(`<html>ASA Version: 9.12.4</html>`),
			headers:  http.Header{},
			expected: "9.12.4",
		},
		{
			name:     "version keyword in body",
			body:     []byte(`<html>version 9.8.2(20)</html>`),
			headers:  http.Header{},
			expected: "9.8.2(20)",
		},
		{
			name:     "no version found",
			body:     []byte(`<html>WebVPN Login</html>`),
			headers:  http.Header{},
			expected: "",
		},
		{
			name:     "empty response",
			body:     []byte{},
			headers:  http.Header{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractAnyConnectVersion(tt.body, tt.headers)
			if result != tt.expected {
				t.Errorf("extractAnyConnectVersion() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// TestExtractGlobalProtectVersion tests Palo Alto PAN-OS version extraction
func TestExtractGlobalProtectVersion(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		headers  http.Header
		expected string
	}{
		{
			name: "PAN-OS in server header",
			body: []byte{},
			headers: http.Header{
				"Server": []string{"PAN-OS 10.2.3"},
			},
			expected: "10.2.3",
		},
		{
			name:     "sw-version XML tag (prelogin.esp)",
			body:     []byte(`<?xml version="1.0"?><prelogin-response><sw-version>10.2.4</sw-version></prelogin-response>`),
			headers:  http.Header{},
			expected: "10.2.4",
		},
		{
			name:     "sw-version with hotfix (prelogin.esp)",
			body:     []byte(`<?xml version="1.0"?><prelogin-response><sw-version>10.1.9-h1</sw-version></prelogin-response>`),
			headers:  http.Header{},
			expected: "10.1.9-h1",
		},
		{
			name:     "app-version XML tag",
			body:     []byte(`<?xml version="1.0"?><response><app-version>10.2.0</app-version></response>`),
			headers:  http.Header{},
			expected: "10.2.0",
		},
		{
			name:     "pan-os version in body",
			body:     []byte(`<html>PAN-OS: 10.1.0</html>`),
			headers:  http.Header{},
			expected: "10.1.0",
		},
		{
			name:     "panos version in body",
			body:     []byte(`<html>PANOS 9.1.12</html>`),
			headers:  http.Header{},
			expected: "9.1.12",
		},
		{
			name:     "no version found",
			body:     []byte(`<html>GlobalProtect Portal</html>`),
			headers:  http.Header{},
			expected: "",
		},
		{
			name:     "empty response",
			body:     []byte{},
			headers:  http.Header{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractGlobalProtectVersion(tt.body, tt.headers)
			if result != tt.expected {
				t.Errorf("extractGlobalProtectVersion() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// TestBuildAnyConnectCPE tests CPE generation for Cisco ASA
func TestBuildAnyConnectCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "specific version",
			version:  "9.16.2",
			expected: "cpe:2.3:a:cisco:adaptive_security_appliance_software:9.16.2:*:*:*:*:*:*:*",
		},
		{
			name:     "version with parentheses",
			version:  "9.14(1)",
			expected: "cpe:2.3:a:cisco:adaptive_security_appliance_software:9.14(1):*:*:*:*:*:*:*",
		},
		{
			name:     "empty version (wildcard)",
			version:  "",
			expected: "cpe:2.3:a:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildAnyConnectCPE(tt.version)
			if result != tt.expected {
				t.Errorf("buildAnyConnectCPE() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// TestBuildGlobalProtectCPE tests CPE generation for Palo Alto PAN-OS
func TestBuildGlobalProtectCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "specific version",
			version:  "10.2.3",
			expected: "cpe:2.3:o:paloaltonetworks:pan-os:10.2.3:*:*:*:*:*:*:*",
		},
		{
			name:     "version 9.x",
			version:  "9.1.12",
			expected: "cpe:2.3:o:paloaltonetworks:pan-os:9.1.12:*:*:*:*:*:*:*",
		},
		{
			name:     "version with hotfix",
			version:  "10.1.9-h1",
			expected: "cpe:2.3:o:paloaltonetworks:pan-os:10.1.9-h1:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version (wildcard)",
			version:  "",
			expected: "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildGlobalProtectCPE(tt.version)
			if result != tt.expected {
				t.Errorf("buildGlobalProtectCPE() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// TestPluginInterface tests that SSLVPNPlugin implements the Plugin interface correctly
func TestPluginInterface(t *testing.T) {
	p := &SSLVPNPlugin{}

	t.Run("Name", func(t *testing.T) {
		if name := p.Name(); name != SSLVPN {
			t.Errorf("Name() = %q, expected %q", name, SSLVPN)
		}
	})

	t.Run("PortPriority for 443", func(t *testing.T) {
		if !p.PortPriority(443) {
			t.Error("PortPriority(443) = false, expected true")
		}
	})

	t.Run("PortPriority for non-443", func(t *testing.T) {
		if p.PortPriority(80) {
			t.Error("PortPriority(80) = true, expected false")
		}
		if p.PortPriority(8443) {
			t.Error("PortPriority(8443) = true, expected false")
		}
	})

	t.Run("Priority", func(t *testing.T) {
		priority := p.Priority()
		if priority <= 1 {
			t.Errorf("Priority() = %d, expected > 1 (higher than HTTPS)", priority)
		}
	})
}

// TestShodanVectors contains test cases based on real-world Shodan data
// These simulate responses from actual VPN appliances
func TestShodanVectors(t *testing.T) {
	// AnyConnect Shodan vectors
	anyConnectVectors := []struct {
		name    string
		body    []byte
		headers http.Header
	}{
		{
			name: "Shodan AnyConnect Sample 1 - ASA 9.16",
			body: []byte(`<!DOCTYPE html>
<html><head><title>SSL VPN Service</title></head>
<body><form action="/+CSCOE+/logon.html" method="post">
<input type="hidden" name="webvpn">
</form></body></html>`),
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(3)14"},
				"Server":        []string{"Cisco ASA"},
			},
		},
		{
			name: "Shodan AnyConnect Sample 2 - ASA 9.14",
			body: []byte(`<html><head><meta http-equiv="refresh" content="0;url=/+CSCOT+/logon.html"></head></html>`),
			headers: http.Header{
				"Server": []string{"Cisco/ASA SSL VPN"},
			},
		},
		{
			name: "Shodan AnyConnect Sample 3 - Firepower",
			body: []byte(`<!DOCTYPE html><html>
<body>Firepower Threat Defense - AnyConnect</body></html>`),
			headers: http.Header{},
		},
		{
			name: "Shodan AnyConnect Sample 4 - Cookie detection",
			body: []byte(`<html><body>Login Page</body></html>`),
			headers: http.Header{
				"Set-Cookie": []string{"webvpncontext=0123456789abcdef; path=/; secure"},
			},
		},
		{
			name: "Shodan AnyConnect Sample 5 - X-Transcend-Version",
			body: []byte(`<html><body>VPN Portal</body></html>`),
			headers: http.Header{
				"X-Transcend-Version": []string{"9.12(4)"},
			},
		},
	}

	for _, tc := range anyConnectVectors {
		t.Run(tc.name, func(t *testing.T) {
			if !detectAnyConnect(tc.body, tc.headers) {
				t.Errorf("Failed to detect AnyConnect from Shodan sample")
			}
		})
	}

	// GlobalProtect Shodan vectors
	globalProtectVectors := []struct {
		name    string
		body    []byte
		headers http.Header
	}{
		{
			name: "Shodan GlobalProtect Sample 1 - PAN-OS 10.2",
			body: []byte(`<!DOCTYPE html>
<html><head><title>GlobalProtect Portal</title></head>
<body><form id="PAN_FORM" action="/global-protect/login.esp" method="post">
</form></body></html>`),
			headers: http.Header{
				"Server": []string{"PAN-OS 10.2.4"},
			},
		},
		{
			name: "Shodan GlobalProtect Sample 2 - PAN-OS 9.1",
			body: []byte(`<html><body>
<div class="global-protect-login">Palo Alto Networks GlobalProtect</div>
</body></html>`),
			headers: http.Header{
				"Server": []string{"Palo Alto Networks"},
			},
		},
		{
			name: "Shodan GlobalProtect Sample 3 - SSL-VPN path",
			body: []byte(`<!DOCTYPE html><html>
<form action="/ssl-vpn/login.esp">GlobalProtect</form></html>`),
			headers: http.Header{},
		},
		{
			name: "Shodan GlobalProtect Sample 4 - prelogin.esp response",
			body: []byte(`<?xml version="1.0" encoding="UTF-8"?>
<prelogin-response>
<status>Success</status>
<sw-version>10.2.3</sw-version>
<saml-auth-method>POST</saml-auth-method>
</prelogin-response>`),
			headers: http.Header{},
		},
		{
			name: "Shodan GlobalProtect Sample 5 - X-Private-Pan-Sslvpn header",
			body: []byte(`<html><body>VPN Portal</body></html>`),
			headers: http.Header{
				"X-Private-Pan-Sslvpn": []string{"auth-failed"},
			},
		},
		{
			name: "Shodan GlobalProtect Sample 6 - portal-prelogin",
			body: []byte(`<?xml version="1.0"?>
<portal-prelogin>
<portal>
<sw-version>10.1.6-h3</sw-version>
</portal>
</portal-prelogin>`),
			headers: http.Header{},
		},
	}

	for _, tc := range globalProtectVectors {
		t.Run(tc.name, func(t *testing.T) {
			if !detectGlobalProtect(tc.body, tc.headers) {
				t.Errorf("Failed to detect GlobalProtect from Shodan sample")
			}
		})
	}
}

// TestPreloginVersionExtraction tests version extraction from prelogin.esp responses
func TestPreloginVersionExtraction(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		expected string
	}{
		{
			name: "standard prelogin response",
			body: []byte(`<?xml version="1.0" encoding="UTF-8"?>
<prelogin-response>
<status>Success</status>
<sw-version>10.2.4</sw-version>
<region>Americas</region>
</prelogin-response>`),
			expected: "10.2.4",
		},
		{
			name: "prelogin with hotfix version",
			body: []byte(`<?xml version="1.0"?>
<prelogin-response>
<sw-version>10.1.9-h1</sw-version>
<saml-auth-method>REDIRECT</saml-auth-method>
</prelogin-response>`),
			expected: "10.1.9-h1",
		},
		{
			name: "prelogin with multiple tags",
			body: []byte(`<?xml version="1.0"?>
<prelogin-response>
<status>Success</status>
<ccusername/>
<autosubmit>false</autosubmit>
<sw-version>9.1.12</sw-version>
<saml-auth-method>POST</saml-auth-method>
<saml-request>base64data</saml-request>
</prelogin-response>`),
			expected: "9.1.12",
		},
		{
			name:     "no sw-version tag",
			body:     []byte(`<?xml version="1.0"?><prelogin-response><status>Error</status></prelogin-response>`),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractGlobalProtectVersion(tt.body, http.Header{})
			if result != tt.expected {
				t.Errorf("extractGlobalProtectVersion() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// TestEdgeCases tests edge cases and boundary conditions
func TestEdgeCases(t *testing.T) {
	tests := []struct {
		name                string
		body                []byte
		headers             http.Header
		expectAnyConnect    bool
		expectGlobalProtect bool
	}{
		{
			name:                "nil body",
			body:                nil,
			headers:             http.Header{},
			expectAnyConnect:    false,
			expectGlobalProtect: false,
		},
		{
			name:                "very large body without markers",
			body:                make([]byte, 1024*1024), // 1MB of zeros
			headers:             http.Header{},
			expectAnyConnect:    false,
			expectGlobalProtect: false,
		},
		{
			name:                "case sensitivity - lowercase webvpn",
			body:                []byte(`webvpn login page`),
			headers:             http.Header{},
			expectAnyConnect:    true,
			expectGlobalProtect: false,
		},
		{
			name:                "case sensitivity - uppercase GLOBALPROTECT",
			body:                []byte(`GLOBALPROTECT PORTAL`),
			headers:             http.Header{},
			expectAnyConnect:    false,
			expectGlobalProtect: true,
		},
		{
			name:                "mixed case GlobalProtect",
			body:                []byte(`GlObAlPrOtEcT`),
			headers:             http.Header{},
			expectAnyConnect:    false,
			expectGlobalProtect: true,
		},
		{
			name:                "both markers present (AnyConnect wins - checked first)",
			body:                []byte(`webvpn GlobalProtect`),
			headers:             http.Header{},
			expectAnyConnect:    true,
			expectGlobalProtect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+" (AnyConnect)", func(t *testing.T) {
			result := detectAnyConnect(tt.body, tt.headers)
			if result != tt.expectAnyConnect {
				t.Errorf("detectAnyConnect() = %v, expected %v", result, tt.expectAnyConnect)
			}
		})
		t.Run(tt.name+" (GlobalProtect)", func(t *testing.T) {
			result := detectGlobalProtect(tt.body, tt.headers)
			if result != tt.expectGlobalProtect {
				t.Errorf("detectGlobalProtect() = %v, expected %v", result, tt.expectGlobalProtect)
			}
		})
	}
}

// TestDetectionPaths verifies that all detection paths are defined
func TestDetectionPaths(t *testing.T) {
	t.Run("AnyConnect paths", func(t *testing.T) {
		if len(anyConnectPaths) < 2 {
			t.Errorf("Expected at least 2 AnyConnect paths, got %d", len(anyConnectPaths))
		}
		// Verify primary paths are present
		found := false
		for _, p := range anyConnectPaths {
			if p == "/+CSCOE+/logon.html" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Primary AnyConnect path /+CSCOE+/logon.html not found")
		}
	})

	t.Run("GlobalProtect paths", func(t *testing.T) {
		if len(globalProtectPaths) < 2 {
			t.Errorf("Expected at least 2 GlobalProtect paths, got %d", len(globalProtectPaths))
		}
		// Verify prelogin.esp is first (for version extraction)
		if globalProtectPaths[0] != "/global-protect/prelogin.esp" {
			t.Error("Expected /global-protect/prelogin.esp to be first GlobalProtect path")
		}
	})
}

// TestCookiePatterns verifies cookie detection patterns
func TestCookiePatterns(t *testing.T) {
	if len(anyConnectCookies) < 3 {
		t.Errorf("Expected at least 3 AnyConnect cookie patterns, got %d", len(anyConnectCookies))
	}

	// Verify essential cookies are in the list
	essential := []string{"webvpn", "webvpnlogin", "webvpncontext"}
	for _, cookie := range essential {
		found := false
		for _, c := range anyConnectCookies {
			if c == cookie {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Essential cookie %q not found in anyConnectCookies", cookie)
		}
	}
}

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
	"strings"
	"testing"
)

// sapPublicInfoXML is a realistic /sap/public/info response body used in tests.
const sapPublicInfoXML = `<?xml version="1.0" encoding="utf-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP-ENV:Body>
<rfc:RFC_SYSTEM_INFO.Response xmlns:rfc="urn:sap-com:document:sap:rfc:functions">
<RFCSI>
<RFCPROTO>011</RFCPROTO>
<RFCCHARTYP>1100</RFCCHARTYP>
<RFCINTTYP>LIT</RFCINTTYP>
<RFCFLOTYP>IE3</RFCFLOTYP>
<RFCDEST></RFCDEST>
<RFCHOST>sapserver01</RFCHOST>
<RFCSYSID>BRQ</RFCSYSID>
<RFCDATABS>BRQ</RFCDATABS>
<RFCDBHOST>hanadb01</RFCDBHOST>
<RFCDBSYS>HDB</RFCDBSYS>
<RFCSAPRL>750</RFCSAPRL>
<RFCMACH>390</RFCMACH>
<RFCOPSYS>Linux</RFCOPSYS>
<RFCTZONE>3600</RFCTZONE>
<RFCDAYST></RFCDAYST>
<RFCIPADDR>10.0.1.50</RFCIPADDR>
<RFCKERNRL>753</RFCKERNRL>
<RFCHOST2>sapserver01</RFCHOST2>
<RFCSI_RESV></RFCSI_RESV>
<RFCIPV6ADDR></RFCIPV6ADDR>
</RFCSI>
</rfc:RFC_SYSTEM_INFO.Response>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>`

func TestSAPNetWeaverFingerprinter_Name(t *testing.T) {
	f := &SAPNetWeaverFingerprinter{}
	if name := f.Name(); name != "sap-netweaver" {
		t.Errorf("Name() = %q, expected %q", name, "sap-netweaver")
	}
}

func TestSAPNetWeaverFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &SAPNetWeaverFingerprinter{}
	if endpoint := f.ProbeEndpoint(); endpoint != "/sap/public/info" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", endpoint, "/sap/public/info")
	}
}

func TestSAPNetWeaverFingerprinter_Match(t *testing.T) {
	f := &SAPNetWeaverFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "matches Server: SAP NetWeaver Application Server 7.45",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SAP NetWeaver Application Server 7.45"},
			},
			want: true,
		},
		{
			name:       "matches Server: SAP J2EE Engine/7.00",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SAP J2EE Engine/7.00"},
			},
			want: true,
		},
		{
			name:       "matches Server: SAP Web Dispatcher",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SAP Web Dispatcher"},
			},
			want: true,
		},
		{
			name:       "matches sap-server header present",
			statusCode: 200,
			headers: http.Header{
				"Sap-Server": []string{"true"},
			},
			want: true,
		},
		{
			name:       "matches sap-system header present",
			statusCode: 200,
			headers: http.Header{
				"Sap-System": []string{"PRD"},
			},
			want: true,
		},
		{
			name:       "matches disp+work header present",
			statusCode: 200,
			headers: http.Header{
				"Disp+work": []string{"1"},
			},
			want: true,
		},
		{
			name:       "does not match Server: nginx",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"nginx"},
			},
			want: false,
		},
		{
			name:       "does not match Server: Apache",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Apache"},
			},
			want: false,
		},
		{
			name:       "does not match 500 response even with SAP header",
			statusCode: 500,
			headers: http.Header{
				"Sap-Server": []string{"true"},
			},
			want: false,
		},
		// Status code boundary tests
		{
			name:       "1xx rejection: status 100 with Sap-Server",
			statusCode: 100,
			headers: http.Header{
				"Sap-Server": []string{"true"},
			},
			want: false,
		},
		{
			name:       "1xx boundary: status 199 with Sap-Server",
			statusCode: 199,
			headers: http.Header{
				"Sap-Server": []string{"true"},
			},
			want: false,
		},
		{
			name:       "3xx acceptance: status 301 with Sap-Server",
			statusCode: 301,
			headers: http.Header{
				"Sap-Server": []string{"true"},
			},
			want: true,
		},
		{
			name:       "4xx acceptance: status 403 with SAP Server header",
			statusCode: 403,
			headers: http.Header{
				"Server": []string{"SAP NetWeaver Application Server 7.45"},
			},
			want: true,
		},
		{
			name:       "4xx boundary: status 499 with Sap-System",
			statusCode: 499,
			headers: http.Header{
				"Sap-System": []string{"PRD"},
			},
			want: true,
		},
		{
			name:       "empty headers: status 200 with no headers",
			statusCode: 200,
			headers:    http.Header{},
			want:       false,
		},
		{
			name:       "multiple SAP indicators all present",
			statusCode: 200,
			headers: http.Header{
				"Server":     []string{"SAP NetWeaver Application Server 7.45"},
				"Sap-Server": []string{"true"},
				"Sap-System": []string{"PRD"},
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

func TestSAPNetWeaverFingerprinter_Fingerprint(t *testing.T) {
	f := &SAPNetWeaverFingerprinter{}

	tests := []struct {
		name          string
		statusCode    int
		headers       http.Header
		body          string
		wantResult    bool
		wantTech      string
		wantVersion   string
		wantCPEPrefix string
		wantCPE       string
		wantStackType string
		wantSID       string
		wantKernelVer string
		wantOS        string
		wantDatabase  string
		wantVendor    string
		wantProduct   string
	}{
		{
			name:       "detects from Server header with version extraction",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SAP NetWeaver Application Server 7.45"},
			},
			body:          `<html><body>SAP NetWeaver</body></html>`,
			wantResult:    true,
			wantTech:      "sap-netweaver",
			wantVersion:   "7.45",
			wantCPEPrefix: "cpe:2.3:a:sap:netweaver:7.45",
		},
		{
			name:       "detects from sap-server header (no version)",
			statusCode: 200,
			headers: http.Header{
				"Sap-Server": []string{"true"},
			},
			body:       `<html><body>Welcome</body></html>`,
			wantResult: true,
			wantTech:   "sap-netweaver",
		},
		{
			name:       "detects from /sap/public/info XML with full metadata extraction",
			statusCode: 200,
			headers:    http.Header{},
			body:       sapPublicInfoXML,
			wantResult: true,
			wantTech:   "sap-netweaver",
			wantSID:    "BRQ",
		},
		{
			name:       "extracts SAP release version from RFCSAPRL",
			statusCode: 200,
			headers:    http.Header{},
			body:       sapPublicInfoXML,
			wantResult:  true,
			wantTech:    "sap-netweaver",
			wantVersion: "7.50",
		},
		{
			name:       "extracts kernel version from RFCKERNRL",
			statusCode: 200,
			headers:    http.Header{},
			body:       sapPublicInfoXML,
			wantResult:    true,
			wantTech:      "sap-netweaver",
			wantKernelVer: "7.53",
		},
		{
			name:       "detects Java stack from Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SAP J2EE Engine/7.00"},
			},
			body:          `<html><body>SAP J2EE</body></html>`,
			wantResult:    true,
			wantTech:      "sap-netweaver",
			wantStackType: "java",
		},
		{
			name:       "detects ABAP stack from Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SAP NetWeaver Application Server / ABAP 753"},
			},
			body:          `<html><body>ABAP</body></html>`,
			wantResult:    true,
			wantTech:      "sap-netweaver",
			wantStackType: "abap",
		},
		{
			name:       "does not detect from generic HTTP response",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"nginx/1.18.0"},
			},
			body:       `<!DOCTYPE html><html><body>Welcome</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not detect from 500 response",
			statusCode: 500,
			headers: http.Header{
				"Sap-Server": []string{"true"},
			},
			body:       `<html><body>Internal Server Error</body></html>`,
			wantResult: false,
		},
		{
			name:       "handles malformed XML gracefully (returns header-only detection)",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SAP NetWeaver Application Server 7.45"},
			},
			body:        `<?xml version="1.0"?><SOAP-ENV:Envelope><truncated`,
			wantResult:  true,
			wantTech:    "sap-netweaver",
			wantVersion: "7.45",
		},
		// Critical edge cases
		{
			name:       "empty body with SAP header detects from header alone",
			statusCode: 200,
			headers: http.Header{
				"Sap-Server": []string{"true"},
			},
			body:       "",
			wantResult: true,
			wantTech:   "sap-netweaver",
		},
		{
			name:       "body-only detection no SAP headers RFCSYSID triggers body match",
			statusCode: 200,
			headers:    http.Header{},
			body:       sapPublicInfoXML,
			wantResult: true,
			wantTech:   "sap-netweaver",
			wantSID:    "BRQ",
		},
		{
			name:       "body has RFCSAPRL but not RFCSYSID no body match",
			statusCode: 200,
			headers:    http.Header{},
			body:       "<RFCSAPRL>750</RFCSAPRL>",
			wantResult: false,
		},
		{
			name:       "version priority header overrides RFCSAPRL",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SAP NetWeaver Application Server 7.45"},
			},
			body:        sapPublicInfoXML,
			wantResult:  true,
			wantTech:    "sap-netweaver",
			wantVersion: "7.45",
		},
		{
			name:       "RFCKERNRL-only version when no RFCSAPRL",
			statusCode: 200,
			headers:    http.Header{},
			body:       "<RFCSYSID>TST</RFCSYSID><RFCKERNRL>753</RFCKERNRL>",
			wantResult:  true,
			wantTech:    "sap-netweaver",
			wantVersion: "7.53",
		},
		{
			name:       "disp+work triggers ABAP stack type without abap in Server",
			statusCode: 200,
			headers: http.Header{
				"Disp+work": []string{"1"},
			},
			body:          `<html></html>`,
			wantResult:    true,
			wantTech:      "sap-netweaver",
			wantStackType: "abap",
		},
		{
			name:       "CPE wildcard when no version available",
			statusCode: 200,
			headers: http.Header{
				"Sap-Server": []string{"true"},
			},
			body:       `<html></html>`,
			wantResult: true,
			wantTech:   "sap-netweaver",
			wantCPE:    "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*",
		},
		{
			name:       "full metadata verification from sapPublicInfoXML",
			statusCode: 200,
			headers:    http.Header{},
			body:       sapPublicInfoXML,
			wantResult:  true,
			wantTech:    "sap-netweaver",
			wantSID:     "BRQ",
			wantKernelVer: "7.53",
			wantOS:      "Linux",
			wantDatabase: "HDB",
			wantVendor:  "SAP",
			wantProduct: "NetWeaver",
		},
		{
			name:       "4xx with SAP header still fingerprints",
			statusCode: 403,
			headers: http.Header{
				"Server": []string{"SAP NetWeaver Application Server 7.45"},
			},
			body:        "<html>Forbidden</html>",
			wantResult:  true,
			wantTech:    "sap-netweaver",
			wantVersion: "7.45",
		},
		{
			name:       "binary garbage body with SAP header does not crash",
			statusCode: 200,
			headers: http.Header{
				"Sap-Server": []string{"true"},
			},
			body:       "\x00\x01\x02\xff\xfe\xfd",
			wantResult: true,
			wantTech:   "sap-netweaver",
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

			if result.Technology != tt.wantTech {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
			}

			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			if tt.wantCPEPrefix != "" && len(result.CPEs) > 0 {
				if !strings.HasPrefix(result.CPEs[0], tt.wantCPEPrefix) {
					t.Errorf("CPE = %q, want prefix %q", result.CPEs[0], tt.wantCPEPrefix)
				}
			}

			if tt.wantCPE != "" {
				if len(result.CPEs) == 0 {
					t.Errorf("CPEs is empty, want %q", tt.wantCPE)
				} else if result.CPEs[0] != tt.wantCPE {
					t.Errorf("CPE = %q, want %q", result.CPEs[0], tt.wantCPE)
				}
			}

			if tt.wantStackType != "" {
				stackType, _ := result.Metadata["stack_type"].(string)
				if stackType != tt.wantStackType {
					t.Errorf("stackType = %q, want %q", stackType, tt.wantStackType)
				}
			}

			if tt.wantSID != "" {
				sid, _ := result.Metadata["sid"].(string)
				if sid != tt.wantSID {
					t.Errorf("sid = %q, want %q", sid, tt.wantSID)
				}
			}

			if tt.wantKernelVer != "" {
				kernelVersion, _ := result.Metadata["kernel_version"].(string)
				if kernelVersion != tt.wantKernelVer {
					t.Errorf("kernelVersion = %q, want %q", kernelVersion, tt.wantKernelVer)
				}
			}

			if tt.wantOS != "" {
				os, _ := result.Metadata["os"].(string)
				if os != tt.wantOS {
					t.Errorf("os = %q, want %q", os, tt.wantOS)
				}
			}

			if tt.wantDatabase != "" {
				database, _ := result.Metadata["database"].(string)
				if database != tt.wantDatabase {
					t.Errorf("database = %q, want %q", database, tt.wantDatabase)
				}
			}

			if tt.wantVendor != "" {
				vendor, _ := result.Metadata["vendor"].(string)
				if vendor != tt.wantVendor {
					t.Errorf("vendor = %q, want %q", vendor, tt.wantVendor)
				}
			}

			if tt.wantProduct != "" {
				product, _ := result.Metadata["product"].(string)
				if product != tt.wantProduct {
					t.Errorf("product = %q, want %q", product, tt.wantProduct)
				}
			}
		})
	}
}

func TestExtractXMLField(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		fieldName string
		want      string
	}{
		{
			name:      "extracts RFCSYSID",
			body:      "<RFCSYSID>BRQ</RFCSYSID>",
			fieldName: "RFCSYSID",
			want:      "BRQ",
		},
		{
			name:      "extracts RFCSAPRL",
			body:      "<RFCSAPRL>750</RFCSAPRL>",
			fieldName: "RFCSAPRL",
			want:      "750",
		},
		{
			name:      "extracts RFCOPSYS",
			body:      "<RFCOPSYS>Linux</RFCOPSYS>",
			fieldName: "RFCOPSYS",
			want:      "Linux",
		},
		{
			name:      "returns empty for missing field",
			body:      "<RFCSYSID>BRQ</RFCSYSID>",
			fieldName: "RFCOPSYS",
			want:      "",
		},
		{
			name:      "handles empty element",
			body:      "<RFCDAYST></RFCDAYST>",
			fieldName: "RFCDAYST",
			want:      "",
		},
		{
			name:      "trims whitespace",
			body:      "<RFCOPSYS>  Linux  </RFCOPSYS>",
			fieldName: "RFCOPSYS",
			want:      "Linux",
		},
		{
			name:      "extracts from full XML body",
			body:      sapPublicInfoXML,
			fieldName: "RFCSYSID",
			want:      "BRQ",
		},
		{
			name:      "extracts RFCDBSYS from full XML",
			body:      sapPublicInfoXML,
			fieldName: "RFCDBSYS",
			want:      "HDB",
		},
		// Edge cases
		{
			name:      "empty body returns empty",
			body:      "",
			fieldName: "RFCSYSID",
			want:      "",
		},
		{
			name:      "duplicate tags returns first value",
			body:      "<RFCSYSID>FIRST</RFCSYSID><RFCSYSID>SECOND</RFCSYSID>",
			fieldName: "RFCSYSID",
			want:      "FIRST",
		},
		{
			name:      "open tag without close tag truncated returns empty",
			body:      "<RFCSYSID>BRQ",
			fieldName: "RFCSYSID",
			want:      "",
		},
		{
			name:      "only close tag returns empty",
			body:      "</RFCSYSID>",
			fieldName: "RFCSYSID",
			want:      "",
		},
		{
			name:      "tag name as substring of value",
			body:      "<RFCSYSID>RFCSYSID_VALUE</RFCSYSID>",
			fieldName: "RFCSYSID",
			want:      "RFCSYSID_VALUE",
		},
		{
			name:      "newlines inside value are trimmed",
			body:      "<RFCOPSYS>\n  Linux\n</RFCOPSYS>",
			fieldName: "RFCOPSYS",
			want:      "Linux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractXMLField(tt.body, tt.fieldName); got != tt.want {
				t.Errorf("extractXMLField() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractSAPVersionFromServer(t *testing.T) {
	tests := []struct {
		name         string
		serverHeader string
		want         string
	}{
		{
			name:         "empty string",
			serverHeader: "",
			want:         "",
		},
		{
			name:         "SAP Web Dispatcher no version",
			serverHeader: "SAP Web Dispatcher",
			want:         "",
		},
		{
			name:         "SAP NetWeaver Application Server 7.45",
			serverHeader: "SAP NetWeaver Application Server 7.45",
			want:         "7.45",
		},
		{
			name:         "SAP NetWeaver Application Server / ABAP 753 normalized",
			serverHeader: "SAP NetWeaver Application Server / ABAP 753",
			want:         "7.53",
		},
		{
			name:         "SAP J2EE Engine/7.00",
			serverHeader: "SAP J2EE Engine/7.00",
			want:         "7.00",
		},
		{
			name:         "SAP Application Server 7.31 no NetWeaver",
			serverHeader: "SAP Application Server 7.31",
			want:         "7.31",
		},
		{
			name:         "nginx not SAP",
			serverHeader: "nginx/1.18.0",
			want:         "",
		},
		{
			name:         "lowercase sap netweaver case-insensitive",
			serverHeader: "sap netweaver application server 7.45",
			want:         "7.45",
		},
		{
			name:         "SAP NetWeaver Application Server / ABAP no version after ABAP",
			serverHeader: "SAP NetWeaver Application Server / ABAP",
			want:         "",
		},
		{
			name:         "SAP NetWeaver Application Server 7.45.1 multi-part version",
			serverHeader: "SAP NetWeaver Application Server 7.45.1",
			want:         "7.45.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractSAPVersionFromServer(tt.serverHeader); got != tt.want {
				t.Errorf("extractSAPVersionFromServer(%q) = %q, want %q", tt.serverHeader, got, tt.want)
			}
		})
	}
}

func TestNormalizeSAPRelease(t *testing.T) {
	tests := []struct {
		release string
		want    string
	}{
		{
			release: "750",
			want:    "7.50",
		},
		{
			release: "753",
			want:    "7.53",
		},
		{
			release: "700",
			want:    "7.00",
		},
		{
			release: "7.45",
			want:    "7.45",
		},
		{
			release: "7.00",
			want:    "7.00",
		},
		{
			release: "",
			want:    "",
		},
		// Edge cases
		{
			release: "7",
			want:    "7",
		},
		{
			release: "75",
			want:    "75",
		},
		{
			release: "7500",
			want:    "7500",
		},
		{
			release: "abc",
			want:    "abc",
		},
		{
			release: "070",
			want:    "0.70",
		},
	}

	for _, tt := range tests {
		t.Run("release_"+tt.release, func(t *testing.T) {
			if got := normalizeSAPRelease(tt.release); got != tt.want {
				t.Errorf("normalizeSAPRelease(%q) = %q, want %q", tt.release, got, tt.want)
			}
		})
	}
}

func TestIsValidVersion(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"7.50", true},
		{"7.45", true},
		{"753", true},
		{"1.2.3", true},
		{"10", true},
		// malicious / unexpected inputs
		{"", false},
		{"7.50 injected", false},
		{"../../etc/passwd", false},
		{"<script>alert(1)</script>", false},
		{"7.50\x00null", false},
		{"version-7.50", false},
		// edge cases
		{".7.50", false},
		{"7.50.", false},
		{"7..50", false},
		{".", false},
		{"0", true},
		{"0.0.0", true},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := isValidVersion(tt.version); got != tt.want {
				t.Errorf("isValidVersion(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestBuildSAPNetWeaverCPE_MaliciousVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantCPE string
	}{
		{
			name:    "valid version passes through",
			version: "7.50",
			wantCPE: "cpe:2.3:a:sap:netweaver:7.50:*:*:*:*:*:*:*",
		},
		{
			name:    "injected string replaced with wildcard",
			version: "7.50 injected content",
			wantCPE: "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*",
		},
		{
			name:    "path traversal replaced with wildcard",
			version: "../../etc/passwd",
			wantCPE: "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version replaced with wildcard",
			version: "",
			wantCPE: "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildSAPNetWeaverCPE(tt.version); got != tt.wantCPE {
				t.Errorf("buildSAPNetWeaverCPE(%q) = %q, want %q", tt.version, got, tt.wantCPE)
			}
		})
	}
}

func TestExtractXMLField_OversizedValue(t *testing.T) {
	// Build a value that exceeds maxXMLFieldLen (256 bytes)
	oversized := strings.Repeat("A", maxXMLFieldLen+1)
	body := "<RFCSYSID>" + oversized + "</RFCSYSID>"

	got := extractXMLField(body, "RFCSYSID")
	if got != "" {
		t.Errorf("extractXMLField() with oversized value = %q (len %d), want empty string", got, len(got))
	}

	// Value exactly at limit should pass
	atLimit := strings.Repeat("B", maxXMLFieldLen)
	body2 := "<RFCSYSID>" + atLimit + "</RFCSYSID>"
	got2 := extractXMLField(body2, "RFCSYSID")
	if len(got2) != maxXMLFieldLen {
		t.Errorf("extractXMLField() at limit = len %d, want %d", len(got2), maxXMLFieldLen)
	}
}

func TestSanitizeXMLValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "normal printable ASCII passes through",
			input: "Linux",
			want:  "Linux",
		},
		{
			name:  "control characters stripped",
			input: "Linux\x00\x01\x1f",
			want:  "Linux",
		},
		{
			name:  "newline stripped",
			input: "Linux\nWindows",
			want:  "LinuxWindows",
		},
		{
			name:  "tab stripped",
			input: "Linux\tWindows",
			want:  "LinuxWindows",
		},
		{
			name:  "value at maxXMLFieldLen is not truncated",
			input: strings.Repeat("X", maxXMLFieldLen),
			want:  strings.Repeat("X", maxXMLFieldLen),
		},
		{
			name:  "value over maxXMLFieldLen is truncated",
			input: strings.Repeat("X", maxXMLFieldLen+10),
			want:  strings.Repeat("X", maxXMLFieldLen),
		},
		{
			name:  "empty string passes through",
			input: "",
			want:  "",
		},
		// Edge cases
		{
			name:  "DEL character (0x7F) above 126 is stripped",
			input: "Linux\x7f",
			want:  "Linux",
		},
		{
			name:  "unicode above ASCII 126 is stripped space remains",
			input: "Linux \xc3\xb1", // ñ encoded as UTF-8 bytes, each > 126
			want:  "Linux ",
		},
		{
			name:  "only control chars results in empty string",
			input: "\x00\x01\x02\x03",
			want:  "",
		},
		{
			name:  "mixed printable and control chars",
			input: "L\x01i\x02n\x03u\x04x",
			want:  "Linux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeXMLValue(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeXMLValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildSAPNetWeaverCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "7.50",
			want:    "cpe:2.3:a:sap:netweaver:7.50:*:*:*:*:*:*:*",
		},
		{
			version: "7.45",
			want:    "cpe:2.3:a:sap:netweaver:7.45:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:a:sap:netweaver:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := buildSAPNetWeaverCPE(tt.version); got != tt.want {
				t.Errorf("buildSAPNetWeaverCPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

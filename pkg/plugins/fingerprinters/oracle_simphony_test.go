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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Name / ProbeEndpoint ─────────────────────────────────────────────────────

func TestOracleSimphonyFingerprinter_Name(t *testing.T) {
	fp := &OracleSimphonyFingerprinter{}
	assert.Equal(t, "oracle_simphony", fp.Name())
}

func TestOracleSimphonyFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &OracleSimphonyFingerprinter{}
	assert.Equal(t, "/EGateway/EGateway.asmx", fp.ProbeEndpoint())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestOracleSimphonyFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{
			name:        "200 text/xml → true",
			statusCode:  200,
			contentType: "text/xml",
			want:        true,
		},
		{
			name:        "200 text/xml; charset=utf-8 → true",
			statusCode:  200,
			contentType: "text/xml; charset=utf-8",
			want:        true,
		},
		{
			name:        "200 text/html → true",
			statusCode:  200,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "200 TEXT/XML mixed case → true",
			statusCode:  200,
			contentType: "TEXT/XML",
			want:        true,
		},
		{
			name:        "200 application/json → false",
			statusCode:  200,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "200 text/plain → false",
			statusCode:  200,
			contentType: "text/plain",
			want:        false,
		},
		{
			name:       "200 no content-type → false",
			statusCode: 200,
			want:       false,
		},
		{
			name:        "400 text/html → true (4xx in range)",
			statusCode:  400,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "401 text/xml → true",
			statusCode:  401,
			contentType: "text/xml",
			want:        true,
		},
		{
			name:        "403 text/html → true",
			statusCode:  403,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "500 text/html → false",
			statusCode:  500,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "503 text/xml → false",
			statusCode:  503,
			contentType: "text/xml",
			want:        false,
		},
		{
			name:        "199 text/html → false",
			statusCode:  199,
			contentType: "text/html",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OracleSimphonyFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint positive cases ────────────────────────────────────────────────

func TestOracleSimphonyFingerprinter_Fingerprint_Positive(t *testing.T) {
	tests := []struct {
		name                string
		body                string
		serverHeader        string
		wantDetectionMethod string
		wantServerHeader    bool
	}{
		{
			name:                "micros_namespace signal",
			body:                `<soap:operation soapAction="http://micros-hosting.com/EGateway/ProcessDimeRequest"`,
			wantDetectionMethod: "micros_namespace",
		},
		{
			name:                "egateway_soap_port signal (no micros-hosting.com)",
			body:                `<portType name="EGatewaySoap">`,
			wantDetectionMethod: "egateway_soap_port",
		},
		{
			name:                "process_dime_operation signal (no EGatewaySoap, no micros-hosting.com)",
			body:                `<operation name="ProcessDimeRequest">`,
			wantDetectionMethod: "process_dime_operation",
		},
		{
			name:                "server_header signal (body has no markers)",
			body:                `<html><body>Service Unavailable</body></html>`,
			serverHeader:        "mCommerceMobileWebServer",
			wantDetectionMethod: "server_header",
			wantServerHeader:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OracleSimphonyFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/xml; charset=utf-8")
			if tt.serverHeader != "" {
				resp.Header.Set("Server", tt.serverHeader)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result, "expected positive detection")

			assert.Equal(t, "oracle_simphony", result.Technology)
			assert.Equal(t, "", result.Version)
			assert.Equal(t, tt.wantDetectionMethod, result.Metadata["detection_method"])

			if tt.wantServerHeader {
				assert.Equal(t, tt.serverHeader, result.Metadata["server_header"],
					"server_header key should be present when mCommerceMobileWebServer detected")
			} else {
				_, hasServerHdr := result.Metadata["server_header"]
				assert.False(t, hasServerHdr,
					"server_header key must not be present for body-only detection")
			}
		})
	}
}

// ── Fingerprint priority test ─────────────────────────────────────────────────

func TestOracleSimphonyFingerprinter_Fingerprint_Priority(t *testing.T) {
	// Body contains ALL body markers AND the server header — micros_namespace wins.
	body := `<soap:operation soapAction="http://micros-hosting.com/EGateway/ProcessDimeRequest"` +
		`<portType name="EGatewaySoap">` +
		`<operation name="ProcessDimeRequest">`

	fp := &OracleSimphonyFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/xml; charset=utf-8")
	resp.Header.Set("Server", "mCommerceMobileWebServer")

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "micros_namespace", result.Metadata["detection_method"],
		"micros_namespace must take priority over all other signals")
}

// ── Fingerprint full WSDL test ────────────────────────────────────────────────

// simphonyWSDLSnippet is a realistic excerpt from the MICROS EGateway WSDL,
// based on the Cymmetria micros_honeypot structure. It includes the EGatewaySoap
// portType (with ProcessDimeRequest) and the micros-hosting.com soapAction namespace.
const simphonyWSDLSnippet = `<?xml version="1.0" encoding="utf-8"?>
<definitions xmlns:http="http://schemas.xmlsoap.org/wsdl/http/"
    xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
    xmlns:s="http://www.w3.org/2001/XMLSchema"
    xmlns:tns="http://tempuri.org/"
    targetNamespace="http://tempuri.org/"
    name="EGateway">
  <portType name="EGatewaySoap">
    <operation name="ProcessBase64Request">
      <input message="tns:ProcessBase64RequestSoapIn"/>
      <output message="tns:ProcessBase64RequestSoapOut"/>
    </operation>
    <operation name="ProcessDimeRequest">
      <input message="tns:ProcessDimeRequestSoapIn"/>
      <output message="tns:ProcessDimeRequestSoapOut"/>
    </operation>
    <operation name="ProcessDimeTestRequest">
      <input message="tns:ProcessDimeTestRequestSoapIn"/>
      <output message="tns:ProcessDimeTestRequestSoapOut"/>
    </operation>
    <operation name="SayHello">
      <input message="tns:SayHelloSoapIn"/>
      <output message="tns:SayHelloSoapOut"/>
    </operation>
  </portType>
  <portType name="EGatewayHttpGet">
    <operation name="ProcessBase64Request">
      <input message="tns:ProcessBase64RequestHttpGetIn"/>
      <output message="tns:ProcessBase64RequestHttpGetOut"/>
    </operation>
  </portType>
  <portType name="EGatewayHttpPost">
    <operation name="ProcessBase64Request">
      <input message="tns:ProcessBase64RequestHttpPostIn"/>
      <output message="tns:ProcessBase64RequestHttpPostOut"/>
    </operation>
  </portType>
  <binding name="EGatewaySoap" type="tns:EGatewaySoap">
    <soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
    <operation name="ProcessBase64Request">
      <soap:operation soapAction="http://micros-hosting.com/EGateway/ProcessBase64Request" style="document"/>
    </operation>
    <operation name="ProcessDimeRequest">
      <soap:operation soapAction="http://micros-hosting.com/EGateway/ProcessDimeRequest" style="document"/>
    </operation>
  </binding>
  <service name="EGateway">
    <port name="EGatewaySoap" binding="tns:EGatewaySoap">
      <soap:address location="http://target/EGateway/EGateway.asmx"/>
    </port>
    <port name="EGatewayHttpGet" binding="tns:EGatewayHttpGet">
      <http:address location="http://target/EGateway/EGateway.asmx"/>
    </port>
    <port name="EGatewayHttpPost" binding="tns:EGatewayHttpPost">
      <http:address location="http://target/EGateway/EGateway.asmx"/>
    </port>
  </service>
</definitions>`

func TestOracleSimphonyFingerprinter_Fingerprint_FullWSDL(t *testing.T) {
	fp := &OracleSimphonyFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/xml; charset=utf-8")

	result, err := fp.Fingerprint(resp, []byte(simphonyWSDLSnippet))
	require.NoError(t, err)
	require.NotNil(t, result, "WSDL with EGatewaySoap + ProcessDimeRequest must be detected")

	assert.Equal(t, "oracle_simphony", result.Technology)
	assert.Equal(t, "", result.Version)
	require.Len(t, result.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:hospitality_simphony:*:*:*:*:*:*:*:*", result.CPEs[0])

	assert.Equal(t, "micros_namespace", result.Metadata["detection_method"])
	assert.Equal(t, "Oracle", result.Metadata["vendor"])
	assert.Equal(t, "Oracle Hospitality Simphony", result.Metadata["product"])
	assert.Equal(t, "MICROS EGateway", result.Metadata["aka"])
	assert.Equal(t, "/EGateway/EGateway.asmx", result.Metadata["service_path"])
}

// ── Fingerprint negative cases ────────────────────────────────────────────────

func TestOracleSimphonyFingerprinter_Fingerprint_Negative(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "reflection guard: probe path echo only → nil",
			body: "<html><body>Error: /EGateway/EGateway.asmx not found</body></html>",
		},
		{
			name: "generic WSDL with different service name → nil",
			body: "<definitions><portType name=\"SomeOtherService\">",
		},
		{
			name: "empty body → nil",
			body: "",
		},
		{
			name: "generic HTML page → nil",
			body: "<html><head><title>Welcome</title></head><body><p>Hello world</p></body></html>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OracleSimphonyFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/xml")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// ── Fingerprint edge cases ────────────────────────────────────────────────────

func TestOracleSimphonyFingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	fp := &OracleSimphonyFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/xml")
	// Build a body > 2 MiB that contains a valid marker — must still return nil.
	prefix := strings.Repeat("x", 2*1024*1024)
	bigBody := []byte(prefix + "EGatewaySoap")
	result, err := fp.Fingerprint(resp, bigBody)
	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestOracleSimphonyFingerprinter_Fingerprint_ServerHeaderCaseInsensitive(t *testing.T) {
	fp := &OracleSimphonyFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/xml")
	resp.Header.Set("Server", "MCOMMERCEMOBILEWEBSERVER") // all caps
	// body has no other markers
	result, err := fp.Fingerprint(resp, []byte("<html><body>generic</body></html>"))
	require.NoError(t, err)
	require.NotNil(t, result, "EqualFold match on Server header must detect")
	assert.Equal(t, "server_header", result.Metadata["detection_method"])
}

func TestOracleSimphonyFingerprinter_Fingerprint_MicrosNamespaceCaseInsensitive(t *testing.T) {
	fp := &OracleSimphonyFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/xml")
	// Uppercase namespace — ToLower search must still detect.
	body := `soapAction="http://MICROS-HOSTING.COM/EGATEWAY/SomeOp"`
	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result, "case-insensitive namespace match must detect")
	assert.Equal(t, "micros_namespace", result.Metadata["detection_method"])
}

// ── Metadata assertions ───────────────────────────────────────────────────────

func TestOracleSimphonyFingerprinter_Fingerprint_MetadataAlwaysPresent(t *testing.T) {
	fp := &OracleSimphonyFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/xml")

	// Trigger via body-only detection (egateway_soap_port).
	result, err := fp.Fingerprint(resp, []byte(`<portType name="EGatewaySoap">`))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "Oracle", result.Metadata["vendor"])
	assert.Equal(t, "Oracle Hospitality Simphony", result.Metadata["product"])
	assert.Equal(t, "MICROS EGateway", result.Metadata["aka"])
	assert.Equal(t, "/EGateway/EGateway.asmx", result.Metadata["service_path"])
	assert.NotEmpty(t, result.Metadata["detection_method"])

	// server_header key must NOT be present for body-only detection.
	_, hasServerHdr := result.Metadata["server_header"]
	assert.False(t, hasServerHdr)
}

func TestOracleSimphonyFingerprinter_Fingerprint_ServerHeaderKeyPresentOnlyWhenDetected(t *testing.T) {
	fp := &OracleSimphonyFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/xml")
	resp.Header.Set("Server", "mCommerceMobileWebServer")

	result, err := fp.Fingerprint(resp, []byte("<html><body>generic</body></html>"))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "mCommerceMobileWebServer", result.Metadata["server_header"])
}

// ── buildOracleSimphonyCPE ────────────────────────────────────────────────────

func TestBuildOracleSimphonyCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "empty version → wildcard",
			version:  "",
			expected: "cpe:2.3:a:oracle:hospitality_simphony:*:*:*:*:*:*:*:*",
		},
		{
			name:     "specific version",
			version:  "2.9",
			expected: "cpe:2.3:a:oracle:hospitality_simphony:2.9:*:*:*:*:*:*:*",
		},
		{
			name:     "colon in version → wildcard",
			version:  "a:b",
			expected: "cpe:2.3:a:oracle:hospitality_simphony:*:*:*:*:*:*:*:*",
		},
		{
			name:     "asterisk in version → wildcard",
			version:  "*",
			expected: "cpe:2.3:a:oracle:hospitality_simphony:*:*:*:*:*:*:*:*",
		},
		{
			name:     "question mark in version → wildcard",
			version:  "a?b",
			expected: "cpe:2.3:a:oracle:hospitality_simphony:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildOracleSimphonyCPE(tt.version))
		})
	}
}

// ── Severity / SecurityFindings ──────────────────────────────────────────────

func TestOracleSimphonyFingerprinter_NoSeverityOrFindings(t *testing.T) {
	fp := &OracleSimphonyFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/xml")

	result, err := fp.Fingerprint(resp, []byte(`<portType name="EGatewaySoap">`))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Zero(t, result.Severity, "fingerprinter-only: Severity must be unset")
	assert.Nil(t, result.SecurityFindings, "fingerprinter-only: no SecurityFindings")
}

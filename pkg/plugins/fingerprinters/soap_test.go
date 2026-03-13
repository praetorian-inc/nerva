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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSOAPFingerprinter_Name(t *testing.T) {
	fp := &SOAPFingerprinter{}
	assert.Equal(t, "soap", fp.Name())
}

func TestSOAPFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &SOAPFingerprinter{}
	assert.Equal(t, "?wsdl", fp.ProbeEndpoint())
}

func TestSOAPFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{
			name:        "matches application/soap+xml (SOAP 1.2)",
			contentType: "application/soap+xml",
			expected:    true,
		},
		{
			name:        "matches application/soap+xml with charset",
			contentType: "application/soap+xml; charset=utf-8",
			expected:    true,
		},
		{
			name:        "matches text/xml (SOAP 1.1)",
			contentType: "text/xml",
			expected:    true,
		},
		{
			name:        "matches text/xml with charset",
			contentType: "text/xml; charset=utf-8",
			expected:    true,
		},
		{
			name:        "matches application/xml",
			contentType: "application/xml",
			expected:    true,
		},
		{
			name:        "does not match application/json",
			contentType: "application/json",
			expected:    false,
		},
		{
			name:        "does not match text/html",
			contentType: "text/html",
			expected:    false,
		},
		{
			name:        "does not match empty content type",
			contentType: "",
			expected:    false,
		},
		{
			name:        "does not match text/plain",
			contentType: "text/plain",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SOAPFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestSOAPFingerprinter_Fingerprint_SOAP11Envelope(t *testing.T) {
	fp := &SOAPFingerprinter{}
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
  xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/1999/XMLSchema">
  <SOAP-ENV:Body>
    <ns:GetPriceResponse xmlns:ns="http://example.com/service">
      <ns:Price>34.5</ns:Price>
    </ns:GetPriceResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`)

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"text/xml; charset=utf-8"},
		},
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "soap", result.Technology)
	assert.Equal(t, "1.1", result.Version)
	assert.Equal(t, "1.1", result.Metadata["soap_version"])
	assert.Equal(t, false, result.Metadata["wsdl_available"])
}

func TestSOAPFingerprinter_Fingerprint_SOAP12Envelope(t *testing.T) {
	fp := &SOAPFingerprinter{}
	body := []byte(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
  xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soap:Body>
    <ProcessResponse xmlns="http://example.com/service">
      <Result>Success</Result>
    </ProcessResponse>
  </soap:Body>
</soap:Envelope>`)

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/soap+xml; charset=utf-8"},
		},
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "soap", result.Technology)
	assert.Equal(t, "1.2", result.Version)
	assert.Equal(t, "1.2", result.Metadata["soap_version"])
	assert.Equal(t, false, result.Metadata["wsdl_available"])
}

func TestSOAPFingerprinter_Fingerprint_SOAP12ContentTypeOnly(t *testing.T) {
	fp := &SOAPFingerprinter{}
	// Minimal body without explicit namespace (Content-Type is definitive for SOAP 1.2)
	body := []byte(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <Response>OK</Response>
  </soap:Body>
</soap:Envelope>`)

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/soap+xml; charset=utf-8; action=\"http://example.com/Action\""},
		},
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "soap", result.Technology)
	assert.Equal(t, "1.2", result.Version)
}

func TestSOAPFingerprinter_Fingerprint_WSDL11(t *testing.T) {
	fp := &SOAPFingerprinter{}
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<definitions
  xmlns="http://schemas.xmlsoap.org/wsdl/"
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
  xmlns:tns="http://example.com/service"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  targetNamespace="http://example.com/service"
  name="MyService">
  <types>
    <xsd:schema targetNamespace="http://example.com/service"/>
  </types>
  <portType name="MyServicePortType">
    <operation name="GetPrice"/>
  </portType>
  <binding name="MyServiceBinding" type="tns:MyServicePortType">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
  </binding>
  <service name="MyService">
    <port name="MyServicePort" binding="tns:MyServiceBinding">
      <soap:address location="http://example.com/service"/>
    </port>
  </service>
</definitions>`)

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"text/xml; charset=utf-8"},
		},
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "soap", result.Technology)
	assert.Equal(t, true, result.Metadata["wsdl_available"])
	assert.Equal(t, "1.1", result.Metadata["wsdl_version"])
	assert.Equal(t, "http://example.com/service", result.Metadata["target_namespace"])
}

func TestSOAPFingerprinter_Fingerprint_WSDL20(t *testing.T) {
	fp := &SOAPFingerprinter{}
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<description
  xmlns="http://www.w3.org/ns/wsdl"
  targetNamespace="http://example.com/service2">
  <types/>
  <interface name="MyInterface"/>
  <binding name="MyBinding" interface="tns:MyInterface" type="http://www.w3.org/ns/wsdl/soap"/>
  <service name="MyService" interface="tns:MyInterface"/>
</description>`)

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/xml"},
		},
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "soap", result.Technology)
	assert.Equal(t, true, result.Metadata["wsdl_available"])
	assert.Equal(t, "2.0", result.Metadata["wsdl_version"])
	assert.Equal(t, "http://example.com/service2", result.Metadata["target_namespace"])
}

func TestSOAPFingerprinter_Fingerprint_SOAP11Fault(t *testing.T) {
	fp := &SOAPFingerprinter{}
	body := []byte(`<?xml version='1.0' encoding='UTF-8'?>
<SOAP-ENV:Envelope
  xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Body>
    <SOAP-ENV:Fault>
      <faultcode>SOAP-ENV:Client</faultcode>
      <faultstring>Failed to locate method</faultstring>
    </SOAP-ENV:Fault>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`)

	resp := &http.Response{
		StatusCode: 500,
		Header: http.Header{
			"Content-Type": []string{"text/xml; charset=utf-8"},
		},
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "soap", result.Technology)
	assert.Equal(t, "1.1", result.Version)
	assert.Equal(t, true, result.Metadata["has_fault"])
}

func TestSOAPFingerprinter_Fingerprint_SOAP12Fault(t *testing.T) {
	fp := &SOAPFingerprinter{}
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
  <env:Body>
    <env:Fault>
      <env:Code>
        <env:Value>env:Sender</env:Value>
      </env:Code>
      <env:Reason>
        <env:Text xml:lang="en">Processing error</env:Text>
      </env:Reason>
    </env:Fault>
  </env:Body>
</env:Envelope>`)

	resp := &http.Response{
		StatusCode: 500,
		Header: http.Header{
			"Content-Type": []string{"application/soap+xml; charset=utf-8"},
		},
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "soap", result.Technology)
	assert.Equal(t, "1.2", result.Version)
	assert.Equal(t, true, result.Metadata["has_fault"])
}

func TestSOAPFingerprinter_Fingerprint_NotSOAP(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "plain XML without SOAP namespaces",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<root>
  <item>Not SOAP</item>
</root>`,
		},
		{
			name: "RSS feed",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Example</title>
  </channel>
</rss>`,
		},
		{
			name: "Atom feed",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Example</title>
</feed>`,
		},
		{
			name: "empty body",
			body: "",
		},
		{
			name: "SVG document",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <circle cx="50" cy="50" r="40"/>
</svg>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SOAPFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{"text/xml"},
				},
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			assert.Nil(t, result)
			assert.Nil(t, err)
		})
	}
}

func TestSOAPFingerprinter_Fingerprint_AlternateNamespacePrefixes(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		expectedVersion string
	}{
		{
			name: "soapenv prefix (SOAP 1.1)",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <Response>OK</Response>
  </soapenv:Body>
</soapenv:Envelope>`,
			expectedVersion: "1.1",
		},
		{
			name: "s prefix (SOAP 1.1)",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <Response>OK</Response>
  </s:Body>
</s:Envelope>`,
			expectedVersion: "1.1",
		},
		{
			name: "env prefix (SOAP 1.2)",
			body: `<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
  <env:Body>
    <Response>OK</Response>
  </env:Body>
</env:Envelope>`,
			expectedVersion: "1.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SOAPFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{"text/xml; charset=utf-8"},
				},
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "soap", result.Technology)
			assert.Equal(t, tt.expectedVersion, result.Version)
		})
	}
}

func TestExtractTargetNamespace(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "extracts targetNamespace",
			body:     `<definitions targetNamespace="http://example.com/service">`,
			expected: "http://example.com/service",
		},
		{
			name:     "no targetNamespace",
			body:     `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/">`,
			expected: "",
		},
		{
			name:     "empty body",
			body:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTargetNamespace([]byte(tt.body))
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSOAPFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	fp := &SOAPFingerprinter{}
	Register(fp)

	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope
  xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Body>
    <ns:GetResponse xmlns:ns="http://example.com/service">
      <ns:Result>42</ns:Result>
    </ns:GetResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`)

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"text/xml; charset=utf-8"},
		},
	}

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1)
	assert.Equal(t, "soap", results[0].Technology)
	assert.Equal(t, "1.1", results[0].Version)
}

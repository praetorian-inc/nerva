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

package vmware

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildSOAPResponse constructs a full SOAP envelope wrapping the about block.
func buildSOAPResponse(name, fullName, vendor, version, build, apiType, apiVersion, osType, productLineId string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><RetrieveServiceContentResponse xmlns="urn:vim25"><returnval><about>` +
		`<name>` + name + `</name>` +
		`<fullName>` + fullName + `</fullName>` +
		`<vendor>` + vendor + `</vendor>` +
		`<version>` + version + `</version>` +
		`<build>` + build + `</build>` +
		`<apiType>` + apiType + `</apiType>` +
		`<apiVersion>` + apiVersion + `</apiVersion>` +
		`<osType>` + osType + `</osType>` +
		`<productLineId>` + productLineId + `</productLineId>` +
		`</about></returnval></RetrieveServiceContentResponse></soapenv:Body></soapenv:Envelope>`)
}

// TestParseVMwareResponse tests the parseVMwareResponse function against valid
// ESXi and vCenter responses, invalid vendor cases, and malformed inputs.
func TestParseVMwareResponse(t *testing.T) {
	tests := []struct {
		name                  string
		input                 []byte
		expectNil             bool
		expectedVendor        string
		expectedVersion       string
		expectedBuild         string
		expectedFullName      string
		expectedApiType       string
		expectedApiVersion    string
		expectedOsType        string
		expectedProductLineId string
	}{
		{
			name: "valid_esxi_5.5",
			input: buildSOAPResponse(
				"VMware ESXi",
				"VMware ESXi 5.5.0 build-3248547",
				"VMware, Inc.",
				"5.5.0",
				"3248547",
				"HostAgent",
				"5.5",
				"vmnix-x86",
				"embeddedEsx",
			),
			expectNil:             false,
			expectedVendor:        "VMware, Inc.",
			expectedVersion:       "5.5.0",
			expectedBuild:         "3248547",
			expectedFullName:      "VMware ESXi 5.5.0 build-3248547",
			expectedApiType:       "HostAgent",
			expectedApiVersion:    "5.5",
			expectedOsType:        "vmnix-x86",
			expectedProductLineId: "embeddedEsx",
		},
		{
			name: "valid_esxi_6.0",
			input: buildSOAPResponse(
				"VMware ESXi",
				"VMware ESXi 6.0.0 build-3620759",
				"VMware, Inc.",
				"6.0.0",
				"3620759",
				"HostAgent",
				"6.0",
				"vmnix-x86",
				"embeddedEsx",
			),
			expectNil:             false,
			expectedVendor:        "VMware, Inc.",
			expectedVersion:       "6.0.0",
			expectedBuild:         "3620759",
			expectedFullName:      "VMware ESXi 6.0.0 build-3620759",
			expectedApiType:       "HostAgent",
			expectedApiVersion:    "6.0",
			expectedOsType:        "vmnix-x86",
			expectedProductLineId: "embeddedEsx",
		},
		{
			name: "valid_esxi_7.0",
			input: buildSOAPResponse(
				"VMware ESXi",
				"VMware ESXi 7.0.3 build-21424296",
				"VMware, Inc.",
				"7.0.3",
				"21424296",
				"HostAgent",
				"7.0.3.0",
				"vmnix-x86",
				"embeddedEsx",
			),
			expectNil:             false,
			expectedVendor:        "VMware, Inc.",
			expectedVersion:       "7.0.3",
			expectedBuild:         "21424296",
			expectedFullName:      "VMware ESXi 7.0.3 build-21424296",
			expectedApiType:       "HostAgent",
			expectedApiVersion:    "7.0.3.0",
			expectedOsType:        "vmnix-x86",
			expectedProductLineId: "embeddedEsx",
		},
		{
			name: "valid_esxi_8.0",
			input: buildSOAPResponse(
				"VMware ESXi",
				"VMware ESXi 8.0.2 build-22380479",
				"VMware, Inc.",
				"8.0.2",
				"22380479",
				"HostAgent",
				"8.0.2.0",
				"vmnix-x86",
				"embeddedEsx",
			),
			expectNil:             false,
			expectedVendor:        "VMware, Inc.",
			expectedVersion:       "8.0.2",
			expectedBuild:         "22380479",
			expectedFullName:      "VMware ESXi 8.0.2 build-22380479",
			expectedApiType:       "HostAgent",
			expectedApiVersion:    "8.0.2.0",
			expectedOsType:        "vmnix-x86",
			expectedProductLineId: "embeddedEsx",
		},
		{
			name: "valid_vcenter_7.0",
			input: buildSOAPResponse(
				"VMware vCenter Server",
				"VMware vCenter Server 7.0.3 build-21784236",
				"VMware, Inc.",
				"7.0.3",
				"21784236",
				"VirtualCenter",
				"7.0.3.0",
				"linux-x64",
				"vpx",
			),
			expectNil:             false,
			expectedVendor:        "VMware, Inc.",
			expectedVersion:       "7.0.3",
			expectedBuild:         "21784236",
			expectedFullName:      "VMware vCenter Server 7.0.3 build-21784236",
			expectedApiType:       "VirtualCenter",
			expectedApiVersion:    "7.0.3.0",
			expectedOsType:        "linux-x64",
			expectedProductLineId: "vpx",
		},
		{
			name: "valid_vcenter_8.0",
			input: buildSOAPResponse(
				"VMware vCenter Server",
				"VMware vCenter Server 8.0.2 build-22385739",
				"VMware, Inc.",
				"8.0.2",
				"22385739",
				"VirtualCenter",
				"8.0.2.0",
				"linux-x64",
				"vpx",
			),
			expectNil:             false,
			expectedVendor:        "VMware, Inc.",
			expectedVersion:       "8.0.2",
			expectedBuild:         "22385739",
			expectedFullName:      "VMware vCenter Server 8.0.2 build-22385739",
			expectedApiType:       "VirtualCenter",
			expectedApiVersion:    "8.0.2.0",
			expectedOsType:        "linux-x64",
			expectedProductLineId: "vpx",
		},
		{
			name: "invalid_wrong_vendor",
			input: buildSOAPResponse(
				"Some Product",
				"Some Product 1.0.0",
				"Not VMware",
				"1.0.0",
				"12345",
				"SomeAgent",
				"1.0",
				"linux-x86",
				"someProduct",
			),
			expectNil: true,
		},
		{
			name:      "invalid_no_vendor",
			input:     []byte(`<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><RetrieveServiceContentResponse xmlns="urn:vim25"><returnval><about><name>Something</name><version>1.0.0</version></about></returnval></RetrieveServiceContentResponse></soapenv:Body></soapenv:Envelope>`),
			expectNil: true,
		},
		{
			name:      "invalid_empty_response",
			input:     []byte{},
			expectNil: true,
		},
		{
			name:      "invalid_html_response",
			input:     []byte(`<html><body>Not SOAP</body></html>`),
			expectNil: true,
		},
		{
			name: "invalid_no_apitype",
			input: []byte(`<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><RetrieveServiceContentResponse xmlns="urn:vim25"><returnval><about>` +
				`<name>VMware ESXi</name>` +
				`<vendor>VMware, Inc.</vendor>` +
				`<version>6.0.0</version>` +
				`<apiType></apiType>` +
				`</about></returnval></RetrieveServiceContentResponse></soapenv:Body></soapenv:Envelope>`),
			expectNil: true,
		},
		{
			name:      "invalid_vendor_in_html_without_soap_marker",
			input:     []byte(`<html><p>Vendor is <vendor>VMware, Inc.</vendor></p><apiType>fake</apiType></html>`),
			expectNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseVMwareResponse(tt.input)
			if tt.expectNil {
				assert.Nil(t, result, "Expected nil result for non-VMware or invalid response")
				return
			}
			assert.NotNil(t, result, "Expected non-nil result for valid VMware response")
			assert.Equal(t, tt.expectedVendor, result.Vendor, "Vendor mismatch")
			assert.Equal(t, tt.expectedVersion, result.Version, "Version mismatch")
			assert.Equal(t, tt.expectedBuild, result.Build, "Build mismatch")
			assert.Equal(t, tt.expectedFullName, result.FullName, "FullName mismatch")
			assert.Equal(t, tt.expectedApiType, result.ApiType, "ApiType mismatch")
			assert.Equal(t, tt.expectedApiVersion, result.ApiVersion, "ApiVersion mismatch")
			assert.Equal(t, tt.expectedOsType, result.OsType, "OsType mismatch")
			assert.Equal(t, tt.expectedProductLineId, result.ProductLineId, "ProductLineId mismatch")
		})
	}
}

// TestClassifyVMwareProduct tests that apiType strings are mapped to the
// correct product type identifiers.
func TestClassifyVMwareProduct(t *testing.T) {
	tests := []struct {
		name     string
		apiType  string
		expected string
	}{
		{
			name:     "host_agent_is_esxi",
			apiType:  "HostAgent",
			expected: "esxi",
		},
		{
			name:     "virtual_center_is_vcenter",
			apiType:  "VirtualCenter",
			expected: "vcenter",
		},
		{
			name:     "unknown_type_is_vsphere",
			apiType:  "SomeOther",
			expected: "vsphere",
		},
		{
			name:     "empty_type_is_vsphere",
			apiType:  "",
			expected: "vsphere",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyVMwareProduct(tt.apiType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestBuildVMwareCPE tests CPE string generation for VMware ESXi, vCenter, and
// generic vSphere products, with and without version information.
func TestBuildVMwareCPE(t *testing.T) {
	tests := []struct {
		name        string
		productType string
		version     string
		expectedCPE string
	}{
		{
			name:        "esxi_with_version",
			productType: "esxi",
			version:     "6.0.0",
			expectedCPE: "cpe:2.3:o:vmware:esxi:6.0.0:*:*:*:*:*:*:*",
		},
		{
			name:        "esxi_without_version",
			productType: "esxi",
			version:     "",
			expectedCPE: "cpe:2.3:o:vmware:esxi:*:*:*:*:*:*:*:*",
		},
		{
			name:        "vcenter_with_version",
			productType: "vcenter",
			version:     "7.0.3",
			expectedCPE: "cpe:2.3:a:vmware:vcenter_server:7.0.3:*:*:*:*:*:*:*",
		},
		{
			name:        "vcenter_without_version",
			productType: "vcenter",
			version:     "",
			expectedCPE: "cpe:2.3:a:vmware:vcenter_server:*:*:*:*:*:*:*:*",
		},
		{
			name:        "vsphere_with_version",
			productType: "vsphere",
			version:     "8.0.0",
			expectedCPE: "cpe:2.3:a:vmware:vsphere:8.0.0:*:*:*:*:*:*:*",
		},
		{
			name:        "vsphere_without_version",
			productType: "vsphere",
			version:     "",
			expectedCPE: "cpe:2.3:a:vmware:vsphere:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildVMwareCPE(tt.productType, tt.version)
			assert.Equal(t, tt.expectedCPE, cpe)
		})
	}
}

// TestBuildSOAPHTTPRequest tests the HTTP request construction for the /sdk endpoint.
func TestBuildSOAPHTTPRequest(t *testing.T) {
	tests := []struct {
		name             string
		host             string
		expectedContains []string
	}{
		{
			name: "ipv4_host",
			host: "192.168.1.1:443",
			expectedContains: []string{
				"POST /sdk HTTP/1.1",
				"Host: 192.168.1.1:443",
				"SOAPAction: urn:vim25/6.0",
				"Content-Type: text/xml",
				"RetrieveServiceContent",
			},
		},
		{
			name: "ipv6_host",
			host: "[::1]:443",
			expectedContains: []string{
				"Host: [::1]:443",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := buildSOAPHTTPRequest(tt.host)
			for _, expected := range tt.expectedContains {
				assert.Contains(t, request, expected)
			}
		})
	}
}

// TestExtractHTTPBody tests extraction of the HTTP body from a raw HTTP response.
func TestExtractHTTPBody(t *testing.T) {
	tests := []struct {
		name         string
		input        []byte
		expectedBody string
		expectNil    bool
	}{
		{
			name: "standard_http_response",
			input: []byte("HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/xml\r\n" +
				"\r\n" +
				"<soap:Envelope/>"),
			expectedBody: "<soap:Envelope/>",
			expectNil:    false,
		},
		{
			name: "multiple_headers",
			input: []byte("HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/xml\r\n" +
				"Server: VMware-SOAP/6.0\r\n" +
				"Date: Mon, 01 Jan 2024 00:00:00 GMT\r\n" +
				"\r\n" +
				"<body/>"),
			expectedBody: "<body/>",
			expectNil:    false,
		},
		{
			name:         "no_separator_returns_full_response",
			input:        []byte("just plain text"),
			expectedBody: "just plain text",
			expectNil:    false,
		},
		{
			name: "empty_body_after_headers",
			input: []byte("HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/plain\r\n" +
				"\r\n"),
			expectedBody: "",
			expectNil:    true,
		},
		{
			name:         "empty_input",
			input:        []byte{},
			expectedBody: "",
			expectNil:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := extractHTTPBody(tt.input)
			if tt.expectNil {
				assert.Nil(t, body)
			} else if len(tt.input) == 0 {
				// empty input: function returns the input (empty slice)
				assert.Equal(t, tt.input, body)
			} else {
				assert.Equal(t, tt.expectedBody, string(body))
			}
		})
	}
}

// TestPluginMetadata tests the VMwarePlugin struct methods.
func TestPluginMetadata(t *testing.T) {
	plugin := &VMwarePlugin{}

	assert.Equal(t, "vmware-vsphere", plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, 0, plugin.Priority())

	assert.True(t, plugin.PortPriority(443), "Port 443 should be prioritized")
	assert.False(t, plugin.PortPriority(80), "Port 80 should not be prioritized")
}

// mockConn implements net.Conn for a single Recv (4096-byte Read).
type mockConn struct {
	readData  []byte
	readIndex int
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readIndex >= len(m.readData) {
		return 0, nil
	}
	n = copy(b, m.readData[m.readIndex:])
	m.readIndex += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func wrapSOAPHTTP(soap []byte) []byte {
	headers := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n")
	out := make([]byte, 0, len(headers)+len(soap))
	out = append(out, headers...)
	return append(out, soap...)
}

func findingIDs(findings []plugins.SecurityFinding) []string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.ID)
	}
	return ids
}

const findingVMwareExposed = "vmware-exposed"

func TestVMwarePlugin_Run_FindingID(t *testing.T) {
	esxiSOAP := wrapSOAPHTTP(buildSOAPResponse(
		"VMware ESXi",
		"VMware ESXi 8.0.2 build-22380479",
		"VMware, Inc.",
		"8.0.2",
		"22380479",
		"HostAgent",
		"8.0.2.0",
		"vmnix-x86",
		"embeddedEsx",
	))
	vcenterSOAP := wrapSOAPHTTP(buildSOAPResponse(
		"VMware vCenter Server",
		"VMware vCenter Server 8.0.2 build-22385739",
		"VMware, Inc.",
		"8.0.2",
		"22385739",
		"VirtualCenter",
		"8.0.2.0",
		"linux-x64",
		"vpx",
	))
	otherSOAP := wrapSOAPHTTP(buildSOAPResponse(
		"VMware vSphere",
		"VMware vSphere 8.0.2 build-22380479",
		"VMware, Inc.",
		"8.0.2",
		"22380479",
		"SomeOther",
		"8.0.2.0",
		"linux-x64",
		"vsphere",
	))

	tests := []struct {
		name         string
		response     []byte
		misconfigs   bool
		wantService  bool
		wantID       bool
		wantEvidence string
	}{
		{
			name:         "hostagent_misconfigs_emits",
			response:     esxiSOAP,
			misconfigs:   true,
			wantService:  true,
			wantID:       true,
			wantEvidence: "VMware ESXi 8.0.2 build-22380479",
		},
		{
			name:         "virtualcenter_misconfigs_emits",
			response:     vcenterSOAP,
			misconfigs:   true,
			wantService:  true,
			wantID:       true,
			wantEvidence: "VMware vCenter Server 8.0.2 build-22385739",
		},
		{
			name:         "other_apitype_misconfigs_emits",
			response:     otherSOAP,
			misconfigs:   true,
			wantService:  true,
			wantID:       true,
			wantEvidence: "VMware vSphere 8.0.2 build-22380479",
		},
		{
			name:        "non_vmware_no_service",
			response:    []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>OK</body></html>"),
			misconfigs:  true,
			wantService: false,
		},
		{
			name:        "hostagent_misconfigs_false_no_id",
			response:    esxiSOAP,
			misconfigs:  false,
			wantService: true,
			wantID:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &VMwarePlugin{}
			target := plugins.Target{
				Host:       "192.0.2.1",
				Address:    netip.MustParseAddrPort("192.0.2.1:443"),
				Misconfigs: tt.misconfigs,
			}
			service, err := plugin.Run(&mockConn{readData: tt.response}, time.Second, target)
			require.NoError(t, err)
			if !tt.wantService {
				require.Nil(t, service)
				return
			}
			require.NotNil(t, service)
			ids := findingIDs(service.SecurityFindings)
			if tt.wantID {
				assert.Contains(t, ids, findingVMwareExposed)
				var evidence string
				for _, f := range service.SecurityFindings {
					if f.ID == findingVMwareExposed {
						evidence = f.Evidence
						break
					}
				}
				assert.Equal(t, tt.wantEvidence, evidence)
			} else {
				assert.NotContains(t, ids, findingVMwareExposed)
			}
		})
	}
}

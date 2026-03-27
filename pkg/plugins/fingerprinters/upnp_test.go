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
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUPnPFingerprinter_Name(t *testing.T) {
	fp := &UPnPFingerprinter{}
	assert.Equal(t, "upnp", fp.Name())
}

func TestUPnPFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name:     "matches SERVER header with UPnP",
			headers:  map[string]string{"Server": "Linux/3.0 UPnP/1.0 IpBridge/1.16.0"},
			expected: true,
		},
		{
			name:     "matches SERVER header with UPnP case insensitive",
			headers:  map[string]string{"Server": "Microsoft-Windows/10.0 UPNP/2.0"},
			expected: true,
		},
		{
			name:     "does not match when no UPnP in SERVER header",
			headers:  map[string]string{"Server": "Apache/2.4.41"},
			expected: false,
		},
		{
			name:     "does not match when no headers present",
			headers:  map[string]string{},
			expected: false,
		},
		{
			name:     "does not match unrelated headers",
			headers:  map[string]string{"X-Custom": "UPnP"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &UPnPFingerprinter{}
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{
				Header: header,
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestUPnPFingerprinter_Fingerprint_ServerHeader(t *testing.T) {
	tests := []struct {
		name             string
		headers          map[string]string
		body             string
		expectedTech     string
		expectedVersion  string
		expectedCPE      string
		expectedMetadata map[string]any
	}{
		{
			name:            "Full UPnP server with version",
			headers:         map[string]string{"Server": "Linux/3.0 UPnP/1.0 IpBridge/1.16.0"},
			body:            "",
			expectedTech:    "upnp",
			expectedVersion: "1.0",
			expectedCPE:     "cpe:2.3:a:upnp:upnp:1.0:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"server": "Linux/3.0 UPnP/1.0 IpBridge/1.16.0",
			},
		},
		{
			name:            "UPnP 2.0 server",
			headers:         map[string]string{"Server": "Microsoft-Windows/10.0 UPnP/2.0 Microsoft-HTTPAPI/2.0"},
			body:            "",
			expectedTech:    "upnp",
			expectedVersion: "2.0",
			expectedCPE:     "cpe:2.3:a:upnp:upnp:2.0:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"server": "Microsoft-Windows/10.0 UPnP/2.0 Microsoft-HTTPAPI/2.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &UPnPFingerprinter{}
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{
				StatusCode: 200,
				Header:     header,
				Body:       io.NopCloser(bytes.NewReader([]byte(tt.body))),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, tt.expectedTech, result.Technology)
			assert.Equal(t, tt.expectedVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.expectedCPE)

			for key, expectedValue := range tt.expectedMetadata {
				assert.Equal(t, expectedValue, result.Metadata[key], "metadata key: %s", key)
			}
		})
	}
}

func TestUPnPFingerprinter_Fingerprint_BodyDetection(t *testing.T) {
	upnpBody := `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
    <friendlyName>Philips hue</friendlyName>
  </device>
</root>`

	fp := &UPnPFingerprinter{}
	header := http.Header{}
	header.Set("Server", "Linux/3.0 UPnP/1.0 IpBridge/1.16.0")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader([]byte(upnpBody))),
	}

	result, err := fp.Fingerprint(resp, []byte(upnpBody))

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "upnp", result.Technology)
	assert.Equal(t, "1.0", result.Version)
	assert.Equal(t, true, result.Metadata["upnp_namespace"])
	assert.Equal(t, "urn:schemas-upnp-org:device:Basic:1", result.Metadata["device_type"])
	assert.Equal(t, "Philips hue", result.Metadata["friendly_name"])
}

func TestUPnPFingerprinter_Fingerprint_BodyOnlyDetection(t *testing.T) {
	// Body with UPnP namespace but SERVER header also has UPnP
	// (Match() requires SERVER header, so body-only can't trigger Match)
	// This tests that body enrichment works when both are present
	upnpBody := `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
    <friendlyName>Living Room Speaker</friendlyName>
  </device>
</root>`

	fp := &UPnPFingerprinter{}
	header := http.Header{}
	header.Set("Server", "Debian/buster UPnP/1.0 GUPnP/1.2.2")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader([]byte(upnpBody))),
	}

	result, err := fp.Fingerprint(resp, []byte(upnpBody))

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "upnp", result.Technology)
	assert.Equal(t, true, result.Metadata["upnp_namespace"])
	assert.Equal(t, "urn:schemas-upnp-org:device:MediaRenderer:1", result.Metadata["device_type"])
	assert.Equal(t, "Living Room Speaker", result.Metadata["friendly_name"])
}

func TestUPnPFingerprinter_Fingerprint_NoMatch(t *testing.T) {
	fp := &UPnPFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
	}

	result, err := fp.Fingerprint(resp, []byte(""))

	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestBuildUPnPCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "1.0",
			expected: "cpe:2.3:a:upnp:upnp:1.0:*:*:*:*:*:*:*",
		},
		{
			name:     "version 2.0",
			version:  "2.0",
			expected: "cpe:2.3:a:upnp:upnp:2.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:upnp:upnp:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildUPnPCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUPnPFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	fp := &UPnPFingerprinter{}
	Register(fp)

	upnpBody := `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
    <friendlyName>Test Device</friendlyName>
  </device>
</root>`

	header := http.Header{}
	header.Set("Server", "Linux/3.0 UPnP/1.0 IpBridge/1.16.0")

	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader([]byte(upnpBody))),
	}

	results := RunFingerprinters(resp, []byte(upnpBody))

	require.Len(t, results, 1)
	assert.Equal(t, "upnp", results[0].Technology)
	assert.Equal(t, "1.0", results[0].Version)
	assert.Equal(t, "Linux/3.0 UPnP/1.0 IpBridge/1.16.0", results[0].Metadata["server"])
	assert.Equal(t, true, results[0].Metadata["upnp_namespace"])
}

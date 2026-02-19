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

func TestQNAPFingerprinter_Name(t *testing.T) {
	fp := &QNAPFingerprinter{}
	assert.Equal(t, "qnap-qts", fp.Name())
}

func TestQNAPFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &QNAPFingerprinter{}
	assert.Equal(t, "/cgi-bin/authLogin.cgi", fp.ProbeEndpoint())
}

func TestQNAPFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{
			name:        "matches text/xml content type",
			contentType: "text/xml",
			expected:    true,
		},
		{
			name:        "matches application/xml content type",
			contentType: "application/xml",
			expected:    true,
		},
		{
			name:        "matches text/xml with charset",
			contentType: "text/xml; charset=utf-8",
			expected:    true,
		},
		{
			name:        "matches application/xml with charset",
			contentType: "application/xml; charset=utf-8",
			expected:    true,
		},
		{
			name:        "does not match text/html",
			contentType: "text/html",
			expected:    false,
		},
		{
			name:        "does not match application/json",
			contentType: "application/json",
			expected:    false,
		},
		{
			name:        "does not match empty content type",
			contentType: "",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &QNAPFingerprinter{}
			header := http.Header{}
			if tt.contentType != "" {
				header.Set("Content-Type", tt.contentType)
			}
			resp := &http.Response{
				Header: header,
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestQNAPFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		expectedTech     string
		expectedVersion  string
		expectedCPE      string
		expectedMetadata map[string]any
	}{
		{
			name: "QTS 4.4.1 full response",
			body: `<?xml version="1.0" encoding="UTF-8" ?>
<QDocRoot version="1.0">
<doQuick><![CDATA[]]></doQuick><is_booting><![CDATA[0]]></is_booting><mediaReady><![CDATA[1]]></mediaReady>
<model><modelName><![CDATA[TS-X73U]]></modelName><displayModelName><![CDATA[TS-873U-RP]]></displayModelName></model>
<firmware><version><![CDATA[4.4.1]]></version><number><![CDATA[1216]]></number><build><![CDATA[20200214]]></build><patch><![CDATA[0]]></patch><buildTime><![CDATA[2020/02/14]]></buildTime></firmware>
<hostname><![CDATA[QNAP-NAS]]></hostname>
</QDocRoot>`,
			expectedTech:    "qnap-qts",
			expectedVersion: "4.4.1",
			expectedCPE:     "cpe:2.3:o:qnap:qts:4.4.1:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"buildNumber": "1216",
				"buildDate":   "20200214",
				"model":       "TS-873U-RP",
				"hostname":    "QNAP-NAS",
			},
		},
		{
			name: "QTS 5.1.0 response",
			body: `<?xml version="1.0" encoding="UTF-8" ?>
<QDocRoot version="1.0">
<doQuick><![CDATA[]]></doQuick><is_booting><![CDATA[0]]></is_booting>
<model><displayModelName><![CDATA[TS-464]]></displayModelName></model>
<firmware><version><![CDATA[5.1.0]]></version><number><![CDATA[2399]]></number><build><![CDATA[20230609]]></build></firmware>
<hostname><![CDATA[NAS-OFFICE]]></hostname>
</QDocRoot>`,
			expectedTech:    "qnap-qts",
			expectedVersion: "5.1.0",
			expectedCPE:     "cpe:2.3:o:qnap:qts:5.1.0:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"buildNumber": "2399",
				"buildDate":   "20230609",
				"model":       "TS-464",
				"hostname":    "NAS-OFFICE",
			},
		},
		{
			name: "minimal response (only QDocRoot + firmware + version)",
			body: `<?xml version="1.0" encoding="UTF-8" ?>
<QDocRoot version="1.0">
<firmware><version><![CDATA[4.5.0]]></version></firmware>
</QDocRoot>`,
			expectedTech:     "qnap-qts",
			expectedVersion:  "4.5.0",
			expectedCPE:      "cpe:2.3:o:qnap:qts:4.5.0:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &QNAPFingerprinter{}
			header := http.Header{}
			header.Set("Content-Type", "text/xml")
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

			if len(tt.expectedMetadata) > 0 {
				for key, expectedValue := range tt.expectedMetadata {
					assert.Equal(t, expectedValue, result.Metadata[key], "metadata key: %s", key)
				}
			} else {
				assert.Empty(t, result.Metadata)
			}
		})
	}
}

func TestQNAPFingerprinter_Fingerprint_NonQNAP(t *testing.T) {
	fp := &QNAPFingerprinter{}

	// Non-QNAP XML response
	body := []byte(`<?xml version="1.0" encoding="UTF-8" ?>
<response>
	<status>OK</status>
</response>`)

	header := http.Header{}
	header.Set("Content-Type", "text/xml")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestQNAPFingerprinter_Fingerprint_NoFirmware(t *testing.T) {
	fp := &QNAPFingerprinter{}

	// QDocRoot without firmware block
	body := []byte(`<?xml version="1.0" encoding="UTF-8" ?>
<QDocRoot version="1.0">
<hostname><![CDATA[NAS]]></hostname>
</QDocRoot>`)

	header := http.Header{}
	header.Set("Content-Type", "text/xml")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestBuildQNAPCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "4.4.1",
			expected: "cpe:2.3:o:qnap:qts:4.4.1:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:o:qnap:qts:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildQNAPCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestQNAPFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &QNAPFingerprinter{}
	Register(fp)

	body := []byte(`<?xml version="1.0" encoding="UTF-8" ?>
<QDocRoot version="1.0">
<firmware><version><![CDATA[4.4.1]]></version><number><![CDATA[1216]]></number><build><![CDATA[20200214]]></build></firmware>
<model><displayModelName><![CDATA[TS-873U-RP]]></displayModelName></model>
<hostname><![CDATA[QNAP-NAS]]></hostname>
</QDocRoot>`)

	header := http.Header{}
	header.Set("Content-Type", "text/xml; charset=UTF-8")

	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1)
	assert.Equal(t, "qnap-qts", results[0].Technology)
	assert.Equal(t, "4.4.1", results[0].Version)
	assert.Equal(t, "1216", results[0].Metadata["buildNumber"])
	assert.Equal(t, "TS-873U-RP", results[0].Metadata["model"])
}

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

func TestOpenSearchDashboardsFingerprinter_Name(t *testing.T) {
	fp := &OpenSearchDashboardsFingerprinter{}
	assert.Equal(t, "opensearch-dashboards", fp.Name())
}

func TestOpenSearchDashboardsFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{
			name:        "matches HTML content type",
			contentType: "text/html",
			expected:    true,
		},
		{
			name:        "matches HTML with charset",
			contentType: "text/html; charset=utf-8",
			expected:    true,
		},
		{
			name:        "does not match JSON",
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
			fp := &OpenSearchDashboardsFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestOpenSearchDashboardsFingerprinter_Fingerprint_Positive(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		headers         map[string]string
		expectedVersion string
		expectedCPE     string
	}{
		{
			name:            "title contains OpenSearch Dashboards",
			body:            `<html><head><title>OpenSearch Dashboards</title></head><body></body></html>`,
			expectedVersion: "",
			expectedCPE:     "cpe:2.3:a:amazon:opensearch_dashboards:*:*:*:*:*:*:*:*",
		},
		{
			name: "osd-injected-metadata element present",
			body: `<!DOCTYPE html><html><head><osd-injected-metadata data="{}"></osd-injected-metadata></head><body></body></html>`,
		},
		{
			name: "osd-version header extraction",
			body: `<html><head><title>OpenSearch Dashboards</title></head><body></body></html>`,
			headers: map[string]string{
				"osd-version": "2.11.0",
			},
			expectedVersion: "2.11.0",
			expectedCPE:     "cpe:2.3:a:amazon:opensearch_dashboards:2.11.0:*:*:*:*:*:*:*",
		},
		{
			name: "osd-version header with SNAPSHOT cleaned",
			body: `<html><head><title>OpenSearch Dashboards</title></head><body></body></html>`,
			headers: map[string]string{
				"osd-version": "2.12.0-SNAPSHOT",
			},
			expectedVersion: "2.12.0",
			expectedCPE:     "cpe:2.3:a:amazon:opensearch_dashboards:2.12.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OpenSearchDashboardsFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "opensearch-dashboards", result.Technology)
			assert.Equal(t, tt.expectedVersion, result.Version)
			if tt.expectedCPE != "" {
				assert.Contains(t, result.CPEs, tt.expectedCPE)
			}
		})
	}
}

func TestOpenSearchDashboardsFingerprinter_Fingerprint_Negative(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Kibana HTML",
			body: `<!DOCTYPE html><html><head><kbn-injected-metadata data="{}"></kbn-injected-metadata><title>Kibana</title></head><body></body></html>`,
		},
		{
			name: "generic HTML with no OpenSearch Dashboards markers",
			body: `<html><head><title>My App</title></head><body></body></html>`,
		},
		{
			name: "empty body",
			body: ``,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OpenSearchDashboardsFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			assert.Nil(t, result)
			assert.Nil(t, err)
		})
	}
}

func TestBuildOpenSearchDashboardsCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "2.11.0",
			expected: "cpe:2.3:a:amazon:opensearch_dashboards:2.11.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:amazon:opensearch_dashboards:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildOpenSearchDashboardsCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}


func TestOpenSearchDashboardsFingerprinter_KibanaCollisionRegression(t *testing.T) {
	// OpenSearch Dashboards HTML must NOT trigger the Kibana fingerprinter.
	body := []byte(`<!DOCTYPE html><html><head>
		<title>OpenSearch Dashboards</title>
		<osd-injected-metadata data="{}"></osd-injected-metadata>
	</head><body></body></html>`)

	kibanaFP := &KibanaFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"text/html; charset=utf-8"},
		},
	}

	result, err := kibanaFP.Fingerprint(resp, body)
	assert.Nil(t, err)
	assert.Nil(t, result, "Kibana fingerprinter must NOT match OpenSearch Dashboards HTML")
}

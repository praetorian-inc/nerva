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

// --- TestUniFiStatusFingerprinter ---

func TestUniFiStatusFingerprinter_Name(t *testing.T) {
	fp := &UniFiStatusFingerprinter{}
	assert.Equal(t, "unifi-status", fp.Name())
}

func TestUniFiStatusFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &UniFiStatusFingerprinter{}
	assert.Equal(t, "/status", fp.ProbeEndpoint())
}

func TestUniFiStatusFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{
			name:        "matches application/json",
			contentType: "application/json",
			expected:    true,
		},
		{
			name:        "matches application/json with charset",
			contentType: "application/json; charset=utf-8",
			expected:    true,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &UniFiStatusFingerprinter{}
			resp := &http.Response{
				Header: http.Header{"Content-Type": []string{tt.contentType}},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestUniFiStatusFingerprinter_Fingerprint(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantNil     bool
		wantVersion string
		wantTech    string
		wantCPE     string
	}{
		{
			name:        "valid UniFi Controller response",
			body:        `{"data":[],"meta":{"rc":"ok","server_version":"7.5.187","up":true,"uuid":"abc-123"}}`,
			wantNil:     false,
			wantVersion: "7.5.187",
			wantTech:    "unifi-controller",
			wantCPE:     "cpe:2.3:a:ui:unifi_network_application:7.5.187:*:*:*:*:*:*:*",
		},
		{
			name:    "rc not ok",
			body:    `{"data":[],"meta":{"rc":"error","server_version":"7.5.187","up":false}}`,
			wantNil: true,
		},
		{
			name:    "missing server_version",
			body:    `{"data":[],"meta":{"rc":"ok","server_version":"","up":true}}`,
			wantNil: true,
		},
		{
			name:    "empty JSON object",
			body:    `{}`,
			wantNil: true,
		},
		{
			name:    "non-JSON body",
			body:    `<html><body>Not JSON</body></html>`,
			wantNil: true,
		},
		{
			name:    "empty body",
			body:    ``,
			wantNil: true,
		},
		{
			name:        "malicious version string is sanitized to empty, still detected",
			body:        `{"meta":{"rc":"ok","server_version":"7.5.187:*:*:*:*:*:cpe:2.3:a:evil:app","up":true}}`,
			wantNil:     false,
			wantVersion: "", // sanitized to empty
			wantTech:    "unifi-controller",
			wantCPE:     "cpe:2.3:a:ui:unifi_network_application:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &UniFiStatusFingerprinter{}
			resp := &http.Response{
				Header: http.Header{"Content-Type": []string{"application/json"}},
			}
			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			assert.Equal(t, tt.wantTech, result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			require.Len(t, result.CPEs, 1)
			assert.Equal(t, tt.wantCPE, result.CPEs[0])
		})
	}
}

// --- TestUniFiTitleFingerprinter ---

func TestUniFiTitleFingerprinter_Name(t *testing.T) {
	fp := &UniFiTitleFingerprinter{}
	assert.Equal(t, "unifi-title", fp.Name())
}

func TestUniFiTitleFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{
			name:        "matches text/html",
			contentType: "text/html",
			expected:    true,
		},
		{
			name:        "matches text/html with charset",
			contentType: "text/html; charset=utf-8",
			expected:    true,
		},
		{
			name:        "matches empty content type",
			contentType: "",
			expected:    true,
		},
		{
			name:        "does not match application/json",
			contentType: "application/json",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &UniFiTitleFingerprinter{}
			resp := &http.Response{
				Header: http.Header{"Content-Type": []string{tt.contentType}},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestUniFiTitleFingerprinter_Fingerprint(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		headers     map[string]string
		wantNil     bool
		wantTech    string
		wantCPE     string
	}{
		{
			name:     "UniFi Network title maps to unifi-controller",
			body:     `<html><head><title>UniFi Network</title></head></html>`,
			wantNil:  false,
			wantTech: "unifi-controller",
			wantCPE:  "cpe:2.3:a:ui:unifi_network_application:*:*:*:*:*:*:*:*",
		},
		{
			name:     "UniFi OS title maps to unifi-os",
			body:     `<html><head><title>UniFi OS</title></head></html>`,
			wantNil:  false,
			wantTech: "unifi-os",
			wantCPE:  "cpe:2.3:a:ui:unifi_network_application:*:*:*:*:*:*:*:*",
		},
		{
			name:     "EdgeOS title maps to edgeos",
			body:     `<html><head><title>EdgeOS</title></head></html>`,
			wantNil:  false,
			wantTech: "edgeos",
			wantCPE:  "cpe:2.3:o:ui:edgeos:*:*:*:*:*:*:*:*",
		},
		{
			name:    "non-Ubiquiti title returns nil",
			body:    `<html><head><title>Apache Tomcat</title></head></html>`,
			wantNil: true,
		},
		{
			name:    "no title tag returns nil",
			body:    `<html><head></head></html>`,
			wantNil: true,
		},
		{
			name:    "empty body returns nil",
			body:    ``,
			wantNil: true,
		},
		{
			name:     "X-CSRF-Token header overrides to unifi-os",
			body:     `<html><head><title>UniFi OS</title></head></html>`,
			headers:  map[string]string{"X-CSRF-Token": "abc123"},
			wantNil:  false,
			wantTech: "unifi-os",
			wantCPE:  "cpe:2.3:a:ui:unifi_network_application:*:*:*:*:*:*:*:*",
		},
		{
			name:     "Server: lighttpd overrides to edgeos",
			body:     `<html><head><title>EdgeOS</title></head></html>`,
			headers:  map[string]string{"Server": "lighttpd/1.4.39"},
			wantNil:  false,
			wantTech: "edgeos",
			wantCPE:  "cpe:2.3:o:ui:edgeos:*:*:*:*:*:*:*:*",
		},
		{
			name:     "UniFi Network title + lighttpd header overrides to edgeos",
			body:     `<html><head><title>UniFi Network</title></head></html>`,
			headers:  map[string]string{"Server": "lighttpd/1.4.39"},
			wantNil:  false,
			wantTech: "edgeos",
			wantCPE:  "cpe:2.3:o:ui:edgeos:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &UniFiTitleFingerprinter{}
			header := make(http.Header)
			header.Set("Content-Type", "text/html")
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{Header: header}
			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			assert.Equal(t, tt.wantTech, result.Technology)
			require.Len(t, result.CPEs, 1)
			assert.Equal(t, tt.wantCPE, result.CPEs[0])
		})
	}
}

// --- TestSanitizeUniFiVersion ---

func TestSanitizeUniFiVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "valid version passes through",
			version: "7.5.187",
			want:    "7.5.187",
		},
		{
			name:    "valid version with dots and dashes passes through",
			version: "8.1.113-beta.1",
			want:    "8.1.113-beta.1",
		},
		{
			name:    "malicious version with colons is rejected",
			version: "7.5.187:*:*:*:*:*:cpe:2.3:a:evil:app",
			want:    "",
		},
		{
			name:    "empty string is rejected",
			version: "",
			want:    "",
		},
		{
			name:    "version exceeding 64 chars is rejected",
			version: "1.2.3456789012345678901234567890123456789012345678901234567890123",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeUniFiVersion(tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- TestBuildUniFiCPE ---

func TestBuildUniFiCPE(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		productType string
		wantCPE     string
	}{
		{
			name:        "UniFi controller with version",
			version:     "7.5.187",
			productType: "unifi-controller",
			wantCPE:     "cpe:2.3:a:ui:unifi_network_application:7.5.187:*:*:*:*:*:*:*",
		},
		{
			name:        "UniFi controller with empty version uses wildcard",
			version:     "",
			productType: "unifi-controller",
			wantCPE:     "cpe:2.3:a:ui:unifi_network_application:*:*:*:*:*:*:*:*",
		},
		{
			name:        "EdgeOS uses OS CPE with wildcard version",
			version:     "",
			productType: "edgeos",
			wantCPE:     "cpe:2.3:o:ui:edgeos:*:*:*:*:*:*:*:*",
		},
		{
			name:        "EdgeOS ignores version argument",
			version:     "2.0.9",
			productType: "edgeos",
			wantCPE:     "cpe:2.3:o:ui:edgeos:*:*:*:*:*:*:*:*",
		},
		{
			name:        "unifi-os uses application CPE",
			version:     "",
			productType: "unifi-os",
			wantCPE:     "cpe:2.3:a:ui:unifi_network_application:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildUniFiCPE(tt.version, tt.productType)
			assert.Equal(t, tt.wantCPE, got)
		})
	}
}

// --- TestExtractHTMLTitle ---

func TestExtractHTMLTitle(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantTitle string
	}{
		{
			name:      "UniFi Network title",
			body:      `<html><head><title>UniFi Network</title></head></html>`,
			wantTitle: "UniFi Network",
		},
		{
			name:      "UniFi OS title",
			body:      `<html><head><title>UniFi OS</title></head></html>`,
			wantTitle: "UniFi OS",
		},
		{
			name:      "EdgeOS title with DOCTYPE",
			body:      `<!DOCTYPE html><html><head><title>EdgeOS</title></head></html>`,
			wantTitle: "EdgeOS",
		},
		{
			name:      "non-Ubiquiti title",
			body:      `<html><head><title>Apache Tomcat</title></head></html>`,
			wantTitle: "Apache Tomcat",
		},
		{
			name:      "no title tag returns empty",
			body:      `<html><head></head><body>No title</body></html>`,
			wantTitle: "",
		},
		{
			name:      "empty body returns empty",
			body:      ``,
			wantTitle: "",
		},
		{
			name:      "title with extra whitespace is trimmed",
			body:      "<html><head><title>  UniFi OS  </title></head></html>",
			wantTitle: "UniFi OS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHTMLTitle([]byte(tt.body))
			assert.Equal(t, tt.wantTitle, got)
		})
	}
}

// --- TestUniFiSystemFingerprinter ---

func TestUniFiSystemFingerprinter_Name(t *testing.T) {
	assert.Equal(t, "unifi-system", (&UniFiSystemFingerprinter{}).Name())
}

func TestUniFiSystemFingerprinter_ProbeEndpoint(t *testing.T) {
	assert.Equal(t, "/api/system", (&UniFiSystemFingerprinter{}).ProbeEndpoint())
}

func TestUniFiSystemFingerprinter_Match(t *testing.T) {
	fp := &UniFiSystemFingerprinter{}
	jsonResp := &http.Response{Header: http.Header{"Content-Type": []string{"application/json"}}}
	htmlResp := &http.Response{Header: http.Header{"Content-Type": []string{"text/html"}}}
	assert.True(t, fp.Match(jsonResp))
	assert.False(t, fp.Match(htmlResp))
}

func TestUniFiSystemFingerprinter_Fingerprint(t *testing.T) {
	fp := &UniFiSystemFingerprinter{}
	resp := &http.Response{Header: http.Header{"Content-Type": []string{"application/json"}}}

	tests := []struct {
		name      string
		body      string
		wantNil   bool
		wantModel string
	}{
		{
			name:      "UDM Pro SE",
			body:      `{"hardware":{"shortname":"UDMPROSE"},"name":"My UDM","deviceState":"setup","cloudConnected":true}`,
			wantModel: "UDMPROSE",
		},
		{
			name:      "Cloud Key",
			body:      `{"hardware":{"shortname":"CLOUD"},"name":"Cloud","deviceState":"setup","cloudConnected":false}`,
			wantModel: "CLOUD",
		},
		{
			name:      "UDM Pro Max",
			body:      `{"hardware":{"shortname":"UDMPROMAX"},"name":"Max","deviceState":"setup","cloudConnected":true}`,
			wantModel: "UDMPROMAX",
		},
		{
			name:    "missing hardware shortname",
			body:    `{"hardware":{},"name":"test"}`,
			wantNil: true,
		},
		{
			name:    "empty JSON",
			body:    `{}`,
			wantNil: true,
		},
		{
			name:    "non-JSON",
			body:    `not json`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := fp.Fingerprint(resp, []byte(tt.body))
			assert.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			assert.Equal(t, "unifi-os", result.Technology)
			assert.Equal(t, tt.wantModel, result.Metadata["hardwareModel"])
		})
	}
}

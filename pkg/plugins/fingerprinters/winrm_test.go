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
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWinRMFingerprinter_Name(t *testing.T) {
	fp := &WinRMFingerprinter{}
	assert.Equal(t, "winrm", fp.Name())
}

func TestWinRMFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &WinRMFingerprinter{}
	assert.Equal(t, "/wsman", fp.ProbeEndpoint())
}

func TestWinRMFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   bool
	}{
		{
			name:   "Server: Microsoft-HTTPAPI/2.0 returns true",
			server: "Microsoft-HTTPAPI/2.0",
			want:   true,
		},
		{
			name:   "Server: Microsoft-HTTPAPI/1.0 returns true",
			server: "Microsoft-HTTPAPI/1.0",
			want:   true,
		},
		{
			name:   "Server: nginx returns false",
			server: "nginx",
			want:   false,
		},
		{
			name:   "Server: Apache returns false",
			server: "Apache/2.4",
			want:   false,
		},
		{
			name:   "No Server header returns false",
			server: "",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &WinRMFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			got := fp.Match(resp)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWinRMFingerprinter_Fingerprint_WithAuth(t *testing.T) {
	fp := &WinRMFingerprinter{}
	resp := &http.Response{
		StatusCode: 401,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Microsoft-HTTPAPI/2.0")

	result, err := fp.Fingerprint(resp, nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "winrm", result.Technology)
	authRequired, ok := result.Metadata["auth_required"].(bool)
	assert.True(t, ok, "authRequired should be bool type")
	assert.True(t, authRequired)
	assert.Equal(t, "Microsoft-HTTPAPI/2.0", result.Metadata["server"])

	// Check CPE
	require.NotEmpty(t, result.CPEs)
	expectedCPE := "cpe:2.3:a:microsoft:windows_remote_management:*:*:*:*:*:*:*:*"
	assert.Contains(t, result.CPEs, expectedCPE)
}

func TestWinRMFingerprinter_Fingerprint_WithoutAuth(t *testing.T) {
	fp := &WinRMFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Microsoft-HTTPAPI/2.0")

	result, err := fp.Fingerprint(resp, nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "winrm", result.Technology)
	authRequired, ok := result.Metadata["auth_required"].(bool)
	assert.True(t, ok, "authRequired should be bool type")
	assert.False(t, authRequired)
	assert.Equal(t, "Microsoft-HTTPAPI/2.0", result.Metadata["server"])

	// Check CPE
	require.NotEmpty(t, result.CPEs)
	expectedCPE := "cpe:2.3:a:microsoft:windows_remote_management:*:*:*:*:*:*:*:*"
	assert.Contains(t, result.CPEs, expectedCPE)
}

func TestWinRMFingerprinter_Fingerprint_NotWinRM(t *testing.T) {
	tests := []struct {
		name   string
		server string
	}{
		{
			name:   "nginx server",
			server: "nginx",
		},
		{
			name:   "Apache server",
			server: "Apache/2.4",
		},
		{
			name:   "no server header",
			server: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &WinRMFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, nil)
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

func TestBuildWinRMCPE(t *testing.T) {
	got := buildWinRMCPE()
	want := "cpe:2.3:a:microsoft:windows_remote_management:*:*:*:*:*:*:*:*"
	assert.Equal(t, want, got)
}

func TestWinRMNoAuth(t *testing.T) {
	fp := &WinRMFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Microsoft-HTTPAPI/2.0")

	result, err := fp.Fingerprint(resp, nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, plugins.SeverityCritical, result.Severity)
	require.Len(t, result.SecurityFindings, 2)
	assert.Equal(t, "winrm-no-auth", result.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityCritical, result.SecurityFindings[0].Severity)
	assert.Contains(t, result.SecurityFindings[0].Evidence, "200")
	assert.Equal(t, "winrm-cleartext", result.SecurityFindings[1].ID)
	assert.Equal(t, plugins.SeverityMedium, result.SecurityFindings[1].Severity)

	authRequired, ok := result.Metadata["auth_required"].(bool)
	assert.True(t, ok)
	assert.False(t, authRequired)
}

func TestWinRMNoAuthTLS(t *testing.T) {
	fp := &WinRMFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		TLS:        &tls.ConnectionState{},
	}
	resp.Header.Set("Server", "Microsoft-HTTPAPI/2.0")

	result, err := fp.Fingerprint(resp, nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, plugins.SeverityCritical, result.Severity)
	require.Len(t, result.SecurityFindings, 1)
	assert.Equal(t, "winrm-no-auth", result.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityCritical, result.SecurityFindings[0].Severity)
}

func TestWinRMAuthRequired(t *testing.T) {
	fp := &WinRMFingerprinter{}
	resp := &http.Response{
		StatusCode: 401,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Microsoft-HTTPAPI/2.0")

	result, err := fp.Fingerprint(resp, nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, plugins.Severity(""), result.Severity)
	assert.Empty(t, result.SecurityFindings)

	authRequired, ok := result.Metadata["auth_required"].(bool)
	assert.True(t, ok)
	assert.True(t, authRequired)
}

func TestWinRMAuthRequiredTLS(t *testing.T) {
	fp := &WinRMFingerprinter{}
	resp := &http.Response{
		StatusCode: 401,
		Header:     make(http.Header),
		TLS:        &tls.ConnectionState{},
	}
	resp.Header.Set("Server", "Microsoft-HTTPAPI/2.0")

	result, err := fp.Fingerprint(resp, nil)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, plugins.Severity(""), result.Severity)
	assert.Empty(t, result.SecurityFindings)

	authRequired, ok := result.Metadata["auth_required"].(bool)
	assert.True(t, ok)
	assert.True(t, authRequired)
}

func TestWinRMStatusCodeEdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"405 Method Not Allowed", 405},
		{"403 Forbidden", 403},
		{"400 Bad Request", 400},
		{"302 Redirect", 302},
		{"500 Internal Server Error", 500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &WinRMFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header: http.Header{
					"Server": []string{"Microsoft-HTTPAPI/2.0"},
				},
			}
			result, err := fp.Fingerprint(resp, nil)
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Empty(t, result.Severity, "status %d should not set severity", tt.statusCode)
			assert.Empty(t, result.SecurityFindings, "status %d should not produce findings", tt.statusCode)
		})
	}
}

func TestWinRMFingerprinter_Integration(t *testing.T) {
	fp := &WinRMFingerprinter{}

	// Create a WinRM response with 401
	body := []byte{}
	resp := &http.Response{
		StatusCode: 401,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Microsoft-HTTPAPI/2.0")

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "winrm", result.Technology)
	authRequired, ok := result.Metadata["auth_required"].(bool)
	assert.True(t, ok, "authRequired should be bool type")
	assert.True(t, authRequired)
}

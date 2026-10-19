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
	resp.Header.Set("Www-Authenticate", "Negotiate")

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

	// Bare HTTP.sys 200 is not WinRM — many HTTP.sys listeners answer 200.
	result, err := fp.Fingerprint(resp, nil)
	require.NoError(t, err)
	assert.Nil(t, result)
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
	resp.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")

	result, err := fp.Fingerprint(resp, []byte(wsmanIdentifyResponse))
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
	resp.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")

	result, err := fp.Fingerprint(resp, []byte(wsmanIdentifyResponse))
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
	resp.Header.Set("Www-Authenticate", "Negotiate")

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
	resp.Header.Set("Www-Authenticate", "Negotiate")

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
			assert.Nil(t, result, "status %d without WS-Man evidence is not WinRM", tt.statusCode)
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
	resp.Header.Set("Www-Authenticate", "Negotiate")

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "winrm", result.Technology)
	authRequired, ok := result.Metadata["auth_required"].(bool)
	assert.True(t, ok, "authRequired should be bool type")
	assert.True(t, authRequired)
}

const wsmanIdentifyResponse = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
  <s:Header/>
  <s:Body>
    <wsmid:IdentifyResponse>
      <wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>
      <wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>
      <wsmid:ProductVersion>OS: 0.0.0 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>
    </wsmid:IdentifyResponse>
  </s:Body>
</s:Envelope>`

const httpAPIGenericServicePage = `<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
    <title>Service</title>
  </head>
  <body>
    <div id="content">
      <p class="heading1">Service</p>
      <p>Endpoint not found.</p>
    </div>
  </body>
</html>`

func TestWinRMFingerprint_HTTPAPIGenericServicePageIsNotWinRM(t *testing.T) {
	fp := &WinRMFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		TLS:        &tls.ConnectionState{},
	}
	resp.Header.Set("Server", "Microsoft-HTTPAPI/2.0")
	resp.Header.Set("Content-Type", "application/xml; charset=utf-8")

	require.True(t, fp.Match(resp), "HTTPAPI still matches as a prefilter")
	result, err := fp.Fingerprint(resp, []byte(httpAPIGenericServicePage))
	require.NoError(t, err)
	assert.Nil(t, result, "WCF/HTTP.sys Endpoint not found must not be winrm-no-auth")
}

func TestWinRMFingerprint_EmptyHTTPAPI200IsNotWinRM(t *testing.T) {
	fp := &WinRMFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Server": []string{"Microsoft-HTTPAPI/2.0"}},
		TLS:        &tls.ConnectionState{},
	}
	result, err := fp.Fingerprint(resp, []byte{})
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestWinRMFingerprint_WSManBodyWithoutSoapContentType(t *testing.T) {
	fp := &WinRMFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Server": []string{"Microsoft-HTTPAPI/2.0"}},
		TLS:        &tls.ConnectionState{},
	}
	result, err := fp.Fingerprint(resp, []byte(wsmanIdentifyResponse))
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotEmpty(t, result.SecurityFindings)
	assert.Equal(t, "winrm-no-auth", result.SecurityFindings[0].ID)
}

func TestWinRMFingerprint_NegotiateChallengeIsWinRM(t *testing.T) {
	fp := &WinRMFingerprinter{}
	resp := &http.Response{
		StatusCode: 401,
		Header: http.Header{
			"Server":           []string{"Microsoft-HTTPAPI/2.0"},
			"Www-Authenticate": []string{`Negotiate`},
		},
	}
	result, err := fp.Fingerprint(resp, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "winrm", result.Technology)
	assert.Empty(t, result.SecurityFindings)
	assert.Equal(t, true, result.Metadata["auth_required"])
}

func TestWinRMFingerprint_GenericServicePage401IsNotWinRM(t *testing.T) {
	fp := &WinRMFingerprinter{}
	resp := &http.Response{
		StatusCode: 401,
		Header:     http.Header{"Server": []string{"Microsoft-HTTPAPI/2.0"}},
	}
	result, err := fp.Fingerprint(resp, []byte(httpAPIGenericServicePage))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestIsHTTPAPIGenericServicePage(t *testing.T) {
	assert.True(t, isHTTPAPIGenericServicePage([]byte(httpAPIGenericServicePage)))
	assert.False(t, isHTTPAPIGenericServicePage([]byte(wsmanIdentifyResponse)))
	assert.False(t, isHTTPAPIGenericServicePage(nil))
	assert.False(t, isHTTPAPIGenericServicePage([]byte("endpoint not found")))
}

func TestWSManBody(t *testing.T) {
	// Only an actual WS-Man SOAP body is evidence; a SOAP Content-Type or a
	// Windows-auth header alone is not (those are exercised via Fingerprint).
	assert.True(t, wsManBody([]byte(wsmanIdentifyResponse)))
	assert.False(t, wsManBody([]byte(httpAPIGenericServicePage)))
	assert.False(t, wsManBody([]byte("<html>not wsman</html>")))
	assert.False(t, wsManBody(nil))
}

func TestWSManAuthChallenge(t *testing.T) {
	for _, scheme := range []string{"Negotiate", "Kerberos", "CredSSP"} {
		resp := &http.Response{Header: http.Header{"Www-Authenticate": []string{scheme}}}
		assert.True(t, wsManAuthChallenge(resp), scheme)
	}
	// Basic alone and no challenge are not WinRM challenges.
	basic := &http.Response{Header: http.Header{"Www-Authenticate": []string{`Basic realm="x"`}}}
	assert.False(t, wsManAuthChallenge(basic))
	assert.False(t, wsManAuthChallenge(&http.Response{Header: make(http.Header)}))
}

// A 2xx carrying only a Windows-auth header (no WS-Man body) is not WS-Man and
// must not raise a Critical winrm-no-auth finding.
func TestWinRMFingerprint_2xxNegotiateOnlyIsNotWinRM(t *testing.T) {
	fp := &WinRMFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Server":           []string{"Microsoft-HTTPAPI/2.0"},
			"Www-Authenticate": []string{"Negotiate"},
		},
		TLS: &tls.ConnectionState{},
	}
	result, err := fp.Fingerprint(resp, nil)
	require.NoError(t, err)
	assert.Nil(t, result, "a 200 with only an auth header is not WS-Man")
}

// A 2xx with only a SOAP Content-Type (no WS-Man body markers) is shared with
// WCF/HTTP.sys services and must not be winrm-no-auth.
func TestWinRMFingerprint_2xxSoapContentTypeOnlyIsNotWinRM(t *testing.T) {
	fp := &WinRMFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Server":       []string{"Microsoft-HTTPAPI/2.0"},
			"Content-Type": []string{"application/soap+xml; charset=utf-8"},
		},
		TLS: &tls.ConnectionState{},
	}
	result, err := fp.Fingerprint(resp, []byte("<html>not wsman</html>"))
	require.NoError(t, err)
	assert.Nil(t, result, "SOAP media type alone is not WS-Man evidence")
}

// After catalog enrichment, winrm-no-auth must stay Critical (unauthenticated
// remote command execution), not be downgraded.
func TestWinRMNoAuthFinding_CatalogEnrichment(t *testing.T) {
	f := plugins.SecurityFinding{ID: "winrm-no-auth", Severity: plugins.SeverityCritical}
	f.Enrich()
	assert.Equal(t, plugins.SeverityCritical, f.Severity, "catalog must keep winrm-no-auth Critical")
	assert.NotEmpty(t, f.Title)
	assert.NotEmpty(t, f.Impact)
	assert.NotEmpty(t, f.CVSS)
}

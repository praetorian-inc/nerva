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
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureKuduFingerprinter_Name(t *testing.T) {
	fp := &AzureKuduFingerprinter{}
	assert.Equal(t, "azure-app-service-kudu", fp.Name())
	assert.Equal(t, "/DebugConsole", fp.ProbeEndpoint())
	assert.Equal(t, "text/html", fp.ProbeAccept())
}

func TestAzureKuduFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		headers  map[string]string
		expected bool
	}{
		{
			name:   "matches Basic realm site",
			status: 401,
			headers: map[string]string{
				"WWW-Authenticate": `Basic realm="site"`,
			},
			expected: true,
		},
		{
			name:   "matches AAD SSO Location",
			status: 302,
			headers: map[string]string{
				"Location": "https://login.microsoftonline.com/common/oauth2/authorize?resource=https://appservice.azure.com",
			},
			expected: true,
		},
		{
			name:   "matches Kudu AAD client id",
			status: 302,
			headers: map[string]string{
				"Location": "https://login.microsoftonline.com/common/oauth2/authorize?client_id=" + azureKuduAADClientID,
			},
			expected: true,
		},
		{
			name:   "matches scm hostname redirect",
			status: 302,
			headers: map[string]string{
				"Location": "https://app.scm.azurewebsites.net/",
			},
			expected: true,
		},
		{
			name:   "matches 200 HTML for body inspection",
			status: 200,
			headers: map[string]string{
				"Content-Type": "text/html; charset=utf-8",
			},
			expected: true,
		},
		{
			name:     "does not match empty 200 without html",
			status:   200,
			headers:  map[string]string{"Content-Type": "application/json"},
			expected: false,
		},
		{
			name:     "does not match unrelated 401",
			status:   401,
			headers:  map[string]string{"WWW-Authenticate": `Basic realm="Restricted"`},
			expected: false,
		},
		{
			name:     "nil response",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &AzureKuduFingerprinter{}
			if tt.status == 0 && tt.headers == nil {
				assert.False(t, fp.Match(nil))
				return
			}
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{StatusCode: tt.status, Header: header}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestAzureKuduFingerprinter_Fingerprint(t *testing.T) {
	fp := &AzureKuduFingerprinter{}

	t.Run("basic auth challenge", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 401,
			Header:     http.Header{"Www-Authenticate": []string{`Basic realm="site"`}},
		}
		result, err := fp.Fingerprint(resp, nil)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "azure-app-service-kudu", result.Technology)
		assert.Equal(t, "basic", result.Metadata["auth_mode"])
		assert.Empty(t, result.SecurityFindings)
		require.NotEmpty(t, result.CPEs)
	})

	t.Run("aad sso redirect", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 302,
			Header: http.Header{
				"Location": []string{"https://login.microsoftonline.com/common/oauth2/authorize?resource=https://appservice.azure.com&client_id=" + azureKuduAADClientID},
			},
		}
		result, err := fp.Fingerprint(resp, nil)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "aad", result.Metadata["auth_mode"])
		assert.Empty(t, result.SecurityFindings)
	})

	t.Run("unauthenticated debug console", func(t *testing.T) {
		body := []byte(`<html><head><title>Debug console - Kudu</title></head><body><script src="/kudu.js"></script></body></html>`)
		resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}}
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "none", result.Metadata["auth_mode"])
		require.Len(t, result.SecurityFindings, 1)
		assert.Equal(t, "kudu-unauthenticated-console", result.SecurityFindings[0].ID)
		assert.Equal(t, "critical", string(result.Severity))
		result.SecurityFindings[0].Enrich()
		assert.Equal(t, "critical", string(result.SecurityFindings[0].Severity))
	})

	t.Run("unauthenticated console embedding its scm hostname still flags critical", func(t *testing.T) {
		// Regression: a real Kudu console links to its own *.scm.azurewebsites.net
		// host, which must not be misread as an AAD SSO redirect and suppress the finding.
		body := []byte(`<html><head><title>Debug console - Kudu</title></head><body><script src="https://myapp.scm.azurewebsites.net/kudu.js"></script></body></html>`)
		resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}}
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "none", result.Metadata["auth_mode"])
		require.Len(t, result.SecurityFindings, 1)
		assert.Equal(t, "kudu-unauthenticated-console", result.SecurityFindings[0].ID)
	})

	t.Run("aad login html is not kudu console", func(t *testing.T) {
		body := []byte(`<html><head><title>Sign in to your account</title></head><body>Kudu</body></html>`)
		resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}}
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("generic html is not kudu", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}}
		result, err := fp.Fingerprint(resp, []byte(`<html><title>Hello</title></html>`))
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

func TestAzureKuduFingerprinter_CheckMisconfigs(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		responseBody  string
		expectFinding bool
	}{
		{
			name:          "unauthenticated process list",
			statusCode:    200,
			responseBody:  `[{"id":1234,"name":"w3wp","is_scm_site":false,"is_webjob":false}]`,
			expectFinding: true,
		},
		{
			name:          "auth required",
			statusCode:    401,
			responseBody:  `unauthorized`,
			expectFinding: false,
		},
		{
			name:          "unrelated json 200",
			statusCode:    200,
			responseBody:  `{"hello":"world"}`,
			expectFinding: false,
		},
		{
			name:          "json array of strings, not process objects",
			statusCode:    200,
			responseBody:  `["is_scm_site","is_webjob","id"]`,
			expectFinding: false,
		},
		{
			name:          "html mentioning process tokens",
			statusCode:    200,
			responseBody:  `<html>"id" "is_webjob" w3wp</html>`,
			expectFinding: false,
		},
		{
			name:          "process list where the first record lacks scm markers",
			statusCode:    200,
			responseBody:  `[{"id":1,"name":"dotnet"},{"id":2,"name":"w3wp"}]`,
			expectFinding: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/processes" {
					w.WriteHeader(tt.statusCode)
					_, _ = w.Write([]byte(tt.responseBody))
					return
				}
				w.WriteHeader(404)
			}))
			defer ts.Close()

			fp := &AzureKuduFingerprinter{}
			findings := fp.CheckMisconfigs(ts.Client(), ts.URL, "")
			if tt.expectFinding {
				require.Len(t, findings, 1)
				assert.Equal(t, "kudu-unauthenticated-api", findings[0].ID)
				findings[0].Enrich()
				assert.Equal(t, "high", string(findings[0].Severity))
			} else {
				assert.Empty(t, findings)
			}
		})
	}
}

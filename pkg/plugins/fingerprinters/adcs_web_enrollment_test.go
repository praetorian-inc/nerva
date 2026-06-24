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

func TestADCSWebEnrollmentFingerprinter_Name(t *testing.T) {
	fp := &ADCSWebEnrollmentFingerprinter{}
	assert.Equal(t, "adcs-web-enrollment", fp.Name())
}

func TestADCSWebEnrollmentFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &ADCSWebEnrollmentFingerprinter{}
	assert.Equal(t, "/certsrv/", fp.ProbeEndpoint())
}

func TestADCSWebEnrollmentFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wwwAuth    string
		server     string
		want       bool
	}{
		{
			name:       "401 + NTLM + IIS returns true",
			statusCode: 401,
			wwwAuth:    "NTLM",
			server:     "Microsoft-IIS/10.0",
			want:       true,
		},
		{
			name:       "403 + Negotiate + IIS returns true",
			statusCode: 403,
			wwwAuth:    "Negotiate",
			server:     "Microsoft-IIS/10.0",
			want:       true,
		},
		{
			name:       "200 + NTLM + IIS returns false",
			statusCode: 200,
			wwwAuth:    "NTLM",
			server:     "Microsoft-IIS/10.0",
			want:       false,
		},
		{
			name:       "401 + Basic + IIS returns false",
			statusCode: 401,
			wwwAuth:    "Basic",
			server:     "Microsoft-IIS/10.0",
			want:       false,
		},
		{
			name:       "401 + NTLM + nginx returns false",
			statusCode: 401,
			wwwAuth:    "NTLM",
			server:     "nginx",
			want:       false,
		},
		{
			name:       "401 + IIS + no WWW-Authenticate returns false",
			statusCode: 401,
			wwwAuth:    "",
			server:     "Microsoft-IIS/10.0",
			want:       false,
		},
		{
			name:       "no relevant headers returns false",
			statusCode: 200,
			wwwAuth:    "",
			server:     "",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ADCSWebEnrollmentFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.wwwAuth != "" {
				resp.Header.Set("WWW-Authenticate", tt.wwwAuth)
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			got := fp.Match(resp)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestADCSWebEnrollmentFingerprinter_Fingerprint_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wwwAuth    string
	}{
		{
			name:       "401 with NTLM",
			statusCode: 401,
			wwwAuth:    "NTLM",
		},
		{
			name:       "403 with Negotiate",
			statusCode: 403,
			wwwAuth:    "Negotiate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ADCSWebEnrollmentFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			resp.Header.Set("WWW-Authenticate", tt.wwwAuth)
			resp.Header.Set("Server", "Microsoft-IIS/10.0")

			result, err := fp.Fingerprint(resp, nil)
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "adcs-web-enrollment", result.Technology)

			require.NotEmpty(t, result.CPEs)
			expectedCPE := "cpe:2.3:a:microsoft:certificate_services:*:*:*:*:*:*:*:*"
			assert.Contains(t, result.CPEs, expectedCPE)
		})
	}
}

func TestADCSWebEnrollmentFingerprinter_Fingerprint_NotADCS(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wwwAuth    string
		server     string
	}{
		{
			name:       "wrong status code",
			statusCode: 200,
			wwwAuth:    "NTLM",
			server:     "Microsoft-IIS/10.0",
		},
		{
			name:       "unsupported auth scheme",
			statusCode: 401,
			wwwAuth:    "Basic",
			server:     "Microsoft-IIS/10.0",
		},
		{
			name:       "non-IIS server",
			statusCode: 401,
			wwwAuth:    "NTLM",
			server:     "nginx",
		},
		{
			name:       "missing WWW-Authenticate",
			statusCode: 401,
			wwwAuth:    "",
			server:     "Microsoft-IIS/10.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ADCSWebEnrollmentFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.wwwAuth != "" {
				resp.Header.Set("WWW-Authenticate", tt.wwwAuth)
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

func TestBuildADCSCPEs(t *testing.T) {
	got := buildADCSCPEs()
	want := []string{
		"cpe:2.3:a:microsoft:certificate_services:*:*:*:*:*:*:*:*",
	}
	assert.Equal(t, want, got)
}

func TestADCSWebEnrollmentFingerprinter_Integration(t *testing.T) {
	fp := &ADCSWebEnrollmentFingerprinter{}

	resp := &http.Response{
		StatusCode: 401,
		Header:     make(http.Header),
	}
	resp.Header.Set("WWW-Authenticate", "NTLM")
	resp.Header.Set("Server", "Microsoft-IIS/10.0")

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "adcs-web-enrollment", result.Technology)
}

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

func TestWSUSFingerprinter_Name(t *testing.T) {
	fp := &WSUSFingerprinter{}
	assert.Equal(t, "wsus", fp.Name())
}

func TestWSUSFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &WSUSFingerprinter{}
	assert.Equal(t, "/ClientWebService/client.asmx", fp.ProbeEndpoint())
}

func TestWSUSFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   bool
	}{
		{
			name:   "Server: Microsoft-IIS/10.0 returns true",
			server: "Microsoft-IIS/10.0",
			want:   true,
		},
		{
			name:   "Server: Microsoft-IIS/8.5 returns true",
			server: "Microsoft-IIS/8.5",
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
			fp := &WSUSFingerprinter{}
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

func TestWSUSFingerprinter_Fingerprint_Match(t *testing.T) {
	fp := &WSUSFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Microsoft-IIS/10.0")
	body := []byte("<html>ClientWebServiceClient</html>")

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "wsus", result.Technology)

	require.NotEmpty(t, result.CPEs)
	expectedCPE := "cpe:2.3:a:microsoft:windows_server_update_services:*:*:*:*:*:*:*:*"
	assert.Contains(t, result.CPEs, expectedCPE)
}

func TestWSUSFingerprinter_Fingerprint_NotWSUS(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{
			name: "empty body",
			body: []byte{},
		},
		{
			name: "nil body",
			body: nil,
		},
		{
			name: "body without marker string",
			body: []byte("<html>some other IIS app</html>"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &WSUSFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			resp.Header.Set("Server", "Microsoft-IIS/10.0")

			result, err := fp.Fingerprint(resp, tt.body)
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

func TestBuildWSUSCPEs(t *testing.T) {
	got := buildWSUSCPEs()
	want := []string{
		"cpe:2.3:a:microsoft:windows_server_update_services:*:*:*:*:*:*:*:*",
	}
	assert.Equal(t, want, got)
}

func TestWSUSFingerprinter_Integration(t *testing.T) {
	fp := &WSUSFingerprinter{}

	body := []byte("<html>ClientWebServiceClient</html>")
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Microsoft-IIS/10.0")

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "wsus", result.Technology)
}

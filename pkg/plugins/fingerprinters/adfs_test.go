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

func TestADFSFingerprinter_Name(t *testing.T) {
	fp := &ADFSFingerprinter{}
	assert.Equal(t, "adfs", fp.Name())
}

func TestADFSFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &ADFSFingerprinter{}
	assert.Equal(t, "/adfs/ls", fp.ProbeEndpoint())
}

func TestADFSFingerprinter_Match(t *testing.T) {
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
			fp := &ADFSFingerprinter{}
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

func TestADFSFingerprinter_Fingerprint_Match(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{
			name: "css marker string",
			body: []byte(`<link href="/adfs/portal/css/style.css">`),
		},
		{
			name: "images marker string",
			body: []byte(`<img src="/adfs/portal/images/logo.png">`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ADFSFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			resp.Header.Set("Server", "Microsoft-HTTPAPI/2.0")

			result, err := fp.Fingerprint(resp, tt.body)
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "adfs", result.Technology)

			require.NotEmpty(t, result.CPEs)
			expectedCPE := "cpe:2.3:a:microsoft:active_directory_federation_services:*:*:*:*:*:*:*:*"
			assert.Contains(t, result.CPEs, expectedCPE)
		})
	}
}

func TestADFSFingerprinter_Fingerprint_NotADFS(t *testing.T) {
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
			body: []byte("<html>some other HTTPAPI app</html>"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ADFSFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			resp.Header.Set("Server", "Microsoft-HTTPAPI/2.0")

			result, err := fp.Fingerprint(resp, tt.body)
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

func TestBuildADFSCPEs(t *testing.T) {
	got := buildADFSCPEs()
	want := []string{
		"cpe:2.3:a:microsoft:active_directory_federation_services:*:*:*:*:*:*:*:*",
	}
	assert.Equal(t, want, got)
}

func TestADFSFingerprinter_Integration(t *testing.T) {
	fp := &ADFSFingerprinter{}

	body := []byte(`<link href="/adfs/portal/css/style.css">`)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Microsoft-HTTPAPI/2.0")

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "adfs", result.Technology)
}

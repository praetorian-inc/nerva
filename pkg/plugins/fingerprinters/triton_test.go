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

func TestTritonFingerprinter_Name(t *testing.T) {
	fp := &TritonFingerprinter{}
	assert.Equal(t, "triton", fp.Name())
}

func TestTritonFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &TritonFingerprinter{}
	assert.Equal(t, "/v2", fp.ProbeEndpoint())
}

func TestTritonFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{
			name:        "200 with application/json returns true",
			statusCode:  200,
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "200 with application/json; charset=utf-8 returns true",
			statusCode:  200,
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "404 with application/json returns false",
			statusCode:  404,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "200 with text/html returns false",
			statusCode:  200,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "200 with no Content-Type returns false",
			statusCode:  200,
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TritonFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     http.Header{"Content-Type": []string{tt.contentType}},
			}
			if tt.contentType == "" {
				resp.Header = make(http.Header)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

func TestTritonFingerprinter_Fingerprint(t *testing.T) {
	fp := &TritonFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}

	t.Run("valid triton JSON with version and extensions", func(t *testing.T) {
		body := []byte(`{"name":"triton","version":"2.42.0","extensions":["classification","sequence"]}`)
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "triton", result.Technology)
		assert.Equal(t, "2.42.0", result.Version)
		assert.Equal(t, []string{"cpe:2.3:a:nvidia:triton_inference_server:2.42.0:*:*:*:*:*:*:*"}, result.CPEs)
		exts, ok := result.Metadata["extensions"].([]string)
		require.True(t, ok)
		assert.Equal(t, []string{"classification", "sequence"}, exts)
	})

	t.Run("valid triton JSON without extensions", func(t *testing.T) {
		body := []byte(`{"name":"triton","version":"2.40.0"}`)
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "triton", result.Technology)
		assert.Equal(t, "2.40.0", result.Version)
		_, hasExtensions := result.Metadata["extensions"]
		assert.False(t, hasExtensions)
	})

	t.Run("non-triton name returns nil", func(t *testing.T) {
		body := []byte(`{"name":"other-server","version":"1.0.0"}`)
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("missing name field returns nil", func(t *testing.T) {
		body := []byte(`{"version":"2.42.0","extensions":["classification"]}`)
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("invalid JSON returns nil", func(t *testing.T) {
		body := []byte(`not valid json`)
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("empty version returns result with wildcard CPE", func(t *testing.T) {
		body := []byte(`{"name":"triton","version":""}`)
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "", result.Version)
		assert.Equal(t, []string{"cpe:2.3:a:nvidia:triton_inference_server:*:*:*:*:*:*:*:*"}, result.CPEs)
	})

	t.Run("version with CPE-injection characters returns wildcard CPE", func(t *testing.T) {
		body := []byte(`{"name":"triton","version":"2.0.0:*:*","extensions":["classification"]}`)
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		// Should detect triton but with wildcard CPE since version is invalid
		assert.Equal(t, "triton", result.Technology)
		assert.Equal(t, "", result.Version)
		assert.Equal(t, []string{"cpe:2.3:a:nvidia:triton_inference_server:*:*:*:*:*:*:*:*"}, result.CPEs)
	})
}

func TestTritonFingerprinter_Integration(t *testing.T) {
	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &TritonFingerprinter{}
	Register(fp)

	// Create a valid Triton metadata response
	body := []byte(`{"name":"triton","version":"2.42.0","extensions":["classification"]}`)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	results := RunFingerprinters(resp, body)

	// Should find at least the Triton fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "triton" {
			found = true
			assert.Equal(t, "2.42.0", result.Version)
			assert.Equal(t, []string{"cpe:2.3:a:nvidia:triton_inference_server:2.42.0:*:*:*:*:*:*:*"}, result.CPEs)
		}
	}

	if !found {
		t.Error("TritonFingerprinter not found in results")
	}
}

func TestBuildTritonCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "with version",
			version: "2.42.0",
			want:    "cpe:2.3:a:nvidia:triton_inference_server:2.42.0:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:nvidia:triton_inference_server:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildTritonCPE(tt.version))
		})
	}
}

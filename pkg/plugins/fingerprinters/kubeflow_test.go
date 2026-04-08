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

func TestKubeflowFingerprinter_Name(t *testing.T) {
	fp := &KubeflowFingerprinter{}
	assert.Equal(t, "kubeflow", fp.Name())
}

func TestKubeflowFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &KubeflowFingerprinter{}
	assert.Equal(t, "/api/workgroup/env-info", fp.ProbeEndpoint())
}

func TestKubeflowFingerprinter_Match(t *testing.T) {
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
			name:        "matches text/html",
			contentType: "text/html",
			expected:    true,
		},
		{
			name:        "matches text/html with charset",
			contentType: "text/html; charset=UTF-8",
			expected:    true,
		},
		{
			name:        "does not match text/plain",
			contentType: "text/plain",
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
			fp := &KubeflowFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestKubeflowFingerprinter_Fingerprint_HTMLValid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "standard Kubeflow Central Dashboard title",
			body: `<!DOCTYPE html><html><head><title>Kubeflow Central Dashboard</title></head><body></body></html>`,
		},
		{
			name: "case insensitive title",
			body: `<html><head><title>kubeflow central dashboard</title></head></html>`,
		},
		{
			name: "extra whitespace in title",
			body: `<html><head><title>  Kubeflow  Central  Dashboard  </title></head></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &KubeflowFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{"text/html; charset=UTF-8"},
				},
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, "kubeflow", result.Technology)
			assert.Equal(t, "", result.Version)
			assert.Contains(t, result.CPEs, "cpe:2.3:a:kubeflow:kubeflow:*:*:*:*:*:*:*:*")
		})
	}
}

func TestKubeflowFingerprinter_Fingerprint_HTMLNotKubeflow(t *testing.T) {
	fp := &KubeflowFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"text/html"},
		},
	}

	body := []byte(`<html><head><title>Jenkins</title></head><body></body></html>`)

	result, err := fp.Fingerprint(resp, body)

	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestKubeflowFingerprinter_Fingerprint_JSONValid(t *testing.T) {
	t.Run("full env-info with user and namespaces", func(t *testing.T) {
		fp := &KubeflowFingerprinter{}
		resp := &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
		}

		body := `{
			"platform": {"provider": "gcp", "providerName": "Google Cloud", "buildVersion": "1.8.0", "buildId": "abc123"},
			"user": "user@example.com",
			"namespaces": [
				{"user": "user@example.com", "namespace": "kubeflow-user", "role": "contributor", "owner": "user@example.com"}
			]
		}`

		result, err := fp.Fingerprint(resp, []byte(body))

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "kubeflow", result.Technology)
		assert.Equal(t, "1.8.0", result.Version)
		assert.Contains(t, result.CPEs, "cpe:2.3:a:kubeflow:kubeflow:1.8.0:*:*:*:*:*:*:*")
		assert.Equal(t, "user@example.com", result.Metadata["user"])
		assert.Equal(t, "gcp", result.Metadata["provider"])
		assert.Equal(t, "Google Cloud", result.Metadata["provider_name"])
		assert.Equal(t, 1, result.Metadata["namespace_count"])
	})

	t.Run("empty namespaces array is still valid", func(t *testing.T) {
		fp := &KubeflowFingerprinter{}
		resp := &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
		}

		body := `{
			"platform": {},
			"user": "admin",
			"namespaces": []
		}`

		result, err := fp.Fingerprint(resp, []byte(body))

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "kubeflow", result.Technology)
		assert.Equal(t, "", result.Version)
		assert.Contains(t, result.CPEs, "cpe:2.3:a:kubeflow:kubeflow:*:*:*:*:*:*:*:*")
		assert.Equal(t, "admin", result.Metadata["user"])
		assert.NotContains(t, result.Metadata, "provider")
		assert.NotContains(t, result.Metadata, "namespace_count")
	})

	t.Run("platform without build version", func(t *testing.T) {
		fp := &KubeflowFingerprinter{}
		resp := &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
		}

		body := `{
			"platform": {"provider": "aws"},
			"user": "admin@kubeflow.org",
			"namespaces": []
		}`

		result, err := fp.Fingerprint(resp, []byte(body))

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "kubeflow", result.Technology)
		assert.Equal(t, "", result.Version)
		assert.Contains(t, result.CPEs, "cpe:2.3:a:kubeflow:kubeflow:*:*:*:*:*:*:*:*")
		assert.Equal(t, "aws", result.Metadata["provider"])
	})

	t.Run("CPE injection in buildVersion is rejected", func(t *testing.T) {
		fp := &KubeflowFingerprinter{}
		resp := &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
		}

		body := `{
			"platform": {"provider": "gcp", "buildVersion": "1.8.0:*:*:*:*:*:*:*"},
			"user": "user@example.com",
			"namespaces": []
		}`

		result, err := fp.Fingerprint(resp, []byte(body))

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "kubeflow", result.Technology)
		assert.Equal(t, "", result.Version)
		assert.Contains(t, result.CPEs, "cpe:2.3:a:kubeflow:kubeflow:*:*:*:*:*:*:*:*")
	})

	t.Run("pre-release version is treated as empty", func(t *testing.T) {
		fp := &KubeflowFingerprinter{}
		resp := &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
		}

		body := `{
			"platform": {"provider": "gcp", "buildVersion": "1.9.0-rc.1"},
			"user": "user@example.com",
			"namespaces": []
		}`

		result, err := fp.Fingerprint(resp, []byte(body))

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "", result.Version)
		assert.Contains(t, result.CPEs, "cpe:2.3:a:kubeflow:kubeflow:*:*:*:*:*:*:*:*")
	})

	t.Run("platform as string returns nil (unmarshal fails gracefully)", func(t *testing.T) {
		fp := &KubeflowFingerprinter{}
		resp := &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
		}

		body := `{
			"platform": "gke",
			"user": "admin",
			"namespaces": []
		}`

		result, err := fp.Fingerprint(resp, []byte(body))

		assert.NoError(t, err)
		assert.Nil(t, result)
	})
}

func TestKubeflowFingerprinter_Fingerprint_JSONEmptyBody(t *testing.T) {
	fp := &KubeflowFingerprinter{}

	t.Run("empty body with JSON content type returns nil", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
		}

		result, err := fp.Fingerprint(resp, []byte{})

		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("empty body with HTML content type returns nil", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"text/html"},
			},
		}

		result, err := fp.Fingerprint(resp, []byte{})

		assert.NoError(t, err)
		assert.Nil(t, result)
	})
}

func TestKubeflowFingerprinter_Fingerprint_JSONMissingUser(t *testing.T) {
	fp := &KubeflowFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	body := []byte(`{"platform": {}, "user": "", "namespaces": []}`)

	result, err := fp.Fingerprint(resp, body)

	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestKubeflowFingerprinter_Fingerprint_JSONMissingNamespacesKey(t *testing.T) {
	fp := &KubeflowFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	// namespaces key is absent entirely
	body := []byte(`{"platform": {}, "user": "admin"}`)

	result, err := fp.Fingerprint(resp, body)

	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestKubeflowFingerprinter_Fingerprint_JSONInvalid(t *testing.T) {
	fp := &KubeflowFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	body := []byte("not valid json")

	result, err := fp.Fingerprint(resp, body)

	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestKubeflowFingerprinter_Fingerprint_JSONUnrelated(t *testing.T) {
	fp := &KubeflowFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	body := []byte(`{"status": "ok"}`)

	result, err := fp.Fingerprint(resp, body)

	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestBuildKubeflowCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "empty version uses wildcard",
			version:  "",
			expected: "cpe:2.3:a:kubeflow:kubeflow:*:*:*:*:*:*:*:*",
		},
		{
			name:     "with version",
			version:  "1.8.0",
			expected: "cpe:2.3:a:kubeflow:kubeflow:1.8.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildKubeflowCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKubeflowFingerprinter_Integration(t *testing.T) {
	originalCount := len(GetFingerprinters())
	t.Cleanup(func() {
		httpFingerprinters = httpFingerprinters[:originalCount]
	})

	fp := &KubeflowFingerprinter{}
	Register(fp)

	body := []byte(`{
		"platform": {"provider": "gcp", "providerName": "Google Cloud", "buildVersion": "1.8.0", "buildId": "abc123"},
		"user": "user@example.com",
		"namespaces": [
			{"user": "user@example.com", "namespace": "kubeflow-user", "role": "contributor", "owner": "user@example.com"}
		]
	}`)

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	results := RunFingerprinters(resp, body)

	found := false
	for _, result := range results {
		if result.Technology == "kubeflow" {
			found = true
			assert.Equal(t, "user@example.com", result.Metadata["user"])
			assert.Equal(t, "1.8.0", result.Version)
		}
	}

	if !found {
		t.Error("KubeflowFingerprinter not found in results")
	}
}

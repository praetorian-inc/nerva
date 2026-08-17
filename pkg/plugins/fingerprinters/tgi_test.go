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

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// ── TGIInfoFingerprinter: Name / ProbeEndpoint ───────────────────────────────

func TestTGIInfoFingerprinter_Name(t *testing.T) {
	fp := &TGIInfoFingerprinter{}
	assert.Equal(t, "tgi", fp.Name())
}

func TestTGIInfoFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &TGIInfoFingerprinter{}
	assert.Equal(t, "/info", fp.ProbeEndpoint())
}

// ── TGIInfoFingerprinter: Match ───────────────────────────────────────────────

func TestTGIInfoFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{
			name:        "200 application/json → true",
			statusCode:  200,
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "200 application/json charset → true",
			statusCode:  200,
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "200 APPLICATION/JSON mixed case → true",
			statusCode:  200,
			contentType: "APPLICATION/JSON",
			want:        true,
		},
		{
			name:        "200 text/html → false",
			statusCode:  200,
			contentType: "text/html",
			want:        false,
		},
		{
			name:       "200 no content-type → false",
			statusCode: 200,
			want:       false,
		},
		{
			name:        "404 application/json → false",
			statusCode:  404,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "500 application/json → false",
			statusCode:  500,
			contentType: "application/json",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TGIInfoFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── TGIInfoFingerprinter: Fingerprint (valid) ────────────────────────────────

func TestTGIInfoFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		wantVersion   string
		wantCPE       string
		wantModelID   string
		wantModelSHA  any
		wantDockerLbl any
	}{
		{
			name: "full valid response",
			body: `{
				"model_id": "meta-llama/Meta-Llama-3-70B-Instruct",
				"model_sha": "abc123",
				"router": "text-generation-router",
				"version": "2.0.2",
				"docker_label": "sha-dccab72"
			}`,
			wantVersion:   "2.0.2",
			wantCPE:       "cpe:2.3:a:huggingface:text_generation_inference:2.0.2:*:*:*:*:*:*:*",
			wantModelID:   "meta-llama/Meta-Llama-3-70B-Instruct",
			wantModelSHA:  "abc123",
			wantDockerLbl: "sha-dccab72",
		},
		{
			name: "null optional fields",
			body: `{
				"model_id": "gpt2",
				"model_sha": null,
				"model_pipeline_tag": null,
				"router": "text-generation-router",
				"version": "2.0.2",
				"docker_label": null
			}`,
			wantVersion: "2.0.2",
			wantCPE:     "cpe:2.3:a:huggingface:text_generation_inference:2.0.2:*:*:*:*:*:*:*",
			wantModelID: "gpt2",
		},
		{
			name:        "router exact match to spec sample",
			body:        `{"model_id":"m","router":"text-generation-router","version":"1.2.3"}`,
			wantVersion: "1.2.3",
			wantCPE:     "cpe:2.3:a:huggingface:text_generation_inference:1.2.3:*:*:*:*:*:*:*",
			wantModelID: "m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TGIInfoFingerprinter{}
			resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
			resp.Header.Set("Content-Type", "application/json")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "tgi", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.wantCPE)
			assert.Equal(t, plugins.SeverityHigh, result.Severity)
			require.Len(t, result.SecurityFindings, 1)
			assert.Equal(t, "tgi-unauthenticated-api", result.SecurityFindings[0].ID)
			assert.Equal(t, plugins.SeverityHigh, result.SecurityFindings[0].Severity)

			if tt.wantModelID != "" {
				assert.Equal(t, tt.wantModelID, result.Metadata["model_id"])
			}
			if tt.wantModelSHA != nil {
				assert.Equal(t, tt.wantModelSHA, result.Metadata["model_sha"])
			} else {
				_, ok := result.Metadata["model_sha"]
				assert.False(t, ok, "model_sha should be absent when not present/null")
			}
			if tt.wantDockerLbl != nil {
				assert.Equal(t, tt.wantDockerLbl, result.Metadata["docker_label"])
			} else {
				_, ok := result.Metadata["docker_label"]
				assert.False(t, ok, "docker_label should be absent when not present/null")
			}
		})
	}
}

// ── TGIInfoFingerprinter: Fingerprint (invalid / false positive prevention) ──

func TestTGIInfoFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "non-JSON body",
			body: "not json",
		},
		{
			name: "empty body",
			body: "",
		},
		{
			name: "missing router field",
			body: `{"model_id":"m","version":"2.0.2"}`,
		},
		{
			name: "wrong router value",
			body: `{"model_id":"m","router":"vllm","version":"2.0.2"}`,
		},
		{
			name: "empty router value",
			body: `{"model_id":"m","router":"","version":"2.0.2"}`,
		},
		{
			name: "generic JSON API with version field (false positive prevention)",
			body: `{"message":"Welcome to Stewart Production Assistant","version":"1.0.0","docs":"/docs"}`,
		},
		{
			name: "vLLM /v1/models style response (false positive prevention)",
			body: `{"object":"list","data":[{"id":"meta-llama/Llama-3-70b","object":"model","owned_by":"vllm","root":"meta-llama/Llama-3-70b"}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TGIInfoFingerprinter{}
			resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
			resp.Header.Set("Content-Type", "application/json")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// ── TGIInfoFingerprinter: version handling ───────────────────────────────────

func TestTGIInfoFingerprinter_Fingerprint_VersionHandling(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantVersion string
		wantCPE     string
	}{
		{
			name:        "invalid version format falls back to wildcard",
			body:        `{"model_id":"m","router":"text-generation-router","version":"2.0.2-rc1"}`,
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:huggingface:text_generation_inference:*:*:*:*:*:*:*:*",
		},
		{
			name:        "empty version falls back to wildcard",
			body:        `{"model_id":"m","router":"text-generation-router","version":""}`,
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:huggingface:text_generation_inference:*:*:*:*:*:*:*:*",
		},
		{
			name:        "missing version field falls back to wildcard",
			body:        `{"model_id":"m","router":"text-generation-router"}`,
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:huggingface:text_generation_inference:*:*:*:*:*:*:*:*",
		},
		{
			name:        "CPE metacharacter injection attempt neutralized",
			body:        `{"model_id":"m","router":"text-generation-router","version":"2.0.2:*:evil"}`,
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:huggingface:text_generation_inference:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TGIInfoFingerprinter{}
			resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
			resp.Header.Set("Content-Type", "application/json")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.wantVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.wantCPE)
			assert.NotContains(t, result.CPEs[0], "evil")
		})
	}
}

func TestTGIInfoFingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	fp := &TGIInfoFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	big := make([]byte, 2*1024*1024+1)
	for i := range big {
		big[i] = 'x'
	}
	result, err := fp.Fingerprint(resp, big)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

// ── TGIInfoFingerprinter: model extraction ───────────────────────────────────

func TestTGIInfoFingerprinter_Fingerprint_ModelExtraction(t *testing.T) {
	fp := &TGIInfoFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	body := `{
		"model_id": "meta-llama/Meta-Llama-3-70B-Instruct",
		"model_sha": "dccab72549635c7eb5ddb17f43f0b7cdff07c214",
		"router": "text-generation-router",
		"version": "2.0.2",
		"docker_label": "sha-dccab72"
	}`

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "meta-llama/Meta-Llama-3-70B-Instruct", result.Metadata["model_id"])
	assert.Equal(t, "dccab72549635c7eb5ddb17f43f0b7cdff07c214", result.Metadata["model_sha"])
	assert.Equal(t, "sha-dccab72", result.Metadata["docker_label"])
}

// ── buildTGICPE ───────────────────────────────────────────────────────────────

func TestBuildTGICPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "with version",
			version:  "2.0.2",
			expected: "cpe:2.3:a:huggingface:text_generation_inference:2.0.2:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version → wildcard",
			version:  "",
			expected: "cpe:2.3:a:huggingface:text_generation_inference:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildTGICPE(tt.version))
		})
	}
}

// ── tgiVersionRegex boundary behavior ─────────────────────────────────────────

func TestTGIVersionRegex(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"2.0.2", true},
		{"0.0.1", true},
		{"10.20.30", true},
		{"5.38abc", false},
		{"V5.38.0", false},
		{"2.0.2-rc1", false},
		{"2.0", false},
		{"2.0.2.1", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			assert.Equal(t, tt.want, tgiVersionRegex.MatchString(tt.version))
		})
	}
}

// ── TGIMetricsFingerprinter: Name / ProbeEndpoint ────────────────────────────

func TestTGIMetricsFingerprinter_Name(t *testing.T) {
	fp := &TGIMetricsFingerprinter{}
	// Must differ from TGIInfoFingerprinter.Name() ("tgi") to avoid colliding
	// in the registry's GetProbeEndpoints/GetFingerprinterByName maps, which
	// are keyed by Name(), not Technology.
	assert.Equal(t, "tgi_metrics", fp.Name())
	assert.NotEqual(t, (&TGIInfoFingerprinter{}).Name(), fp.Name())
}

func TestTGIMetricsFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &TGIMetricsFingerprinter{}
	assert.Equal(t, "/metrics", fp.ProbeEndpoint())
}

// ── TGIMetricsFingerprinter: Match ────────────────────────────────────────────

func TestTGIMetricsFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{
			name:        "200 text/plain → true",
			statusCode:  200,
			contentType: "text/plain",
			want:        true,
		},
		{
			name:        "200 text/plain with prometheus version param → true",
			statusCode:  200,
			contentType: "text/plain; version=0.0.4; charset=utf-8",
			want:        true,
		},
		{
			name:        "200 TEXT/PLAIN mixed case → true",
			statusCode:  200,
			contentType: "TEXT/PLAIN",
			want:        true,
		},
		{
			name:        "200 application/json → false",
			statusCode:  200,
			contentType: "application/json",
			want:        false,
		},
		{
			name:       "200 no content-type → false",
			statusCode: 200,
			want:       false,
		},
		{
			name:        "404 text/plain → false",
			statusCode:  404,
			contentType: "text/plain",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TGIMetricsFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── TGIMetricsFingerprinter: Fingerprint ──────────────────────────────────────

const tgiMetricsBody = `# HELP tgi_request_count Total number of requests
# TYPE tgi_request_count counter
tgi_request_count 42
# HELP tgi_request_success Number of successful requests
# TYPE tgi_request_success counter
tgi_request_success 40
# HELP tgi_queue_size Current queue size
# TYPE tgi_queue_size gauge
tgi_queue_size 0
# HELP tgi_batch_current_size Current batch size
# TYPE tgi_batch_current_size gauge
tgi_batch_current_size 0
`

func TestTGIMetricsFingerprinter_Fingerprint_Valid(t *testing.T) {
	fp := &TGIMetricsFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	result, err := fp.Fingerprint(resp, []byte(tgiMetricsBody))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "tgi", result.Technology)
	assert.Empty(t, result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:huggingface:text_generation_inference:*:*:*:*:*:*:*:*")
	assert.Empty(t, result.SecurityFindings, "metrics fingerprinter must not emit findings; /info handles the unauthenticated-access finding to avoid duplicates")
}

func TestTGIMetricsFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "too few tgi_ metrics (only 1 distinct name)",
			body: "tgi_request_count 42\ntgi_request_count{route=\"/generate\"} 1\n",
		},
		{
			name: "no tgi_ metrics at all",
			body: "# HELP http_requests_total Total requests\nhttp_requests_total 100\n",
		},
		{
			name: "generic prometheus metrics without tgi_ prefix (false positive prevention)",
			body: "# HELP process_cpu_seconds_total Total CPU time\nprocess_cpu_seconds_total 1.23\ngo_goroutines 10\n",
		},
		{
			name: "empty body",
			body: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TGIMetricsFingerprinter{}
			resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
			resp.Header.Set("Content-Type", "text/plain")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

func TestTGIMetricsFingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	fp := &TGIMetricsFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/plain")

	big := make([]byte, 2*1024*1024+1)
	for i := range big {
		big[i] = 'x'
	}
	result, err := fp.Fingerprint(resp, big)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

// ── Registry: no Name() collision between the two TGI fingerprinters ────────
//
// Registered in isolation (save/restore the global registry) rather than
// relying on the ambient httpFingerprinters state populated by init(),
// because some other test files in this package (e.g. pinecone_test.go)
// clear httpFingerprinters without restoring it, making ambient-state
// assertions order-dependent across the full test binary.

func TestTGIFingerprinters_RegistryNoCollision(t *testing.T) {
	saved := httpFingerprinters
	defer func() { httpFingerprinters = saved }()

	httpFingerprinters = nil
	Register(&TGIInfoFingerprinter{})
	Register(&TGIMetricsFingerprinter{})

	endpoints := GetProbeEndpoints()
	assert.Equal(t, "/info", endpoints["tgi"], "TGIInfoFingerprinter must own the 'tgi' registry slot with /info")
	assert.Equal(t, "/metrics", endpoints["tgi_metrics"], "TGIMetricsFingerprinter must own its own registry slot with /metrics")

	infoFP := GetFingerprinterByName("tgi")
	require.NotNil(t, infoFP)
	_, isInfo := infoFP.(*TGIInfoFingerprinter)
	assert.True(t, isInfo, "GetFingerprinterByName(\"tgi\") must resolve to TGIInfoFingerprinter")

	metricsFP := GetFingerprinterByName("tgi_metrics")
	require.NotNil(t, metricsFP)
	_, isMetrics := metricsFP.(*TGIMetricsFingerprinter)
	assert.True(t, isMetrics, "GetFingerprinterByName(\"tgi_metrics\") must resolve to TGIMetricsFingerprinter")
}

// ── Integration: Match + Fingerprint ─────────────────────────────────────────

func TestTGIInfoFingerprinter_Integration(t *testing.T) {
	fp := &TGIInfoFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	require.True(t, fp.Match(resp))

	body := `{"model_id":"meta-llama/Meta-Llama-3-70B-Instruct","router":"text-generation-router","version":"2.0.2"}`
	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "tgi", result.Technology)
	assert.Equal(t, "2.0.2", result.Version)
}

func TestTGIInfoFingerprinter_Integration_NonTGI(t *testing.T) {
	fp := &TGIInfoFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte(`{"status":"healthy"}`))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestTGIMetricsFingerprinter_Integration(t *testing.T) {
	fp := &TGIMetricsFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte(tgiMetricsBody))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "tgi", result.Technology)
}

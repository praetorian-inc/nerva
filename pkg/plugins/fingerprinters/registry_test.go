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
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockFingerprinter for testing
type MockFingerprinter struct {
	name          string
	matchResult   bool
	fingerprintFn func(*http.Response, []byte) (*FingerprintResult, error)
}

func (m *MockFingerprinter) Name() string {
	return m.name
}

func (m *MockFingerprinter) Match(resp *http.Response) bool {
	return m.matchResult
}

func (m *MockFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if m.fingerprintFn != nil {
		return m.fingerprintFn(resp, body)
	}
	return &FingerprintResult{
		Technology: m.name,
		Version:    "1.0.0",
		CPEs:       []string{"cpe:2.3:a:test:test:1.0.0:*:*:*:*:*:*:*"},
	}, nil
}

func TestRegister(t *testing.T) {
	// Clear registry before test
	httpFingerprinters = nil

	fp := &MockFingerprinter{
		name:        "test-fp",
		matchResult: true,
	}

	Register(fp)

	assert.Len(t, httpFingerprinters, 1, "should register one fingerprinter")
	assert.Equal(t, fp, httpFingerprinters[0], "should register the correct fingerprinter")
}

func TestGetFingerprinters(t *testing.T) {
	// Clear and setup registry
	httpFingerprinters = nil

	fp1 := &MockFingerprinter{name: "fp1", matchResult: true}
	fp2 := &MockFingerprinter{name: "fp2", matchResult: true}

	Register(fp1)
	Register(fp2)

	fingerprinters := GetFingerprinters()

	assert.Len(t, fingerprinters, 2, "should return all registered fingerprinters")
	assert.Equal(t, fp1, fingerprinters[0])
	assert.Equal(t, fp2, fingerprinters[1])
}

func TestRunFingerprinters_NoMatch(t *testing.T) {
	// Clear and setup registry
	httpFingerprinters = nil

	fp := &MockFingerprinter{
		name:        "no-match",
		matchResult: false, // Won't match
	}
	Register(fp)

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader([]byte("test body"))),
	}
	body := []byte("test body")

	results := RunFingerprinters(resp, body)

	assert.Empty(t, results, "should return no results when no fingerprinters match")
}

func TestRunFingerprinters_WithMatch(t *testing.T) {
	// Clear and setup registry
	httpFingerprinters = nil

	fp := &MockFingerprinter{
		name:        "kubernetes",
		matchResult: true,
		fingerprintFn: func(resp *http.Response, body []byte) (*FingerprintResult, error) {
			return &FingerprintResult{
				Technology: "kubernetes",
				Version:    "1.29.0",
				CPEs:       []string{"cpe:2.3:a:kubernetes:kubernetes:1.29.0:*:*:*:*:*:*:*"},
				Metadata: map[string]any{
					"platform": "linux/amd64",
				},
			}, nil
		},
	}
	Register(fp)

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"git_version":"v1.29.0"}`))),
	}
	body := []byte(`{"git_version":"v1.29.0"}`)

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1, "should return one result")
	assert.Equal(t, "kubernetes", results[0].Technology)
	assert.Equal(t, "1.29.0", results[0].Version)
	assert.Contains(t, results[0].CPEs, "cpe:2.3:a:kubernetes:kubernetes:1.29.0:*:*:*:*:*:*:*")
	assert.Equal(t, "linux/amd64", results[0].Metadata["platform"])
}

func TestRunFingerprinters_FingerprintError(t *testing.T) {
	// Clear and setup registry
	httpFingerprinters = nil

	fp := &MockFingerprinter{
		name:        "error-fp",
		matchResult: true,
		fingerprintFn: func(resp *http.Response, body []byte) (*FingerprintResult, error) {
			return nil, assert.AnError
		},
	}
	Register(fp)

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader([]byte("test"))),
	}
	body := []byte("test")

	results := RunFingerprinters(resp, body)

	assert.Empty(t, results, "should return no results when fingerprinting errors")
}

func TestRunFingerprinters_NilResult(t *testing.T) {
	// Clear and setup registry
	httpFingerprinters = nil

	fp := &MockFingerprinter{
		name:        "nil-fp",
		matchResult: true,
		fingerprintFn: func(resp *http.Response, body []byte) (*FingerprintResult, error) {
			return nil, nil // Not an error, just no match
		},
	}
	Register(fp)

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader([]byte("test"))),
	}
	body := []byte("test")

	results := RunFingerprinters(resp, body)

	assert.Empty(t, results, "should return no results when fingerprint returns nil")
}

func TestRunFingerprinters_MultipleFingerprinters(t *testing.T) {
	// Clear and setup registry
	httpFingerprinters = nil

	fp1 := &MockFingerprinter{
		name:        "tech1",
		matchResult: true,
		fingerprintFn: func(resp *http.Response, body []byte) (*FingerprintResult, error) {
			return &FingerprintResult{
				Technology: "tech1",
				Version:    "1.0.0",
				CPEs:       []string{"cpe:2.3:a:vendor1:tech1:1.0.0:*:*:*:*:*:*:*"},
			}, nil
		},
	}

	fp2 := &MockFingerprinter{
		name:        "tech2",
		matchResult: true,
		fingerprintFn: func(resp *http.Response, body []byte) (*FingerprintResult, error) {
			return &FingerprintResult{
				Technology: "tech2",
				Version:    "2.0.0",
				CPEs:       []string{"cpe:2.3:a:vendor2:tech2:2.0.0:*:*:*:*:*:*:*"},
			}, nil
		},
	}

	Register(fp1)
	Register(fp2)

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte("test"))),
	}
	body := []byte("test")

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 2, "should return results from both fingerprinters")
	assert.Equal(t, "tech1", results[0].Technology)
	assert.Equal(t, "tech2", results[1].Technology)
}

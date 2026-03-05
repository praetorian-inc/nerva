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

package http

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/nerva/pkg/plugins/fingerprinters"
)

func TestFormatTechnologyWithVersion(t *testing.T) {
	tests := []struct {
		name       string
		technology string
		version    string
		expected   string
	}{
		{
			name:       "technology with version",
			technology: "kubernetes",
			version:    "1.29.0",
			expected:   "kubernetes:1.29.0",
		},
		{
			name:       "technology without version",
			technology: "nginx",
			version:    "",
			expected:   "nginx",
		},
		{
			name:       "technology with complex version",
			technology: "nats",
			version:    "2.10.4",
			expected:   "nats:2.10.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatTechnologyWithVersion(tt.technology, tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProcessFingerprintResult_IncludesVersion(t *testing.T) {
	// This test verifies that when processing a FingerprintResult,
	// the version is included in the technology string.
	result := &fingerprinters.FingerprintResult{
		Technology: "kubernetes",
		Version:    "1.29.0",
		CPEs:       []string{"cpe:2.3:a:kubernetes:kubernetes:1.29.0:*:*:*:*:*:*:*"},
		Metadata: map[string]any{
			"platform":  "linux/amd64",
			"goVersion": "go1.21.5",
		},
	}

	tech, cpes, metadata := processFingerprintResult(result)

	// Version should be included in technology string
	assert.Equal(t, "kubernetes:1.29.0", tech)
	assert.Equal(t, []string{"cpe:2.3:a:kubernetes:kubernetes:1.29.0:*:*:*:*:*:*:*"}, cpes)
	assert.NotNil(t, metadata)
	assert.Equal(t, "linux/amd64", metadata["platform"])
}

func TestProcessFingerprintResult_NoVersion(t *testing.T) {
	result := &fingerprinters.FingerprintResult{
		Technology: "nginx",
		Version:    "",
		CPEs:       []string{"cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"},
	}

	tech, cpes, metadata := processFingerprintResult(result)

	// No version means just the technology name
	assert.Equal(t, "nginx", tech)
	assert.Equal(t, []string{"cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"}, cpes)
	assert.Nil(t, metadata)
}

func TestProcessFingerprintResult_NilResult(t *testing.T) {
	tech, cpes, metadata := processFingerprintResult(nil)

	assert.Equal(t, "", tech)
	assert.Nil(t, cpes)
	assert.Nil(t, metadata)
}

func TestFormatTechnologyWithVersion_SpecialCharacters(t *testing.T) {
	tests := []struct {
		name       string
		technology string
		version    string
		expected   string
	}{
		{
			name:       "k3s version with plus",
			technology: "kubernetes",
			version:    "1.28.3+k3s1",
			expected:   "kubernetes:1.28.3+k3s1",
		},
		{
			name:       "GKE version with dash",
			technology: "kubernetes",
			version:    "1.27.8-gke.1067004",
			expected:   "kubernetes:1.27.8-gke.1067004",
		},
		{
			name:       "version with spaces (edge case)",
			technology: "apache",
			version:    "2.4.52 (Ubuntu)",
			expected:   "apache:2.4.52 (Ubuntu)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatTechnologyWithVersion(tt.technology, tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProcessFingerprintResult_EmptyTechnology(t *testing.T) {
	result := &fingerprinters.FingerprintResult{
		Technology: "",
		Version:    "1.0.0",
		CPEs:       []string{},
	}

	tech, cpes, metadata := processFingerprintResult(result)

	// Even with empty technology, it should still format correctly
	assert.Equal(t, ":1.0.0", tech)
	assert.Empty(t, cpes)
	assert.Nil(t, metadata)
}

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
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
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

	tech, cpes, metadata, _ := processFingerprintResult(result)

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

	tech, cpes, metadata, _ := processFingerprintResult(result)

	// No version means just the technology name
	assert.Equal(t, "nginx", tech)
	assert.Equal(t, []string{"cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"}, cpes)
	assert.Nil(t, metadata)
}

func TestProcessFingerprintResult_NilResult(t *testing.T) {
	tech, cpes, metadata, _ := processFingerprintResult(nil)

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

	tech, cpes, metadata, _ := processFingerprintResult(result)

	// Empty technology with version still produces ":1.0.0"
	// but the caller should guard against appending empty technologies
	assert.Equal(t, ":1.0.0", tech)
	assert.Empty(t, cpes)
	assert.Nil(t, metadata)
}

func TestFingerprint_TitleExtraction(t *testing.T) {
	tests := []struct {
		name          string
		contentType   string
		body          string
		expectedTitle string
	}{
		{
			name:          "extracts title from html response",
			contentType:   "text/html; charset=utf-8",
			body:          "<html><head><title>My Dashboard</title></head><body></body></html>",
			expectedTitle: "My Dashboard",
		},
		{
			name:          "returns empty title for non-html response",
			contentType:   "application/json",
			body:          `{"status":"ok"}`,
			expectedTitle: "",
		},
		{
			name:          "returns empty title when no title tag present",
			contentType:   "text/html",
			body:          "<html><head></head><body>no title here</body></html>",
			expectedTitle: "",
		},
	}

	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		t.Fatal("unable to initialize wappalyzer:", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Status:     "200 OK",
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{tt.contentType}},
				Body:       io.NopCloser(bytes.NewBufferString(tt.body)),
			}
			_, _, _, _, _, title, _, err := fingerprint(resp, wappalyzerClient, nil, "", "", false)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedTitle, title)
		})
	}
}

func TestFingerprint_TitleEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		contentType   string
		body          string
		expectedTitle string
		description   string
	}{
		{
			// The outer <title> tag is opened; its text content begins with "<title>Inner"
			// because the tokenizer treats the nested <title> open tag as literal text
			// inside an already-open title element. The trailing </title> closes the inner
			// tag, leaving the outer unclosed, so the extracted value is "<title>Inner".
			name:          "nested title tags",
			contentType:   "text/html",
			body:          "<title><title>Inner</title></title>",
			expectedTitle: "<title>Inner",
			description:   "tokenizer behavior with nested title tags — outer tag text includes the inner open tag",
		},
		{
			// wappalyzergo's tokenizer extracts titles without truncation.
			// The full 10001-character string is returned unchanged.
			name:          "very long title",
			contentType:   "text/html",
			body:          "<html><head><title>" + strings.Repeat("A", 10001) + "</title></head></html>",
			expectedTitle: strings.Repeat("A", 10001),
			description:   "wappalyzergo handles 10k+ character titles without truncation or panic",
		},
		{
			// The HTML tokenizer decodes &amp; to & before returning the title text.
			name:          "title with html entities",
			contentType:   "text/html",
			body:          "<html><head><title>Dashboard &amp; Settings</title></head></html>",
			expectedTitle: "Dashboard & Settings",
			description:   "tokenizer decodes HTML entities in title text",
		},
		{
			// Whitespace and newlines inside the title are preserved as-is; no trimming occurs.
			name:          "title with whitespace and newlines",
			contentType:   "text/html",
			body:          "<html><head><title>\n  My Dashboard  \n</title></head></html>",
			expectedTitle: "\n  My Dashboard  \n",
			description:   "tokenizer preserves leading/trailing whitespace and newlines in title",
		},
		{
			// When multiple title tags appear, the last one wins — the tokenizer overwrites
			// the title on each new <title> open/close pair it encounters.
			name:          "multiple title tags last wins",
			contentType:   "text/html",
			body:          "<html><head><title>First</title><title>Second</title></head></html>",
			expectedTitle: "Second",
			description:   "last title tag wins when multiple are present",
		},
		{
			// The tokenizer does not validate HTML structure, so a <title> inside <body>
			// is extracted the same as one inside <head>.
			name:          "title in body not head",
			contentType:   "text/html",
			body:          "<html><body><title>Body Title</title></body></html>",
			expectedTitle: "Body Title",
			description:   "HTML tokenizer extracts title regardless of its position in the document",
		},
		{
			// An empty <title></title> pair returns an empty string, not nil or a blank.
			name:          "empty title tag",
			contentType:   "text/html",
			body:          "<html><head><title></title></head></html>",
			expectedTitle: "",
			description:   "empty title tag returns empty string",
		},
		{
			// Tag matching is case-insensitive: <TITLE> is treated identically to <title>.
			name:          "uppercase TITLE tag",
			contentType:   "text/html",
			body:          "<html><head><TITLE>Caps Title</TITLE></head></html>",
			expectedTitle: "Caps Title",
			description:   "tag matching is case-insensitive",
		},
	}

	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		t.Fatal("unable to initialize wappalyzer:", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Status:     "200 OK",
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{tt.contentType}},
				Body:       io.NopCloser(bytes.NewBufferString(tt.body)),
			}
			_, _, _, _, _, title, _, err := fingerprint(resp, wappalyzerClient, nil, "", "", false)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedTitle, title)
		})
	}
}

func TestFingerprintPipeline_Integration(t *testing.T) {
	// Test that the full pipeline correctly processes fingerprint results
	// including version in technology and metadata collection

	// Create a mock FingerprintResult
	mockResults := []*fingerprinters.FingerprintResult{
		{
			Technology: "kubernetes",
			Version:    "1.29.0",
			CPEs:       []string{"cpe:2.3:a:kubernetes:kubernetes:1.29.0:*:*:*:*:*:*:*"},
			Metadata: map[string]any{
				"platform":   "linux/amd64",
				"go_version": "go1.21.5",
			},
		},
		{
			Technology: "nginx",
			Version:    "1.24.0",
			CPEs:       []string{"cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"},
			Metadata:   nil,
		},
		{
			Technology: "",
			Version:    "1.0.0",
			CPEs:       []string{"cpe:2.3:a:unknown:unknown:1.0.0:*:*:*:*:*:*:*"},
			Metadata:   map[string]any{"should": "be-ignored"},
		},
	}

	var technologies []string
	var cpes []string
	fingerprintMetadata := make(map[string]map[string]any)

	for _, result := range mockResults {
		tech, resultCPEs, metadata, _ := processFingerprintResult(result)
		if result.Technology != "" { // Guard on raw technology, not formatted
			technologies = append(technologies, tech)
		}
		cpes = append(cpes, resultCPEs...)
		if metadata != nil && result.Technology != "" {
			fingerprintMetadata[result.Technology] = metadata
		}
	}

	// Verify technologies include versions (empty tech should be skipped)
	assert.Contains(t, technologies, "kubernetes:1.29.0")
	assert.Contains(t, technologies, "nginx:1.24.0")
	assert.Len(t, technologies, 2) // Still 2, empty tech skipped

	// Verify CPEs are collected (including from empty tech - CPEs are separate)
	assert.Len(t, cpes, 3)

	// Verify metadata is collected for kubernetes but not nginx or empty tech
	assert.Len(t, fingerprintMetadata, 1) // Still 1, empty tech metadata skipped
	assert.NotNil(t, fingerprintMetadata["kubernetes"])
	assert.Equal(t, "linux/amd64", fingerprintMetadata["kubernetes"]["platform"])
	assert.Nil(t, fingerprintMetadata["nginx"])
}

func TestProcessFingerprintResult_EmptyTechWithMetadata(t *testing.T) {
	// Verifies that metadata is accessible even when Technology is empty
	// (e.g., favicon fingerprinter returning an unknown hash).
	result := &fingerprinters.FingerprintResult{
		Technology: "",
		Version:    "",
		Metadata: map[string]any{
			"favicon_hash": "-1787112514",
		},
	}

	tech, cpes, metadata, _ := processFingerprintResult(result)

	assert.Equal(t, "", tech)
	assert.Nil(t, cpes)
	assert.NotNil(t, metadata, "metadata must be accessible even with empty Technology")
	assert.Equal(t, "-1787112514", metadata["favicon_hash"])
}

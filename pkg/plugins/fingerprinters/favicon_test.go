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
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twmb/murmur3"
)

// hashString computes the signed 32-bit MurmurHash3 (seed 0) of s.
// Used in tests to cross-check faviconMMH3Hash without going through base64.
func hashString(s string) int32 {
	h := murmur3.SeedNew32(0)
	_, _ = h.Write([]byte(s))
	return int32(h.Sum32())
}

func TestFaviconMMH3Hash_KnownValues(t *testing.T) {
	tests := []struct {
		name         string
		input        []byte
		expectedHash int32
	}{
		{
			name:         "hello world",
			input:        []byte("hello world"),
			expectedHash: -1787112514,
		},
		{
			name:         "single byte 0xFF",
			input:        []byte{0xFF},
			expectedHash: 1903948049,
		},
		{
			name:         "three bytes",
			input:        []byte{0x00, 0x01, 0x02},
			expectedHash: 304933308,
		},
		{
			name:         "test favicon data",
			input:        []byte("test favicon data"),
			expectedHash: -1222974236,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := faviconMMH3Hash(tt.input)
			assert.Equal(t, tt.expectedHash, got)
		})
	}
}

// TestFaviconMMH3Hash_MIMEWrapping verifies that newlines are inserted every
// 76 base64 characters, matching Shodan's algorithm.
func TestFaviconMMH3Hash_MIMEWrapping(t *testing.T) {
	// 57 raw bytes encodes to exactly 76 base64 chars — no wrapping needed
	// beyond the trailing newline.
	input57 := bytes.Repeat([]byte{0xAB}, 57)
	b64 := base64.StdEncoding.EncodeToString(input57)
	require.Equal(t, 76, len(b64), "57 bytes should encode to exactly 76 b64 chars")

	expected57 := hashString(b64 + "\n")
	assert.Equal(t, expected57, faviconMMH3Hash(input57))

	// 58 raw bytes encodes to 80 base64 chars — wraps as 76+"\n"+4+"\n".
	input58 := bytes.Repeat([]byte{0xAB}, 58)
	b64long := base64.StdEncoding.EncodeToString(input58)
	require.Equal(t, 80, len(b64long))
	wrapped := b64long[:76] + "\n" + b64long[76:] + "\n"
	assert.Equal(t, hashString(wrapped), faviconMMH3Hash(input58))
}

func TestFaviconFingerprinter_Name(t *testing.T) {
	fp := &FaviconFingerprinter{}
	assert.Equal(t, "favicon", fp.Name())
}

func TestFaviconFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &FaviconFingerprinter{}
	assert.Equal(t, "/favicon.ico", fp.ProbeEndpoint())
}

func TestFaviconFingerprinter_ProbeAccept(t *testing.T) {
	fp := &FaviconFingerprinter{}
	assert.Equal(t, "*/*", fp.ProbeAccept())
}

func TestFaviconFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		expected   bool
	}{
		{"matches 200 OK", 200, true},
		{"does not match 404", 404, false},
		{"does not match 403", 403, false},
		{"does not match 302 redirect", 302, false},
		{"does not match 500", 500, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &FaviconFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: http.Header{}}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestFaviconFingerprinter_Fingerprint_EmptyBody(t *testing.T) {
	fp := &FaviconFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(nil)),
	}

	result, err := fp.Fingerprint(resp, []byte{})

	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestFaviconFingerprinter_Fingerprint_KnownHash(t *testing.T) {
	body := []byte("hello world")
	h := faviconMMH3Hash(body) // -1787112514

	// Temporarily register this hash so we can test the lookup path.
	// This test must NOT use t.Parallel() — it mutates the package-level faviconHashes map.
	const testTech = "test-known-tech"
	faviconHashes[h] = testTech
	defer delete(faviconHashes, h)

	fp := &FaviconFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, testTech, result.Technology)
	assert.Equal(t, fmt.Sprintf("%d", h), result.Metadata["favicon_hash"])
}

func TestFaviconFingerprinter_Fingerprint_UnknownHash(t *testing.T) {
	// "test favicon data" hashes to -1222974236, which is not in faviconHashes.
	body := []byte("test favicon data")
	h := faviconMMH3Hash(body)

	_, registered := faviconHashes[h]
	require.False(t, registered, "test precondition: hash must not be in faviconHashes")

	fp := &FaviconFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result, "should return a result even for unknown hashes")
	assert.Equal(t, "", result.Technology, "Technology must be empty for unknown hash")
	assert.Equal(t, fmt.Sprintf("%d", h), result.Metadata["favicon_hash"])
}

func TestFaviconFingerprinter_Fingerprint_MetadataHashFormat(t *testing.T) {
	// Verify favicon_hash is stored as a decimal string (not hex, not int).
	body := []byte{0xFF}
	h := faviconMMH3Hash(body) // 1903948049

	fp := &FaviconFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, fmt.Sprintf("%d", h), result.Metadata["favicon_hash"])
}

func TestFaviconFingerprinter_Integration(t *testing.T) {
	body := []byte("integration test body")
	h := faviconMMH3Hash(body)

	fp := &FaviconFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, fmt.Sprintf("%d", h), result.Metadata["favicon_hash"])
}

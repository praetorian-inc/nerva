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

// This file contains pure unit tests for the version-decode logic added to
// the oracledb plugin (LAB-5043). Unlike oracle_test.go (a dockertest
// integration test that spins up a real Oracle container), these tests
// exercise only the unexported helper functions in oracle.go and require no
// Docker, no network, and no external services.

package oracledb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDecodeVSNNUM verifies decodeVSNNUM against known-good VSNNUM bitfield
// vectors observed from real Oracle listeners, plus the documented zero case
// and a synthesized 23.x (23ai) vector.
func TestDecodeVSNNUM(t *testing.T) {
	tests := []struct {
		name string
		in   uint32
		want string
	}{
		{name: "19c", in: 318767104, want: "19.0.0.0.0"},
		{name: "12.1.0.2.0", in: 202375680, want: "12.1.0.2.0"},
		{name: "11.2.0.4.0", in: 186647552, want: "11.2.0.4.0"},
		{name: "21c", in: 352321536, want: "21.0.0.0.0"},
		{name: "zero returns empty string", in: 0, want: ""},
		{name: "23ai (23<<24)", in: 23 << 24, want: "23.0.0.0.0"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := decodeVSNNUM(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestExtractVSNNUM verifies extraction of the VSNNUM field from a raw TNS
// response byte slice, both when present and when absent.
func TestExtractVSNNUM(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		response := []byte("(DESCRIPTION=(TMP=)(VSNNUM=318767104)(ERR=1189)(ERROR_STACK=(ERROR=(CODE=1189)(EMFI=4))))")
		n, ok := extractVSNNUM(response)
		require.True(t, ok)
		assert.Equal(t, uint32(318767104), n)
	})

	t.Run("absent", func(t *testing.T) {
		response := []byte("(DESCRIPTION=(TMP=)(ERR=1189)(ERROR_STACK=(ERROR=(CODE=1189)(EMFI=4))))")
		n, ok := extractVSNNUM(response)
		assert.False(t, ok)
		assert.Equal(t, uint32(0), n)
	})
}

// TestExtractBannerVersion verifies extraction of a dotted version string
// from a listener banner, covering the primary "Version X.Y.Z..." pattern,
// the bare-dotted-version fallback pattern, and the absent case.
func TestExtractBannerVersion(t *testing.T) {
	t.Run("Version marker", func(t *testing.T) {
		response := []byte("TNSLSNR for Linux: Version 19.0.0.0.0 - Production")
		assert.Equal(t, "19.0.0.0.0", extractBannerVersion(response))
	})

	t.Run("bare dotted fallback", func(t *testing.T) {
		response := []byte("Oracle TNS Listener 11.2.0.x")
		assert.Equal(t, "11.2.0", extractBannerVersion(response))
	})

	t.Run("absent", func(t *testing.T) {
		response := []byte("no version information here")
		assert.Equal(t, "", extractBannerVersion(response))
	})
}

// TestMajorVersion verifies extraction of the leading integer component from
// a dotted version string, including empty and malformed inputs.
func TestMajorVersion(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
	}{
		{name: "23ai", in: "23.0.0.0.0", want: 23},
		{name: "19c", in: "19.0.0.0.0", want: 19},
		{name: "empty string", in: "", want: 0},
		{name: "garbage", in: "not-a-version", want: 0},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, majorVersion(tc.in))
		})
	}
}

// TestOracleCPE verifies CPE 2.3 string construction, both with a known
// version and with the wildcard fallback used when the version is unknown.
func TestOracleCPE(t *testing.T) {
	t.Run("versioned", func(t *testing.T) {
		assert.Equal(t, "cpe:2.3:a:oracle:database:19.0.0.0.0:*:*:*:*:*:*:*", oracleCPE("19.0.0.0.0"))
	})

	t.Run("wildcard when version unknown", func(t *testing.T) {
		assert.Equal(t, "cpe:2.3:a:oracle:database:*:*:*:*:*:*:*:*", oracleCPE(""))
	})
}

// TestLooksLikeOracleTNS verifies the additive TNS detection heuristic used
// for hardened 18c/19c+ listeners that suppress the classic VSNNUM refuse
// packet.
func TestLooksLikeOracleTNS(t *testing.T) {
	t.Run("TNS-looking response with DESCRIPTION marker", func(t *testing.T) {
		response := []byte("(DESCRIPTION=(TMP=)(VSNNUM=318767104)(ERR=1189)(ERROR_STACK=(ERROR=(CODE=1189)(EMFI=4))))")
		assert.True(t, looksLikeOracleTNS(response))
	})

	t.Run("refuse packet marker only", func(t *testing.T) {
		response := []byte("some prefix bytes ERROR_STACK trailing bytes")
		assert.True(t, looksLikeOracleTNS(response))
	})

	t.Run("unrelated bytes", func(t *testing.T) {
		response := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
		assert.False(t, looksLikeOracleTNS(response))
	})
}

// TestAICapableBoundary verifies the major-version boundary (>= 23) that
// Run() uses to set payload.AICapable / payload.Note. There is no separate
// pure helper for this decision (it is inlined as `majorVersion(version) >=
// 23` in oracle.go's Run method), so the boundary is exercised here via the
// same majorVersion() helper used at that call site.
func TestAICapableBoundary(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		wantAICap bool
	}{
		{name: "22.x is not AI capable", version: "22.0.0.0.0", wantAICap: false},
		{name: "23.x is AI capable", version: "23.0.0.0.0", wantAICap: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			gotAICap := majorVersion(tc.version) >= 23
			assert.Equal(t, tc.wantAICap, gotAICap)
		})
	}
}

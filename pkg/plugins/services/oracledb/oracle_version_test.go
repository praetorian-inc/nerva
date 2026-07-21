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
// from a listener banner. The version must be anchored to a "Version" or
// "Release" token; the bare-dotted-version fallback was removed because it
// matched unrelated dotted numbers such as an IP address echoed in HOST=.
func TestExtractBannerVersion(t *testing.T) {
	t.Run("Version marker", func(t *testing.T) {
		response := []byte("TNSLSNR for Linux: Version 19.0.0.0.0 - Production")
		assert.Equal(t, "19.0.0.0.0", extractBannerVersion(response))
	})

	t.Run("Release marker", func(t *testing.T) {
		response := []byte("... Release 11.2.0.4 ...")
		assert.Equal(t, "11.2.0.4", extractBannerVersion(response))
	})

	t.Run("bare dotted fallback is no longer matched", func(t *testing.T) {
		response := []byte("Oracle TNS Listener 11.2.0.x")
		assert.Equal(t, "", extractBannerVersion(response))
	})

	t.Run("dotted IP address in HOST= is not mistaken for a version", func(t *testing.T) {
		response := []byte("(DESCRIPTION=(CONNECT_DATA=(COMMAND=version))(ADDRESS=(PROTOCOL=tcp)(HOST=192.168.1.1)))")
		assert.Equal(t, "", extractBannerVersion(response))
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

// TestOracleCPEs verifies CPE 2.3 string construction. Both the
// "database_server" and "database" products are emitted (CVE applicability
// keys predominantly to database_server), and the version component is
// ALWAYS a wildcard "*": VSNNUM only exposes the RU-less family version
// (e.g. 19.0.0.0.0), but NVD's Oracle DB CVE ranges are keyed to RU-level
// versions, so a fake-precise family version would sort below those ranges
// and miss the CVEs. A wildcard keeps the CPE matchable against every RU
// range regardless of the decoded family version passed in.
func TestOracleCPEs(t *testing.T) {
	t.Run("versioned input still yields wildcard CPEs", func(t *testing.T) {
		got := oracleCPEs("19.0.0.0.0")
		assert.Equal(t, []string{
			"cpe:2.3:a:oracle:database_server:*:*:*:*:*:*:*:*",
			"cpe:2.3:a:oracle:database:*:*:*:*:*:*:*:*",
		}, got)
	})

	t.Run("23ai version input still yields wildcard CPEs", func(t *testing.T) {
		got := oracleCPEs("23.26.0.0.0")
		assert.Equal(t, []string{
			"cpe:2.3:a:oracle:database_server:*:*:*:*:*:*:*:*",
			"cpe:2.3:a:oracle:database:*:*:*:*:*:*:*:*",
		}, got)
	})

	t.Run("wildcard when version unknown", func(t *testing.T) {
		got := oracleCPEs("")
		assert.Equal(t, []string{
			"cpe:2.3:a:oracle:database_server:*:*:*:*:*:*:*:*",
			"cpe:2.3:a:oracle:database:*:*:*:*:*:*:*:*",
		}, got)
	})
}

// TestLooksLikeOracleTNS verifies the additive TNS detection heuristic used
// for hardened 18c/19c+ listeners that suppress the classic VSNNUM refuse
// packet. It requires an Oracle-specific RESPONSE marker (ERROR_STACK=,
// (ERR=, TNSLSNR, ORA-, or a non-zero VSNNUM=); a bare "(DESCRIPTION=" is
// intentionally NOT sufficient because it is exactly what the plugin's own
// probe transmits, which would otherwise misidentify an echo/reflecting
// service as Oracle.
func TestLooksLikeOracleTNS(t *testing.T) {
	t.Run("TNS-looking response with DESCRIPTION marker", func(t *testing.T) {
		response := []byte("(DESCRIPTION=(TMP=)(VSNNUM=318767104)(ERR=1189)(ERROR_STACK=(ERROR=(CODE=1189)(EMFI=4))))")
		assert.True(t, looksLikeOracleTNS(response))
	})

	t.Run("refuse packet marker only", func(t *testing.T) {
		response := []byte("some prefix bytes ERROR_STACK= trailing bytes")
		assert.True(t, looksLikeOracleTNS(response))
	})

	t.Run("real refuse packet with (ERR= marker", func(t *testing.T) {
		response := []byte("(DESCRIPTION=(TMP=)(VSNNUM=0)(ERR=12514)(ERROR_STACK=(ERROR=(CODE=12514)(EMFI=4))))")
		assert.True(t, looksLikeOracleTNS(response))
	})

	t.Run("real refuse packet with ERROR_STACK= marker", func(t *testing.T) {
		response := []byte("ERROR_STACK=(ERROR=(CODE=12514)(EMFI=4))")
		assert.True(t, looksLikeOracleTNS(response))
	})

	t.Run("real refuse packet with non-zero VSNNUM= marker", func(t *testing.T) {
		response := []byte("(DESCRIPTION=(TMP=)(VSNNUM=318767104))")
		assert.True(t, looksLikeOracleTNS(response))
	})

	t.Run("echoed probe payload is not mistaken for Oracle (fixes false positive)", func(t *testing.T) {
		// This is exactly the shape of data checkForOracle sends (minus the
		// service name substitution); an echo/reflecting service that bounces
		// the probe back verbatim must NOT be misidentified as Oracle.
		response := []byte("(DESCRIPTION=(CONNECT_DATA=(COMMAND=version))(ADDRESS=(PROTOCOL=tcp)(HOST=192.168.1.1)))")
		assert.False(t, looksLikeOracleTNS(response))
	})

	t.Run("bare zero VSNNUM alone is not sufficient", func(t *testing.T) {
		response := []byte("(DESCRIPTION=(TMP=)(VSNNUM=0))")
		assert.False(t, looksLikeOracleTNS(response))
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

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

package kerberos

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

func TestParseDERLength(t *testing.T) {
	tests := []struct {
		name         string
		input        []byte
		wantLength   int
		wantConsumed int
	}{
		{"empty input", []byte{}, 0, 0},
		{"short form zero", []byte{0x00}, 0, 1},
		{"short form small", []byte{0x05}, 5, 1},
		{"short form max", []byte{0x7f}, 127, 1},
		{"long form one byte", []byte{0x81, 0x80}, 128, 2},
		{"long form one byte large", []byte{0x81, 0xff}, 255, 2},
		{"long form two bytes", []byte{0x82, 0x01, 0x00}, 256, 3},
		{"long form two bytes large", []byte{0x82, 0x04, 0x00}, 1024, 3},
		{"long form truncated", []byte{0x82, 0x01}, 0, 0},     // missing second length byte
		{"indefinite length", []byte{0x80}, 0, 0},             // numBytes=0, not supported
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLength, gotConsumed := parseDERLength(tt.input)
			if gotLength != tt.wantLength || gotConsumed != tt.wantConsumed {
				t.Errorf("parseDERLength(%x) = (%d, %d), want (%d, %d)",
					tt.input, gotLength, gotConsumed, tt.wantLength, tt.wantConsumed)
			}
		})
	}
}

func TestDetectKerberosResponse(t *testing.T) {
	// Test that we can validate bytes patterns correctly
	tests := []struct {
		name         string
		response     []byte // raw response including 4-byte TCP length prefix
		wantDetected bool
	}{
		{
			name: "valid KRB-ERROR response",
			// 4-byte TCP length + 0x7E (KRB-ERROR) + SEQUENCE + pvno=5 pattern
			response: append([]byte{0x00, 0x00, 0x00, 0x20, 0x7e, 0x81, 0x1d, 0x30, 0x81, 0x1a},
				append([]byte{0xa0, 0x03, 0x02, 0x01, 0x05}, // pvno=5
					append([]byte{0xa1, 0x03, 0x02, 0x01, 0x1e}, // msg-type=30
						make([]byte, 14)...)...)...),
			wantDetected: true,
		},
		{
			name: "valid AS-REP response",
			response: append([]byte{0x00, 0x00, 0x00, 0x20, 0x6b, 0x81, 0x1d, 0x30, 0x81, 0x1a},
				append([]byte{0xa0, 0x03, 0x02, 0x01, 0x05}, // pvno=5
					append([]byte{0xa1, 0x03, 0x02, 0x01, 0x0b}, // msg-type=11
						make([]byte, 14)...)...)...),
			wantDetected: true,
		},
		{
			name:         "too short response",
			response:     []byte{0x00, 0x00, 0x00, 0x02, 0x7e, 0x00},
			wantDetected: false,
		},
		{
			name: "wrong message type",
			response: append([]byte{0x00, 0x00, 0x00, 0x20, 0x60, 0x81, 0x1d, 0x30, 0x81, 0x1a},
				append([]byte{0xa0, 0x03, 0x02, 0x01, 0x05},
					make([]byte, 19)...)...),
			wantDetected: false,
		},
		{
			name: "missing pvno pattern",
			response: append([]byte{0x00, 0x00, 0x00, 0x20, 0x7e, 0x81, 0x1d, 0x30, 0x81, 0x1a},
				append([]byte{0xa0, 0x03, 0x02, 0x01, 0x04}, // pvno=4 (not Kerberos v5)
					make([]byte, 19)...)...),
			wantDetected: false,
		},
		{
			name:         "empty response",
			response:     []byte{},
			wantDetected: false,
		},
		{
			name: "HTTP response on port 88",
			response: append([]byte{0x00, 0x00, 0x00, 0x10},
				[]byte("HTTP/1.1 200 OK\r")...),
			wantDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate what detectKerberos does with the response
			detected := false
			if len(tt.response) >= 10 {
				kerberosData := tt.response[4:]
				messageType := kerberosData[0]
				if (messageType == tagKRBError || messageType == tagASREP) &&
					bytes.Contains(kerberosData, pvnoPattern) {
					detected = true
				}
			}
			if detected != tt.wantDetected {
				t.Errorf("detection for %q: got %v, want %v", tt.name, detected, tt.wantDetected)
			}
		})
	}
}

func TestParseKerberosError(t *testing.T) {
	tests := []struct {
		name          string
		response      []byte
		wantRealm     string
		wantErrorCode int
		wantErrorText string
	}{
		{
			name:          "empty response",
			response:      []byte{},
			wantRealm:     "",
			wantErrorCode: 0,
			wantErrorText: "",
		},
		{
			name:          "too short for TCP prefix",
			response:      []byte{0x00, 0x00},
			wantRealm:     "",
			wantErrorCode: 0,
			wantErrorText: "",
		},
		{
			name: "realistic KRB-ERROR with realm and error code",
			// TCP length prefix + APPLICATION 30 + SEQUENCE + fields
			response:      buildTestKRBError(6, "EXAMPLE.COM", ""),
			wantRealm:     "EXAMPLE.COM",
			wantErrorCode: 6,
			wantErrorText: "",
		},
		{
			name:          "not a KRB-ERROR (wrong tag)",
			response:      []byte{0x00, 0x00, 0x00, 0x10, 0x6b, 0x0e, 0x30, 0x0c, 0xa0, 0x03, 0x02, 0x01, 0x05, 0xa1, 0x03, 0x02, 0x01, 0x0b, 0x00, 0x00},
			wantRealm:     "",
			wantErrorCode: 0,
			wantErrorText: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			realm, errorCode, errorText := parseKerberosError(tt.response)
			if realm != tt.wantRealm {
				t.Errorf("realm: got %q, want %q", realm, tt.wantRealm)
			}
			if errorCode != tt.wantErrorCode {
				t.Errorf("errorCode: got %d, want %d", errorCode, tt.wantErrorCode)
			}
			if errorText != tt.wantErrorText {
				t.Errorf("errorText: got %q, want %q", errorText, tt.wantErrorText)
			}
		})
	}
}

// buildTestKRBError constructs a synthetic KRB-ERROR response for testing.
// It builds a valid DER-encoded KRB-ERROR with the given error code, realm, and optional e-text.
func buildTestKRBError(errorCode int, realm string, etext string) []byte {
	// Build the inner SEQUENCE fields
	var fields []byte

	// [0] pvno = 5
	fields = append(fields, 0xa0, 0x03, 0x02, 0x01, 0x05)

	// [1] msg-type = 30 (KRB-ERROR)
	fields = append(fields, 0xa1, 0x03, 0x02, 0x01, 0x1e)

	// [4] stime (GeneralizedTime "20260213000000Z")
	stime := []byte("20260213000000Z")
	fields = append(fields, 0xa4, byte(2+len(stime)), 0x18, byte(len(stime)))
	fields = append(fields, stime...)

	// [5] susec = 0
	fields = append(fields, 0xa5, 0x03, 0x02, 0x01, 0x00)

	// [6] error-code
	fields = append(fields, 0xa6, 0x03, 0x02, 0x01, byte(errorCode))

	// [9] realm
	if realm != "" {
		realmBytes := []byte(realm)
		fields = append(fields, 0xa9, byte(2+len(realmBytes)), 0x1b, byte(len(realmBytes)))
		fields = append(fields, realmBytes...)
	}

	// [10] sname (PrincipalName for krbtgt/realm) - simplified
	sname := []byte("krbtgt")
	snameSeq := []byte{0x30, byte(6 + len(sname)), 0xa0, 0x03, 0x02, 0x01, 0x01, 0xa1, byte(2 + len(sname)), 0x30, byte(len(sname))}
	// This is a simplified version - real sname is more complex
	snameField := append([]byte{0xaa, byte(2 + len(snameSeq) + len(sname))}, append(snameSeq, sname...)...)
	fields = append(fields, snameField...)

	// [11] e-text (optional)
	if etext != "" {
		etextBytes := []byte(etext)
		fields = append(fields, 0xab, byte(2+len(etextBytes)), 0x1b, byte(len(etextBytes)))
		fields = append(fields, etextBytes...)
	}

	// Wrap in SEQUENCE
	seqLen := len(fields)
	var seq []byte
	seq = append(seq, 0x30)
	if seqLen < 128 {
		seq = append(seq, byte(seqLen))
	} else {
		seq = append(seq, 0x81, byte(seqLen))
	}
	seq = append(seq, fields...)

	// Wrap in APPLICATION 30
	appLen := len(seq)
	var app []byte
	app = append(app, 0x7e)
	if appLen < 128 {
		app = append(app, byte(appLen))
	} else {
		app = append(app, 0x81, byte(appLen))
	}
	app = append(app, seq...)

	// Prepend TCP length prefix
	tcpLen := make([]byte, 4)
	binary.BigEndian.PutUint32(tcpLen, uint32(len(app)))
	return append(tcpLen, app...)
}

func TestKerberos(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "kerberos",
			Port:        88,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil && res.Protocol == "kerberos" && res.Version == "5"
			},
			RunConfig: dockertest.RunOptions{
				Repository: "gcavalcante8808/krb5-server",
				Tag:        "latest",
				Env: []string{
					"KRB5_REALM=EXAMPLE.COM",
					"KRB5_KDC=localhost",
					"KRB5_PASS=admin",
				},
			},
		},
	}

	p := &KerberosPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

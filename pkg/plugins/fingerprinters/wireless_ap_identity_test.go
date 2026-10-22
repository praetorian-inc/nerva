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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wirelessAPIdentities are the Technology values ENG-9236 must not emit on
// generic HTTP (R2) and must emit on named product fixtures (R1).
var wirelessAPIdentities = []string{"aruba-instant", "cisco-wlc", "cisco-aironet", "ruckus"}

func TestWirelessAPFingerprinters_GenericHTTPDoesNotEmitIdentities(t *testing.T) {
	fps := []HTTPFingerprinter{
		&ArubaInstantFingerprinter{},
		&CiscoWLCFingerprinter{},
		&RuckusFingerprinter{},
	}
	fixtures := []struct {
		name    string
		headers map[string]string
		status  int
		body    string
	}{
		{
			name:    "generic HTML",
			headers: map[string]string{"Content-Type": "text/html"},
			status:  200,
			body:    `<html><head><title>Welcome</title></head><body>Hello World</body></html>`,
		},
		{
			name:    "Apache default page",
			headers: map[string]string{"Content-Type": "text/html"},
			status:  200,
			body:    `<html><head><title>Apache2 Ubuntu Default Page</title></head><body><h1>It works!</h1></body></html>`,
		},
		{
			name:    "empty body",
			headers: map[string]string{"Content-Type": "text/html"},
			status:  200,
			body:    "",
		},
		{
			name:    "plain text",
			headers: map[string]string{"Content-Type": "text/plain"},
			status:  200,
			body:    "OK",
		},
	}

	for _, fp := range fps {
		for _, fx := range fixtures {
			t.Run(fp.Name()+"/"+fx.name, func(t *testing.T) {
				resp := newHTMLHeadersResp(fx.status, fx.headers)
				result, err := fp.Fingerprint(resp, []byte(fx.body))
				require.NoError(t, err)
				assert.Nil(t, result)
				if result != nil {
					assert.NotContains(t, wirelessAPIdentities, result.Technology)
				}
			})
		}
	}
}

func TestWirelessAPFingerprinters_DoNotCrossEmit(t *testing.T) {
	html := map[string]string{"Content-Type": "text/html"}
	resp := newHTMLHeadersResp(200, html)

	instantBody := []byte(`<html><head><title>Aruba Instant</title></head><body><form action="/swarm.cgi"></form></body></html>`)
	wlcBody := []byte(`<html><head><title>Cisco Wireless LAN Controller</title></head><body><p>Cisco Systems</p></body></html>`)
	aironetBody := []byte(`<html><head><title>Cisco Aironet Access Point</title></head><body><p>Cisco Aironet</p></body></html>`)
	ruckusBody := []byte(`<html><head><title>Unleashed Login</title></head><body></body></html>`)

	tests := []struct {
		name string
		fp   HTTPFingerprinter
		body []byte
	}{
		{"cisco-wlc does not emit Instant identity", &CiscoWLCFingerprinter{}, instantBody},
		{"ruckus does not emit Instant identity", &RuckusFingerprinter{}, instantBody},
		{"aruba-instant does not emit WLC identity", &ArubaInstantFingerprinter{}, wlcBody},
		{"ruckus does not emit WLC identity", &RuckusFingerprinter{}, wlcBody},
		{"aruba-instant does not emit Aironet identity", &ArubaInstantFingerprinter{}, aironetBody},
		{"ruckus does not emit Aironet identity", &RuckusFingerprinter{}, aironetBody},
		{"aruba-instant does not emit Ruckus identity", &ArubaInstantFingerprinter{}, ruckusBody},
		{"cisco-wlc does not emit Ruckus identity", &CiscoWLCFingerprinter{}, ruckusBody},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.fp.Fingerprint(resp, tt.body)
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

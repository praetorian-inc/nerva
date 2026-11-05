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
)

func TestCUPSFingerprint(t *testing.T) {
	fp := &CUPSFingerprinter{}
	if fp.Name() != "cups" {
		t.Fatalf("name = %q", fp.Name())
	}
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Server": []string{"CUPS/2.4.18 IPP/2.1"}}}
	if !fp.Match(resp) {
		t.Fatal("expected match")
	}
	got, err := fp.Fingerprint(resp, []byte(`<title>Administration - CUPS 2.4.18</title>`))
	if err != nil || got == nil || got.Technology != "cups" || got.Version != "2.4.18" {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	if len(got.CPEs) != 1 || got.CPEs[0] != "cpe:2.3:a:openprinting:cups:2.4.18:*:*:*:*:*:*:*" {
		t.Fatalf("cpes = %v", got.CPEs)
	}
	miss := &http.Response{StatusCode: 200, Header: http.Header{"Server": []string{"Apache"}}}
	if fp.Match(miss) {
		t.Fatal("apache matched as CUPS")
	}
	bodyOnly, err := fp.Fingerprint(miss, []byte("how to install CUPS"))
	if err != nil || bodyOnly != nil {
		t.Fatalf("body mention fingerprinted: %+v %v", bodyOnly, err)
	}
}

func TestCUPSFingerprint_ServerTokens(t *testing.T) {
	fp := &CUPSFingerprinter{}
	tests := []struct {
		name      string
		server    string
		wantMatch bool
		wantVer   string
		wantCPE   string
	}{
		{"default minimal tokens", "CUPS/2.4 IPP/2.1", true, "2.4", "cpe:2.3:a:openprinting:cups:2.4:*:*:*:*:*:*:*"},
		{"full version", "CUPS/2.4.18 IPP/2.1", true, "2.4.18", "cpe:2.3:a:openprinting:cups:2.4.18:*:*:*:*:*:*:*"},
		{"major only", "CUPS/2 IPP/2", true, "2", "cpe:2.3:a:openprinting:cups:2:*:*:*:*:*:*:*"},
		{"product only, no version", "CUPS IPP/2.1", true, "", "cpe:2.3:a:openprinting:cups:*:*:*:*:*:*:*:*"},
		{"not cups prefix", "NotCUPS/2.4", false, "", ""},
		{"cups-proxy is not cups", "CUPS-Proxy/1.0", false, "", ""},
		{"apache", "Apache/2.4", false, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: 200, Header: http.Header{"Server": []string{tt.server}}}
			if got := fp.Match(resp); got != tt.wantMatch {
				t.Fatalf("Match=%v want %v", got, tt.wantMatch)
			}
			got, err := fp.Fingerprint(resp, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !tt.wantMatch {
				if got != nil {
					t.Fatalf("expected no fingerprint, got %+v", got)
				}
				return
			}
			if got == nil || got.Version != tt.wantVer {
				t.Fatalf("version=%+v want %q", got, tt.wantVer)
			}
			if len(got.CPEs) != 1 || got.CPEs[0] != tt.wantCPE {
				t.Fatalf("cpe=%v want %v", got.CPEs, tt.wantCPE)
			}
		})
	}
}

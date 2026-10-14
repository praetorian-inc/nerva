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

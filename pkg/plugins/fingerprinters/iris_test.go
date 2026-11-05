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

func TestIRISFingerprint(t *testing.T) {
	fp := &IRISFingerprinter{}
	if fp.Name() != "intersystems-iris" || fp.ProbeEndpoint() != "/csp/sys/UtilHome.csp" {
		t.Fatalf("name=%s probe=%s", fp.Name(), fp.ProbeEndpoint())
	}
	body := []byte(`<title>Login IRIS</title><link rel="icon" href="portal/ISC_IRIS_icon.ico"><input name="IRISUsername">`)
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	got, err := fp.Fingerprint(resp, body)
	if err != nil || got == nil || got.Technology != "intersystems-iris" {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	miss, err := fp.Fingerprint(resp, []byte(`<title>Login</title><input name="username">`))
	if err != nil || miss != nil {
		t.Fatalf("unrelated page fingerprinted: %+v %v", miss, err)
	}
}

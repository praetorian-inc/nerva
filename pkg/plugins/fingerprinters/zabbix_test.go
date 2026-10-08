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

func TestZabbixFingerprint(t *testing.T) {
	fp := &ZabbixFingerprinter{}
	if fp.Name() != "zabbix" || fp.ProbeEndpoint() != "/index.php" {
		t.Fatalf("name=%s probe=%s", fp.Name(), fp.ProbeEndpoint())
	}
	body := []byte(`<title>Zabbix docker: Zabbix</title><meta name="Author" content="Zabbix SIA"><form action="index.php"><input name="name"><input name="password"></form>`)
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	got, err := fp.Fingerprint(resp, body)
	if err != nil || got == nil || got.Technology != "zabbix" {
		t.Fatalf("result=%+v err=%v", got, err)
	}
	miss, err := fp.Fingerprint(resp, []byte(`<title>Docs</title><p>How to install Zabbix</p>`))
	if err != nil || miss != nil {
		t.Fatalf("mention fingerprinted: %+v %v", miss, err)
	}
}

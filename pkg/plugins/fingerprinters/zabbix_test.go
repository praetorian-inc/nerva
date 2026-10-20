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

func TestZabbixPage(t *testing.T) {
	fp := &ZabbixFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "title and form, no author marker",
			body: `<html><head><title>Production - Zabbix</title></head><body><form><input name="name"><input name="password"></form></body></html>`,
			want: true,
		},
		{
			name: "author marker and form, no zabbix title",
			body: `<html><head><title>Login</title><meta name="Author" content="Zabbix SIA"></head><body><form><input name="name"><input name="password"></form></body></html>`,
			want: true,
		},
		{
			name: "zabbix sia in prose without form does not match",
			body: `<html><head><title>News</title></head><body><footer>&copy; 2001-2024 Zabbix SIA</footer></body></html>`,
			want: false,
		},
		{
			name: "zabbix title without the sign-in form does not match",
			body: `<html><head><title>Zabbix docs</title></head><body>installation guide</body></html>`,
			want: false,
		},
		{
			name: "zabbix title with input names in prose but no form tag does not match",
			body: `<html><head><title>Zabbix API docs</title></head><body><code>name="name" name="password"</code></body></html>`,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			if (got != nil) != tt.want {
				t.Fatalf("Fingerprint match=%v want %v (result=%+v)", got != nil, tt.want, got)
			}
		})
	}
}

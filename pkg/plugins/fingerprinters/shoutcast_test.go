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

func TestShoutcastMatch(t *testing.T) {
	fp := &ShoutcastFingerprinter{}
	if fp.Name() != "shoutcast" {
		t.Fatalf("name = %q", fp.Name())
	}
	if fp.ProbeEndpoint() != "/admin.cgi" {
		t.Fatalf("probe = %q", fp.ProbeEndpoint())
	}
	tests := []struct {
		name   string
		status int
		header http.Header
		want   bool
	}{
		{
			name:   "admin challenge",
			status: 401,
			header: http.Header{
				"Server":           []string{"Shoutcast DNAS"},
				"Www-Authenticate": []string{`Basic realm="Shoutcast Server"`},
			},
			want: true,
		},
		{
			name:   "listener banner",
			status: 401,
			header: http.Header{
				"Icy-Notice1": []string{"<BR>Shoutcast DNAS/posix(linux x64) v2.6.1.777<BR>"},
			},
			want: true,
		},
		{
			name:   "nginx mentioning shoutcast",
			status: 200,
			header: http.Header{"Server": []string{"nginx"}},
			want:   false,
		},
		{
			name:   "prefixed server token",
			status: 200,
			header: http.Header{"Server": []string{"NotShoutcast DNAS"}},
			want:   false,
		},
		{
			name:   "server error",
			status: 500,
			header: http.Header{"Server": []string{"Shoutcast DNAS"}},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: tt.status, Header: tt.header}
			if got := fp.Match(resp); got != tt.want {
				t.Fatalf("Match = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShoutcastFingerprint(t *testing.T) {
	fp := &ShoutcastFingerprinter{}
	resp := &http.Response{
		StatusCode: 401,
		Header: http.Header{
			"Server":      []string{"Shoutcast DNAS"},
			"Icy-Notice1": []string{"<BR>Shoutcast DNAS/posix(linux x64) v2.6.1.777<BR>"},
		},
	}
	got, err := fp.Fingerprint(resp, []byte(`<title>Shoutcast Administrator</title>`))
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Technology != "shoutcast" || got.Version != "2.6.1.777" {
		t.Fatalf("result = %+v", got)
	}
	wantCPE := "cpe:2.3:a:shoutcast:dnas:2.6.1.777:*:*:*:*:*:*:*"
	if len(got.CPEs) != 1 || got.CPEs[0] != wantCPE {
		t.Fatalf("cpes = %v", got.CPEs)
	}

	miss, err := fp.Fingerprint(&http.Response{
		StatusCode: 200,
		Header:     http.Header{"Server": []string{"nginx"}},
	}, []byte("how to install shoutcast"))
	if err != nil {
		t.Fatal(err)
	}
	if miss != nil {
		t.Fatalf("unrelated page fingerprinted: %+v", miss)
	}
}

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

func TestAppwebFingerprinter_Name(t *testing.T) {
	fp := &AppwebFingerprinter{}
	if got := fp.Name(); got != "appweb" {
		t.Errorf("Name() = %q, want %q", got, "appweb")
	}
}

func TestAppwebFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		statusCode int
		want       bool
	}{
		{
			name:       "Server: Embedthis-Appweb/4.1.0 returns true",
			server:     "Embedthis-Appweb/4.1.0",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: Mbedthis-Appweb/2.4.2 returns true",
			server:     "Mbedthis-Appweb/2.4.2",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: Appweb/7.0.1 returns true",
			server:     "Appweb/7.0.1",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: Appweb (bare, no version) returns true",
			server:     "Appweb",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: embedthis-appweb/8.2.1 (lowercase) returns true",
			server:     "embedthis-appweb/8.2.1",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: EMBEDTHIS-APPWEB/4.1.0 (uppercase) returns true",
			server:     "EMBEDTHIS-APPWEB/4.1.0",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: Apache/2.4.41 returns false",
			server:     "Apache/2.4.41",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "Server: Embedthis-http returns false (v5+ out of scope)",
			server:     "Embedthis-http",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "Empty Server header returns false",
			server:     "",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "Status 500 returns false (even with Appweb header)",
			server:     "Embedthis-Appweb/4.1.0",
			statusCode: 500,
			want:       false,
		},
		{
			name:       "Status 503 returns false",
			server:     "Appweb",
			statusCode: 503,
			want:       false,
		},
		{
			name:       "Status 404 returns true (client error accepted)",
			server:     "Embedthis-Appweb/4.1.0",
			statusCode: 404,
			want:       true,
		},
		{
			name:       "Status 401 returns true (auth required accepted)",
			server:     "Appweb/7.0.1",
			statusCode: 401,
			want:       true,
		},
		{
			name:       "Server: GoAhead-http returns false",
			server:     "GoAhead-http",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "Server: nginx returns false",
			server:     "nginx/1.18.0",
			statusCode: 200,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &AppwebFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

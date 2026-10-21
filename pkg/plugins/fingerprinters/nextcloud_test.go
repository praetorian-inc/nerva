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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const nextcloudStatusJSON = `{"installed":true,"maintenance":false,"needsDbUpgrade":false,"version":"28.0.4.1","versionstring":"28.0.4","edition":"","productname":"Nextcloud","extendedSupport":false}`

const owncloudStatusJSON = `{"installed":true,"maintenance":false,"version":"10.13.0.1","versionstring":"10.13.0","edition":"Community","productname":"ownCloud"}`

func newStatusResp(status int, ct, body string) *http.Response {
	h := make(http.Header)
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	return &http.Response{StatusCode: status, Header: h}
}

func TestNextcloudFingerprinter_NameAndProbe(t *testing.T) {
	fp := &NextcloudFingerprinter{}
	assert.Equal(t, "nextcloud", fp.Name())
	assert.Equal(t, "/status.php", fp.ProbeEndpoint())
	assert.Equal(t, "application/json", fp.ProbeAccept())
}

func TestNextcloudFingerprinter_Match(t *testing.T) {
	fp := &NextcloudFingerprinter{}
	assert.True(t, fp.Match(newStatusResp(200, "application/json", "")))
	assert.True(t, fp.Match(newStatusResp(200, "application/json; charset=utf-8", "")))
	assert.True(t, fp.Match(newStatusResp(200, "", "")))
	assert.False(t, fp.Match(newStatusResp(404, "application/json", "")))
	assert.False(t, fp.Match(newStatusResp(200, "text/html", "")))
	assert.False(t, fp.Match(nil))
}

func TestNextcloudFingerprinter_Fingerprint_Nextcloud(t *testing.T) {
	fp := &NextcloudFingerprinter{}
	resp := newStatusResp(200, "application/json", nextcloudStatusJSON)
	got, err := fp.Fingerprint(resp, []byte(nextcloudStatusJSON))
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "nextcloud", got.Technology)
	assert.Equal(t, "28.0.4", got.Version)
	assert.Equal(t, "cpe:2.3:a:nextcloud:nextcloud:28.0.4:*:*:*:*:*:*:*", got.CPEs[0])
	assert.Equal(t, "Nextcloud", got.Metadata["vendor"])
	assert.Equal(t, "nextcloud", got.Metadata["product"])
	assert.Equal(t, true, got.Metadata["installed"])
	assert.Equal(t, "28.0.4.1", got.Metadata["version"])
	assert.Empty(t, got.SecurityFindings)
}

func TestNextcloudFingerprinter_Fingerprint_OwnCloud(t *testing.T) {
	fp := &NextcloudFingerprinter{}
	resp := newStatusResp(200, "application/json", owncloudStatusJSON)
	got, err := fp.Fingerprint(resp, []byte(owncloudStatusJSON))
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "owncloud", got.Technology)
	assert.Equal(t, "10.13.0", got.Version)
	assert.Equal(t, "cpe:2.3:a:owncloud:owncloud:10.13.0:*:*:*:*:*:*:*", got.CPEs[0])
	assert.Equal(t, "ownCloud", got.Metadata["vendor"])
	assert.Equal(t, "Community", got.Metadata["edition"])
}

func TestNextcloudFingerprinter_Fingerprint_Rejects(t *testing.T) {
	fp := &NextcloudFingerprinter{}
	resp := newStatusResp(200, "application/json", "")
	tests := []struct {
		name string
		body string
	}{
		{name: "invalid json", body: `not json`},
		{name: "empty product", body: `{"installed":true,"version":"28.0.4","productname":""}`},
		{name: "unrelated product", body: `{"installed":true,"version":"1.0.0","productname":"Widget"}`},
		{name: "generic installed flag", body: `{"installed":true,"version":"1.2.3"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, got)
		})
	}
}

func TestSanitizeNextcloudVersion(t *testing.T) {
	assert.Equal(t, "28.0.4", sanitizeNextcloudVersion("28.0.4"))
	assert.Equal(t, "28.0.4.1", sanitizeNextcloudVersion("28.0.4.1"))
	assert.Equal(t, "", sanitizeNextcloudVersion("28.0.4:*"))
	assert.Equal(t, "", sanitizeNextcloudVersion("not-a-version"))
	assert.Equal(t, "", sanitizeNextcloudVersion(""))
}

func TestBuildNextcloudCPE(t *testing.T) {
	assert.Equal(t, "cpe:2.3:a:nextcloud:nextcloud:28.0.4:*:*:*:*:*:*:*", buildNextcloudCPE("nextcloud", "28.0.4"))
	assert.Equal(t, "cpe:2.3:a:owncloud:owncloud:*:*:*:*:*:*:*:*", buildNextcloudCPE("owncloud", ""))
}

func TestNextcloudFingerprinter_RegisteredProbe(t *testing.T) {
	assert.Equal(t, "/status.php", GetProbeEndpoints()["nextcloud"])
}

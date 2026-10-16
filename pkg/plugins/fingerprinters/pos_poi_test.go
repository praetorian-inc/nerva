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

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Recorded/fixture Verifone Commander management-plane HTML (ENG-9060 AC3).
const verifoneCommanderFixture = `<!DOCTYPE html>
<html><head><title>VeriFone Commander</title></head>
<body>
<h1>VeriFone Commander Site Controller</h1>
<p>Copyright VeriFone Systems, Inc.</p>
</body></html>`

// Recorded/fixture Ingenico Telium terminal-management HTML (ENG-9060 AC3).
const ingenicoTeliumFixture = `<!DOCTYPE html>
<html><head><title>Ingenico Telium</title></head>
<body>
<form method="post" action="/login">
<label>Username</label><input name="user">
<label>Password</label><input type="password" name="password">
</form>
</body></html>`

const genericApacheFixture = `<!DOCTYPE html>
<html><head><title>Apache2 Ubuntu Default Page</title></head>
<body><h1>It works!</h1></body></html>`

func htmlResp(status int, body string) *http.Response {
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	return &http.Response{StatusCode: status, Header: h}
}

func TestVerifoneFingerprinter_Name(t *testing.T) {
	assert.Equal(t, "verifone", (&VerifoneFingerprinter{}).Name())
}

func TestIngenicoFingerprinter_Name(t *testing.T) {
	assert.Equal(t, "ingenico", (&IngenicoFingerprinter{}).Name())
}

func TestVerifoneFingerprinter_Match(t *testing.T) {
	fp := &VerifoneFingerprinter{}
	assert.True(t, fp.Match(htmlResp(200, "")))
	assert.False(t, fp.Match(htmlResp(401, "")))
	assert.False(t, fp.Match(htmlResp(404, "")))
	assert.False(t, fp.Match(&http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}}))
	assert.False(t, fp.Match(&http.Response{StatusCode: 500, Header: http.Header{"Content-Type": []string{"text/html"}}}))
}

func TestIngenicoFingerprinter_Match(t *testing.T) {
	fp := &IngenicoFingerprinter{}
	assert.True(t, fp.Match(htmlResp(200, "")))
	assert.False(t, fp.Match(&http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}}))
}

func TestVerifoneFingerprinter_FixtureIdentifiesAndEmits(t *testing.T) {
	fp := &VerifoneFingerprinter{}
	resp := htmlResp(200, verifoneCommanderFixture)
	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, []byte(verifoneCommanderFixture))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "verifone", result.Technology)
	require.NotEmpty(t, result.CPEs)
	assert.Contains(t, result.CPEs[0], "verifone")
	require.Len(t, result.SecurityFindings, 1)
	assert.Equal(t, posPOIManagementFindingID, result.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityMedium, result.SecurityFindings[0].Severity)
}

func TestIngenicoFingerprinter_FixtureIdentifiesAndEmits(t *testing.T) {
	fp := &IngenicoFingerprinter{}
	resp := htmlResp(200, ingenicoTeliumFixture)
	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, []byte(ingenicoTeliumFixture))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "ingenico", result.Technology)
	require.NotEmpty(t, result.CPEs)
	assert.Contains(t, result.CPEs[0], "ingenico")
	require.Len(t, result.SecurityFindings, 1)
	assert.Equal(t, posPOIManagementFindingID, result.SecurityFindings[0].ID)
}

func TestPOSPOI_GenericHTTPDoesNotEmit(t *testing.T) {
	resp := htmlResp(200, genericApacheFixture)
	nginx := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Server": []string{"nginx"}, "Content-Type": []string{"text/html"}},
	}

	v, err := (&VerifoneFingerprinter{}).Fingerprint(resp, []byte(genericApacheFixture))
	require.NoError(t, err)
	assert.Nil(t, v)

	i, err := (&IngenicoFingerprinter{}).Fingerprint(resp, []byte(genericApacheFixture))
	require.NoError(t, err)
	assert.Nil(t, i)

	v2, err := (&VerifoneFingerprinter{}).Fingerprint(nginx, []byte("welcome"))
	require.NoError(t, err)
	assert.Nil(t, v2)

	i2, err := (&IngenicoFingerprinter{}).Fingerprint(nginx, []byte("welcome"))
	require.NoError(t, err)
	assert.Nil(t, i2)
}

func TestPOSPOI_MarketingPageWithoutManagementMarkersDoesNotMatch(t *testing.T) {
	copyrightOnly := []byte(`<html><head><title>Verifone Home</title></head><body><p>Copyright VeriFone Systems, Inc.</p></body></html>`)
	v, err := (&VerifoneFingerprinter{}).Fingerprint(htmlResp(200, string(copyrightOnly)), copyrightOnly)
	require.NoError(t, err)
	assert.Nil(t, v)

	datasheet := []byte(`<html><head><title>Buy Ingenico Telium iCT220</title></head><body><p>Ingenico Telium iCT220 datasheet</p></body></html>`)
	i, err := (&IngenicoFingerprinter{}).Fingerprint(htmlResp(200, string(datasheet)), datasheet)
	require.NoError(t, err)
	assert.Nil(t, i)
}

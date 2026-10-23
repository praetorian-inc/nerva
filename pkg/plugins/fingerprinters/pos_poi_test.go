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

// Live vhq.connect.verifone.com/VHQ.Authentication.VHQFederationV1/Account/Login
const verifoneVHQFixture = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>VHQ</title>
</head>
<body>
    <div class="version-text">Version 3.30.02.27</div>
    <form method="post" action="Account/Login" id="formTest">
        <span id="loginFailedMsg">Invalid user name or password</span>
        <input type="text" name="username" id="txtloginname" autocomplete="off">
        <input type="password" name="password" id="txtpassword" autocomplete="off">
        <button type="submit" id="Btnsubmit">Login</button>
    </form>
    <div class="login-footer">
        Copyright &copy; 2026, Verifone Systems, Inc.
        <img src="/VHQ.Authentication.VHQFederationV1/Content/images/verifone-b.png" alt="">
    </div>
</body>
</html>`

// Live mcmemuat.roamdata.com/emgui/resetPassword.jsp
const ingenicoEstateFixture = `<!DOCTYPE html>
<html class="login-page">
<head>
    <meta charset="utf-8">
    <title>Ingenico Estate Management</title>
</head>
<body>
<div class="login-holder">
    <h1>Welcome to <span> The Estate Manager</span></h1>
    <form action="/emgui/login.jsp" method="post" class="form-login-user">
        <label for="login">Login</label>
        <input type="text" id="userName" name="userName">
        <button type="submit">Reset</button>
    </form>
    <img alt="Ingenico Group" src="/emgui/resources/common/img_content/ingenico-group-logo.png">
    <div class="mentions">Copyright 2021</div>
</div>
</body>
</html>`

// Live tmsweb.services.ingenico.co.uk/extranet/login.sm
const ingenicoTMSFixture = `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
  <title>TMS Web Access- Login</title>
</head>
<body>
<form name="fmLogin" method="POST" action="j_spring_security_check" autocomplete="off">
  <table>
    <tr><td>Web Site : <a href="http://www.ingenico.com">www.ingenico.com</a></td></tr>
    <tr><td>Please sign in to access the TMS</td></tr>
    <tr><td>User Name <input type="text" name="j_username" value=""></td></tr>
    <tr><td>Password <input type="password" name="j_password" value=""></td></tr>
    <tr><td><button type="submit" id="j_submit">Log In</button></td></tr>
  </table>
</form>
</body>
</html>`

const genericApacheFixture = `<!DOCTYPE html>
<html><head><title>Apache2 Ubuntu Default Page</title></head>
<body><h1>It works!</h1></body></html>`

const genericLoginFixture = `<!DOCTYPE html>
<html><head><title>Login</title></head>
<body>
<form method="post" action="/login">
<label>Username</label><input name="user">
<label>Password</label><input type="password" name="password">
</form>
</body></html>`

const verifoneMarketingFixture = `<!DOCTYPE html>
<html>
<head><title>Verifone | Payment Devices</title></head>
<body>
  <h1>Verifone payment terminals</h1>
  <p>The Verifone MX 915 and Commander site controller help retailers take payments.</p>
  <p>Contact sales to learn about Configuration Client training.</p>
</body>
</html>`

const ingenicoMarketingFixture = `<!DOCTYPE html>
<html>
<head><title>Ingenico | Payment Terminals</title></head>
<body>
  <h1>Ingenico payment terminals</h1>
  <p>Manage estates with The Estate Manager. This page is marketing, not the console.</p>
</body>
</html>`

func posPoiHTMLResp(status int) *http.Response {
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	return &http.Response{StatusCode: status, Header: h}
}

func headerResp(status int, headers http.Header) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: headers}
}

func TestVerifoneFingerprinter_Name(t *testing.T) {
	assert.Equal(t, "verifone", (&VerifoneFingerprinter{}).Name())
}

func TestIngenicoFingerprinter_Name(t *testing.T) {
	assert.Equal(t, "ingenico", (&IngenicoFingerprinter{}).Name())
}

func TestVerifoneFingerprinter_ProbeEndpoint(t *testing.T) {
	assert.Equal(t, "/VHQ.Authentication.VHQFederationV1/Account/Login", (&VerifoneFingerprinter{}).ProbeEndpoint())
	assert.Equal(t, "text/html", (&VerifoneFingerprinter{}).ProbeAccept())
}

func TestIngenicoFingerprinter_ProbeEndpoint(t *testing.T) {
	assert.Equal(t, "/emgui/resetPassword.jsp", (&IngenicoFingerprinter{}).ProbeEndpoint())
	assert.Equal(t, "text/html", (&IngenicoFingerprinter{}).ProbeAccept())
}

func TestIngenicoTMSFingerprinter_ProbeEndpoint(t *testing.T) {
	assert.Equal(t, "/extranet/login.sm", (&IngenicoTMSFingerprinter{}).ProbeEndpoint())
	assert.Equal(t, "text/html", (&IngenicoTMSFingerprinter{}).ProbeAccept())
}

func TestVerifoneFingerprinter_Match(t *testing.T) {
	fp := &VerifoneFingerprinter{}
	assert.True(t, fp.Match(posPoiHTMLResp(200)))
	assert.True(t, fp.Match(posPoiHTMLResp(302)))
	assert.False(t, fp.Match(posPoiHTMLResp(401)))
	assert.False(t, fp.Match(posPoiHTMLResp(404)))
	assert.False(t, fp.Match(&http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}}))
	assert.False(t, fp.Match(&http.Response{StatusCode: 500, Header: http.Header{"Content-Type": []string{"text/html"}}}))
	assert.False(t, fp.Match(headerResp(302, http.Header{"Location": []string{"/VHQ.Authentication.VHQFederationV1/Account/Login"}})))
}

func TestIngenicoFingerprinter_Match(t *testing.T) {
	fp := &IngenicoFingerprinter{}
	assert.True(t, fp.Match(posPoiHTMLResp(200)))
	assert.False(t, fp.Match(&http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}}))
	assert.False(t, fp.Match(headerResp(302, http.Header{"Location": []string{"/emgui/resetPassword.jsp"}})))
}

func TestVerifoneFingerprinter_LiveVHQIdentifiesAndEmits(t *testing.T) {
	fp := &VerifoneFingerprinter{}
	resp := posPoiHTMLResp(200)
	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, []byte(verifoneVHQFixture))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "verifone", result.Technology)
	assert.Equal(t, "VHQ", result.Metadata["product"])
	require.NotEmpty(t, result.CPEs)
	assert.Contains(t, result.CPEs[0], "vhq")
	require.Len(t, result.SecurityFindings, 1)
	assert.Equal(t, posPOIManagementFindingID, result.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityMedium, result.SecurityFindings[0].Severity)
}

func TestIngenicoFingerprinter_LiveEstateIdentifiesAndEmits(t *testing.T) {
	fp := &IngenicoFingerprinter{}
	resp := posPoiHTMLResp(200)
	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, []byte(ingenicoEstateFixture))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "ingenico", result.Technology)
	assert.Equal(t, "Estate Manager", result.Metadata["product"])
	require.NotEmpty(t, result.CPEs)
	assert.Contains(t, result.CPEs, ingenicoEstateCPE)
	assert.Contains(t, result.CPEs, ingenicoEstateCPEAlias)
	require.Len(t, result.SecurityFindings, 1)
	assert.Equal(t, posPOIManagementFindingID, result.SecurityFindings[0].ID)
}

func TestIngenicoFingerprinter_LiveTMSIdentifiesAndEmits(t *testing.T) {
	fp := &IngenicoTMSFingerprinter{}
	result, err := fp.Fingerprint(posPoiHTMLResp(200), []byte(ingenicoTMSFixture))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "ingenico-tms", result.Technology)
	assert.Equal(t, "TMS", result.Metadata["product"])
	assert.Contains(t, result.CPEs[0], ":tms:")
	assert.Equal(t, posPOIManagementFindingID, result.SecurityFindings[0].ID)
}

func TestPOSPOI_IngenicoFingerprintersDoNotCrossMatch(t *testing.T) {
	estate := posPoiHTMLResp(200)
	tms := posPoiHTMLResp(200)

	estateOnTMS, err := (&IngenicoTMSFingerprinter{}).Fingerprint(estate, []byte(ingenicoEstateFixture))
	require.NoError(t, err)
	assert.Nil(t, estateOnTMS)

	tmsOnEstate, err := (&IngenicoFingerprinter{}).Fingerprint(tms, []byte(ingenicoTMSFixture))
	require.NoError(t, err)
	assert.Nil(t, tmsOnEstate)
}

func TestPOSPOI_GenericHTTPDoesNotEmit(t *testing.T) {
	resp := posPoiHTMLResp(200)
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
	titleOnly := []byte(`<html><head><title>VHQ</title></head><body><p>Copyright Verifone Systems, Inc.</p></body></html>`)
	v, err := (&VerifoneFingerprinter{}).Fingerprint(posPoiHTMLResp(200), titleOnly)
	require.NoError(t, err)
	assert.Nil(t, v)

	datasheet := []byte(`<html><head><title>Buy Ingenico Telium iCT220</title></head><body><p>Ingenico Telium iCT220 datasheet</p></body></html>`)
	i, err := (&IngenicoFingerprinter{}).Fingerprint(posPoiHTMLResp(200), datasheet)
	require.NoError(t, err)
	assert.Nil(t, i)

	vm, err := (&VerifoneFingerprinter{}).Fingerprint(posPoiHTMLResp(200), []byte(verifoneMarketingFixture))
	require.NoError(t, err)
	assert.Nil(t, vm)

	im, err := (&IngenicoFingerprinter{}).Fingerprint(posPoiHTMLResp(200), []byte(ingenicoMarketingFixture))
	require.NoError(t, err)
	assert.Nil(t, im)
}

func TestPOSPOI_UnverifiedStringsDoNotEmit(t *testing.T) {
	commander := []byte(`<html><head><title>VeriFone Commander</title></head><body><form><input type="password" name="password"></form></body></html>`)
	v, err := (&VerifoneFingerprinter{}).Fingerprint(posPoiHTMLResp(200), commander)
	require.NoError(t, err)
	assert.Nil(t, v)

	configClient := []byte(`<html><head><title>Configuration Client</title></head><body><h1>Verifone Commander</h1><form><input type="password"></form></body></html>`)
	v2, err := (&VerifoneFingerprinter{}).Fingerprint(posPoiHTMLResp(200), configClient)
	require.NoError(t, err)
	assert.Nil(t, v2)

	telium := []byte(`<html><head><title>Ingenico Telium</title></head><body><form><input type="password" name="password"></form></body></html>`)
	i, err := (&IngenicoFingerprinter{}).Fingerprint(posPoiHTMLResp(200), telium)
	require.NoError(t, err)
	assert.Nil(t, i)

	estateExactTitle := []byte(`<html><head><title>The Estate Manager</title></head><body><p>Ingenico</p><form><input type="password"></form></body></html>`)
	i2, err := (&IngenicoFingerprinter{}).Fingerprint(posPoiHTMLResp(200), estateExactTitle)
	require.NoError(t, err)
	assert.Nil(t, i2)

	serverOnly := headerResp(200, http.Header{"Server": []string{"Ingenico-TEM/1.0"}, "Content-Type": []string{"text/html"}})
	i3, err := (&IngenicoFingerprinter{}).Fingerprint(serverOnly, nil)
	require.NoError(t, err)
	assert.Nil(t, i3)
}

func TestPOSPOI_RedirectLocationIsNeverIdentity(t *testing.T) {
	tests := []struct {
		name string
		fp   HTTPFingerprinter
		resp *http.Response
		body []byte
	}{
		{
			name: "verifone 302 Location to probe path with empty body",
			fp:   &VerifoneFingerprinter{},
			resp: headerResp(302, http.Header{"Location": []string{"/VHQ.Authentication.VHQFederationV1/Account/Login"}}),
		},
		{
			name: "verifone 302 Location to probe path with generic login HTML",
			fp:   &VerifoneFingerprinter{},
			resp: headerResp(302, http.Header{
				"Location":     []string{"/VHQ.Authentication.VHQFederationV1/Account/Login"},
				"Content-Type": []string{"text/html"},
			}),
			body: []byte(genericLoginFixture),
		},
		{
			name: "verifone catch-all 302 to /login",
			fp:   &VerifoneFingerprinter{},
			resp: headerResp(302, http.Header{
				"Location":     []string{"/login"},
				"Content-Type": []string{"text/html"},
			}),
			body: []byte(genericLoginFixture),
		},
		{
			name: "ingenico 302 Location to probe path with empty body",
			fp:   &IngenicoFingerprinter{},
			resp: headerResp(302, http.Header{"Location": []string{"/emgui/resetPassword.jsp"}}),
		},
		{
			name: "ingenico catch-all 302 to /login",
			fp:   &IngenicoFingerprinter{},
			resp: headerResp(302, http.Header{
				"Location":     []string{"/login"},
				"Content-Type": []string{"text/html"},
			}),
			body: []byte(genericLoginFixture),
		},
		{
			name: "verifone catch-all 200 apache on probe path",
			fp:   &VerifoneFingerprinter{},
			resp: posPoiHTMLResp(200),
			body: []byte(genericApacheFixture),
		},
		{
			name: "ingenico catch-all 200 apache on probe path",
			fp:   &IngenicoFingerprinter{},
			resp: posPoiHTMLResp(200),
			body: []byte(genericApacheFixture),
		},
		{
			name: "product Server token is not identity",
			fp:   &VerifoneFingerprinter{},
			resp: headerResp(302, http.Header{
				"Server":       []string{"Verifone-Commander/57.01"},
				"Location":     []string{"/ConfigClient.html"},
				"Content-Type": []string{"text/html"},
			}),
		},
		{
			name: "ingenico TEM Server token is not identity",
			fp:   &IngenicoFingerprinter{},
			resp: headerResp(302, http.Header{
				"Server":       []string{"Ingenico-TEM/1.0"},
				"Location":     []string{"/emgui/vue/"},
				"Content-Type": []string{"text/html"},
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.fp.Fingerprint(tt.resp, tt.body)
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

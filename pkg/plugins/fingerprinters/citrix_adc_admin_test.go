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

const citrixADCAdminGUIBody = `<!DOCTYPE html><html><head>
<title>Citrix ADC</title>
<script src="/menu/neo/js/app.js"></script>
</head><body><div id="neo-app"></div></body></html>`

const citrixNitroJSON = `{"errorcode":354,"message":"Not authorized to execute this command [login]","severity":"ERROR"}`

func newJSONResp(status int, body string) *http.Response {
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	return &http.Response{StatusCode: status, Header: h}
}

func TestCitrixADCAdminFingerprinter_NameAndProbe(t *testing.T) {
	fp := &CitrixADCAdminFingerprinter{}
	assert.Equal(t, "citrix-adc-admin", fp.Name())
	assert.Equal(t, "/menu/neo", fp.ProbeEndpoint())
	assert.Equal(t, "text/html", fp.ProbeAccept())
}

func TestCitrixADCNitroFingerprinter_NameAndProbe(t *testing.T) {
	fp := &CitrixADCNitroFingerprinter{}
	assert.Equal(t, "citrix-adc-nitro", fp.Name())
	assert.Equal(t, "/nitro/v1/config", fp.ProbeEndpoint())
	assert.Equal(t, "application/json", fp.ProbeAccept())
}

func TestCitrixADCAdmin_RegisteredProbes(t *testing.T) {
	endpoints := GetProbeEndpoints()
	assert.Equal(t, "/menu/neo", endpoints["citrix-adc-admin"])
	assert.Equal(t, "/nitro/v1/config", endpoints["citrix-adc-nitro"])
}

func TestCitrixADCAdminFingerprinter_Fingerprint(t *testing.T) {
	fp := &CitrixADCAdminFingerprinter{}
	resp := newCitrixResp(citrixADCAdminGUIBody, nil)

	result, err := fp.Fingerprint(resp, []byte(citrixADCAdminGUIBody))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "citrix-adc-admin", result.Technology)
	assert.Equal(t, "management", result.Metadata["interface_type"])
	assert.Equal(t, "gui", result.Metadata["detection_method"])
	require.Len(t, result.SecurityFindings, 1)
	assert.Equal(t, citrixADCAdminFindingID, result.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityMedium, result.SecurityFindings[0].Severity)
	require.NotEmpty(t, result.CPEs)
	assert.Contains(t, result.CPEs[0], "citrix:netscaler_application_delivery_controller")
}

func TestCitrixADCAdminFingerprinter_RejectsGateway(t *testing.T) {
	fp := &CitrixADCAdminFingerprinter{}
	resp := newCitrixResp(citrixGatewayBody, nil)

	result, err := fp.Fingerprint(resp, []byte(citrixGatewayBody))
	require.NoError(t, err)
	assert.Nil(t, result)

	aaa := newCitrixResp(citrixAAABody, nil)
	result, err = fp.Fingerprint(aaa, []byte(citrixAAABody))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestCitrixADCAdminFingerprinter_LocationRedirect(t *testing.T) {
	fp := &CitrixADCAdminFingerprinter{}
	resp := newCitrix302Resp("/ns_gui/", nil, nil)

	result, err := fp.Fingerprint(resp, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "citrix-adc-admin", result.Technology)
}

func TestCitrixADCNitroFingerprinter_Fingerprint(t *testing.T) {
	fp := &CitrixADCNitroFingerprinter{}
	resp := newJSONResp(401, citrixNitroJSON)

	result, err := fp.Fingerprint(resp, []byte(citrixNitroJSON))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "citrix-adc-admin", result.Technology)
	assert.Equal(t, "nitro", result.Metadata["detection_method"])
	require.Len(t, result.SecurityFindings, 1)
	assert.Equal(t, citrixADCAdminFindingID, result.SecurityFindings[0].ID)
}

func TestCitrixADCNitroFingerprinter_RejectsUnrelatedJSON(t *testing.T) {
	fp := &CitrixADCNitroFingerprinter{}
	body := `{"errorcode":500,"message":"internal error"}`
	resp := newJSONResp(500, body)
	resp.StatusCode = 200

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestCitrixADCNitroFingerprinter_RejectsGatewayHTML(t *testing.T) {
	fp := &CitrixADCNitroFingerprinter{}
	resp := newCitrixResp(citrixGatewayBody, nil)

	result, err := fp.Fingerprint(resp, []byte(citrixGatewayBody))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestIsCitrixNITRO(t *testing.T) {
	assert.True(t, isCitrixNITRO([]byte(citrixNitroJSON)))
	assert.True(t, isCitrixNITRO([]byte(`{"errorcode":444,"message":"Session expired or not logged in"}`)))
	assert.True(t, isCitrixNITRO([]byte(`{"errorcode":0,"message":"Done"}`)))
	assert.False(t, isCitrixNITRO([]byte(`{"errorcode":1,"message":"nope"}`)))
	assert.False(t, isCitrixNITRO([]byte(`not json`)))
}

func TestCitrixADCAdminFinding_CatalogEnrichment(t *testing.T) {
	f := plugins.SecurityFinding{
		ID:          citrixADCAdminFindingID,
		Severity:    plugins.SeverityMedium,
		Description: "Citrix ADC / NetScaler management plane is reachable",
	}
	f.Enrich()
	assert.Equal(t, "Citrix ADC Management Interface Exposed", f.Title)
	assert.Equal(t, plugins.SeverityMedium, f.Severity)
	assert.NotEmpty(t, f.Impact)
	assert.NotEmpty(t, f.Recommendation)
}

func TestCitrixADCAdminFingerprinter_RejectsPathEcho(t *testing.T) {
	fp := &CitrixADCAdminFingerprinter{}

	// Apache-style 404 that reflects the probed path must not match.
	notFound := `<html><head><title>404 Not Found</title></head><body>` +
		`<p>The requested URL /menu/neo was not found on this server.</p></body></html>`
	resp404 := newCitrixResp(notFound, nil)
	resp404.StatusCode = 404
	assert.False(t, fp.Match(resp404), "a 404 must not Match")
	result, err := fp.Fingerprint(resp404, []byte(notFound))
	require.NoError(t, err)
	assert.Nil(t, result, "a 404 echoing the probed path must not be detected")

	// Login redirect carrying the path only in a query param must not match.
	redir := newCitrix302Resp("/login?next=/menu/neo", nil, nil)
	result, err = fp.Fingerprint(redir, []byte(""))
	require.NoError(t, err)
	assert.Nil(t, result, "a login redirect with ?next=/menu/neo must not be detected")

	// A non-Citrix SPA that only uses the generic neo-app mount id must not match.
	spa := `<html><head><title>My App</title></head><body><div id="neo-app"></div></body></html>`
	resp200 := newCitrixResp(spa, nil)
	result, err = fp.Fingerprint(resp200, []byte(spa))
	require.NoError(t, err)
	assert.Nil(t, result, "a generic neo-app SPA must not be detected")

	// A cross-host redirect to /menu/neo is not evidence about this service.
	crossHost := newCitrix302Resp("https://sso.example.com/menu/neo/", nil, nil)
	result, err = fp.Fingerprint(crossHost, []byte(""))
	require.NoError(t, err)
	assert.Nil(t, result, "a cross-host redirect must not be detected")

	// /menu/neofoo is a different path segment and must not match.
	neoFoo := newCitrix302Resp("/menu/neofoo", nil, nil)
	result, err = fp.Fingerprint(neoFoo, []byte(""))
	require.NoError(t, err)
	assert.Nil(t, result, "/menu/neofoo must not be treated as the ADC GUI")
}

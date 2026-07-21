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

package webcenter

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// hdaBody is a representative unauthenticated PING_SERVER HDA response.
const hdaBody = `<?hda version="12.2.1.2.0-2017-07-05 09:25:44Z-r155055" jcharset="UTF8" encoding="utf-8"?>
@Properties LocalData
IdcService=PING_SERVER
IsAllowAnonymous=1
StatusCode=0
StatusMessage=You are logged in as 'weblogic'
@end`

// ---------------------------------------------------------------------------
// Unit-level tests for the small helper functions.
// ---------------------------------------------------------------------------

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "simple title",
			body:     `<html><head><title>Oracle WebCenter Content</title></head></html>`,
			expected: "Oracle WebCenter Content",
		},
		{
			name:     "title with surrounding whitespace",
			body:     `<html><head><title>  Content Server  </title></head></html>`,
			expected: "Content Server",
		},
		{
			name:     "no title element",
			body:     `<html><head></head><body>hello</body></html>`,
			expected: "",
		},
		{
			// TP2 regression: titlePattern must tolerate attributes on the
			// opening <title> tag (e.g. an id attribute), not just a bare
			// <title>.
			name:     "title with id attribute",
			body:     `<html><head><title id="pageTitle">Oracle WebCenter Content</title></head></html>`,
			expected: "Oracle WebCenter Content",
		},
		{
			name:     "empty body",
			body:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractTitle(tt.body))
		})
	}
}

func TestParseHDAVersion(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "HDA prefix with dotted build version",
			body:     hdaBody,
			expected: "12.2.1.2.0",
		},
		{
			name:     "no HDA prefix",
			body:     "<html><body>not an HDA response</body></html>",
			expected: "",
		},
		{
			name:     "HDA prefix with non-numeric version",
			body:     `<?hda version="unknown" jcharset="UTF8"?>`,
			expected: "",
		},
		{
			name:     "empty body",
			body:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseHDAVersion(tt.body))
		})
	}
}

func TestHasHDAMarker(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{name: "genuine HDA response", body: hdaBody, expected: true},
		{
			// Reflection guard: an error/echo page that merely reflects the
			// requested query tokens (idcplg, PING_SERVER, IdcService) back
			// must NOT be treated as a valid Idc/HDA structure.
			name:     "body reflecting probe tokens is not an HDA structure",
			body:     "Error: unknown IdcService=PING_SERVER at /cs/idcplg",
			expected: false,
		},
		{
			name:     "body reflecting all three probe tokens verbatim",
			body:     "<html><body>Bad request: idcplg?IdcService=PING_SERVER not found</body></html>",
			expected: false,
		},
		{name: "generic html", body: "<html><body>hi</body></html>", expected: false},
		{name: "empty", body: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasHDAMarker(tt.body))
		})
	}
}

func TestHasContentServerCookie(t *testing.T) {
	tests := []struct {
		name      string
		setCookie string
		expected  bool
	}{
		{name: "IdcLocale cookie present", setCookie: "IdcLocale=English-US; Path=/", expected: true},
		{name: "IntradocAuth cookie present", setCookie: "IntradocAuth=Internet; Path=/", expected: true},
		{name: "unrelated cookie", setCookie: "JSESSIONID=abc123; Path=/", expected: false},
		{name: "empty", setCookie: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasContentServerCookie(tt.setCookie))
		})
	}
}

func TestTitleHelpers(t *testing.T) {
	tests := []struct {
		name    string
		title   string
		content bool
		portal  bool
		sites   bool
		family  bool
	}{
		{name: "Oracle WebCenter Content", title: "Oracle WebCenter Content", content: true, family: true},
		{name: "Content Server", title: "Content Server Login", content: true},
		{name: "Stellent", title: "Stellent Content Server", content: true},
		{name: "Oracle WebCenter Portal", title: "Oracle WebCenter Portal", portal: true, family: true},
		{name: "Oracle WebCenter Sites", title: "Oracle WebCenter Sites", sites: true, family: true},
		{name: "generic admin", title: "System Administration"},
		{name: "generic welcome", title: "Welcome"},
		{name: "empty", title: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.content, titleIsWebCenterContent(tt.title), "content")
			assert.Equal(t, tt.portal, titleIsWebCenterPortal(tt.title), "portal")
			assert.Equal(t, tt.sites, titleIsWebCenterSites(tt.title), "sites")
			assert.Equal(t, tt.family, titleIsWebCenterFamily(tt.title), "family")
		})
	}
}

func TestBuildWebCenterCPE(t *testing.T) {
	tests := []struct {
		name      string
		component string
		version   string
		expected  string
	}{
		{
			name:      "Content with version",
			component: componentContent,
			version:   "12.2.1.2.0",
			expected:  "cpe:2.3:a:oracle:webcenter_content:12.2.1.2.0:*:*:*:*:*:*:*",
		},
		{
			name:      "Content without version wildcards",
			component: componentContent,
			version:   "",
			expected:  "cpe:2.3:a:oracle:webcenter_content:*:*:*:*:*:*:*:*",
		},
		{
			name:      "Portal always wildcard",
			component: componentPortal,
			version:   "",
			expected:  "cpe:2.3:a:oracle:webcenter_portal:*:*:*:*:*:*:*:*",
		},
		{
			name:      "Portal ignores any supplied version",
			component: componentPortal,
			version:   "12.2.1.4.0",
			expected:  "cpe:2.3:a:oracle:webcenter_portal:*:*:*:*:*:*:*:*",
		},
		{
			name:      "Sites always wildcard",
			component: componentSites,
			version:   "",
			expected:  "cpe:2.3:a:oracle:webcenter_sites:*:*:*:*:*:*:*:*",
		},
		{
			name:      "unknown component returns empty string",
			component: "",
			version:   "",
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildWebCenterCPE(tt.component, tt.version))
		})
	}
}

func TestEvaluateWebCenter(t *testing.T) {
	tests := []struct {
		name              string
		evidence          []wcEvidence
		expectedComponent string
		expectedVersion   string
		expectedDetect    bool
	}{
		{
			name: "idcplg HDA body classifies Content and yields version",
			evidence: []wcEvidence{
				{path: pathPing, statusCode: http.StatusOK, body: hdaBody},
			},
			expectedComponent: componentContent,
			expectedVersion:   "12.2.1.2.0",
			expectedDetect:    true,
		},
		{
			name: "IdcLocale cookie on /cs classifies Content",
			evidence: []wcEvidence{
				{path: pathCS, statusCode: http.StatusOK, setCookie: "IdcLocale=English-US; Path=/"},
			},
			expectedComponent: componentContent,
			expectedDetect:    true,
		},
		{
			name: "IntradocAuth cookie classifies Content",
			evidence: []wcEvidence{
				{path: pathCS, statusCode: http.StatusOK, setCookie: "IntradocAuth=Internet; Path=/"},
			},
			expectedComponent: componentContent,
			expectedDetect:    true,
		},
		{
			name: "Content Server title classifies Content",
			evidence: []wcEvidence{
				{path: pathCS, statusCode: http.StatusOK, body: `<html><head><title>Content Server</title></head></html>`},
			},
			expectedComponent: componentContent,
			expectedDetect:    true,
		},
		{
			name: "Stellent title classifies Content",
			evidence: []wcEvidence{
				{path: pathCS, statusCode: http.StatusOK, body: `<html><head><title>Stellent Universal Content Management</title></head></html>`},
			},
			expectedComponent: componentContent,
			expectedDetect:    true,
		},
		{
			name: "bare 200 on /webcenter with no branded title is not detected",
			evidence: []wcEvidence{
				{path: pathWebCenter, statusCode: http.StatusOK, body: `<html><head><title>Welcome</title></head></html>`},
			},
			expectedDetect: false,
		},
		{
			name: "/webcenter with Oracle WebCenter Portal title classifies Portal",
			evidence: []wcEvidence{
				{path: pathWebCenter, statusCode: http.StatusOK, body: `<html><head><title>Oracle WebCenter Portal</title></head></html>`},
			},
			expectedComponent: componentPortal,
			expectedDetect:    true,
		},
		{
			name: "bare 200 on /sites with no marker is not detected",
			evidence: []wcEvidence{
				{path: pathSites, statusCode: http.StatusOK, body: `<html><head><title>Welcome</title></head></html>`},
			},
			expectedDetect: false,
		},
		{
			name: "/sites with Oracle WebCenter Sites title classifies Sites",
			evidence: []wcEvidence{
				{path: pathSites, statusCode: http.StatusOK, body: `<html><head><title>Oracle WebCenter Sites</title></head></html>`},
			},
			expectedComponent: componentSites,
			expectedDetect:    true,
		},
		{
			name: "/cs/Satellite non-404 with WebCenter family title classifies Sites",
			evidence: []wcEvidence{
				{path: pathSatellite, statusCode: http.StatusOK, body: `<html><head><title>Oracle WebCenter (Sites edition)</title></head></html>`},
			},
			expectedComponent: componentSites,
			expectedDetect:    true,
		},
		{
			name: "/cs/Satellite non-404 without a family title is not detected",
			evidence: []wcEvidence{
				{path: pathSatellite, statusCode: http.StatusOK, body: `<html><head><title>Welcome</title></head></html>`},
			},
			expectedDetect: false,
		},
		{
			// TP1 regression: a Portal host whose /cs/Satellite merely returns a
			// non-404 (with a NON-branded title on that same response) must not
			// be misclassified as Sites. The Satellite/Sites signal must be
			// correlated to its OWN response's title, not corroborated by a
			// family title seen on a completely different path (the old
			// satelliteSeen && familyTitle cross-path aggregation bug).
			name: "Portal host with non-404 /cs/Satellite bearing a non-branded title stays Portal, not Sites",
			evidence: []wcEvidence{
				{path: pathWebCenter, statusCode: http.StatusOK, body: `<html><head><title>Oracle WebCenter Portal</title></head></html>`},
				{path: pathSatellite, statusCode: http.StatusOK, body: `<html><head><title>Welcome</title></head></html>`},
			},
			expectedComponent: componentPortal,
			expectedDetect:    true,
		},
		{
			name: "idcplg body reflecting probe tokens only is not detected (reflection guard)",
			evidence: []wcEvidence{
				{path: pathPing, statusCode: http.StatusOK, body: "Error: unknown IdcService=PING_SERVER via idcplg"},
			},
			expectedDetect: false,
		},
		{
			name: "404 on /cs and /_dav with no markers is not detected",
			evidence: []wcEvidence{
				{path: pathCS, statusCode: http.StatusNotFound},
				{path: pathDav, statusCode: http.StatusNotFound},
			},
			expectedDetect: false,
		},
		{
			name:           "empty evidence is not detected",
			evidence:       []wcEvidence{},
			expectedDetect: false,
		},
		{
			name: "Content precedence over Portal when both present",
			evidence: []wcEvidence{
				{path: pathPing, statusCode: http.StatusOK, body: hdaBody},
				{path: pathWebCenter, statusCode: http.StatusOK, body: `<html><head><title>Oracle WebCenter Portal</title></head></html>`},
			},
			expectedComponent: componentContent,
			expectedVersion:   "12.2.1.2.0",
			expectedDetect:    true,
		},
		{
			name: "Sites precedence over Portal when both present",
			evidence: []wcEvidence{
				{path: pathSites, statusCode: http.StatusOK, body: `<html><head><title>Oracle WebCenter Sites</title></head></html>`},
				{path: pathWebCenter, statusCode: http.StatusOK, body: `<html><head><title>Oracle WebCenter Portal</title></head></html>`},
			},
			expectedComponent: componentSites,
			expectedDetect:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			component, version, detected := evaluateWebCenter(tt.evidence)
			assert.Equal(t, tt.expectedComponent, component, "component")
			assert.Equal(t, tt.expectedVersion, version, "version")
			assert.Equal(t, tt.expectedDetect, detected, "detected")
		})
	}
}

func TestEvaluateFindings(t *testing.T) {
	tests := []struct {
		name            string
		evidence        []wcEvidence
		expectedSurface bool
		expectedIdcAnon bool
	}{
		{
			name: "idcplg HDA on 2xx sets surface and anonymous Idc",
			evidence: []wcEvidence{
				{path: pathPing, statusCode: http.StatusOK, body: hdaBody},
			},
			expectedSurface: true,
			expectedIdcAnon: true,
		},
		{
			name: "branded title on 2xx sets surface but not anonymous Idc",
			evidence: []wcEvidence{
				{path: pathWebCenter, statusCode: http.StatusOK, body: `<html><head><title>Oracle WebCenter Portal</title></head></html>`},
			},
			expectedSurface: true,
			expectedIdcAnon: false,
		},
		{
			name: "idcplg HDA behind a redirect is neither surface nor anonymous",
			evidence: []wcEvidence{
				{path: pathPing, statusCode: http.StatusFound, body: hdaBody},
			},
			expectedSurface: false,
			expectedIdcAnon: false,
		},
		{
			name: "Idc cookie only on a redirect is not anonymous surface",
			evidence: []wcEvidence{
				{path: pathCS, statusCode: http.StatusFound, setCookie: "IdcLocale=English-US; Path=/"},
			},
			expectedSurface: false,
			expectedIdcAnon: false,
		},
		{
			name: "reflected idcplg tokens on 2xx never set surface or anonymous Idc",
			evidence: []wcEvidence{
				{path: pathPing, statusCode: http.StatusOK, body: "Error: unknown IdcService=PING_SERVER via idcplg"},
			},
			expectedSurface: false,
			expectedIdcAnon: false,
		},
		{
			name:            "empty evidence",
			evidence:        []wcEvidence{},
			expectedSurface: false,
			expectedIdcAnon: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			surface, idcAnon := evaluateFindings(tt.evidence)
			assert.Equal(t, tt.expectedSurface, surface, "surfaceReachable")
			assert.Equal(t, tt.expectedIdcAnon, idcAnon, "idcAnonymous")
		})
	}
}

// ---------------------------------------------------------------------------
// httptest-backed Run() tests. A tiny per-path response table drives a single
// handler so scenarios can be expressed as table-driven cases matching the
// exact probe paths issued by detectWebCenter.
// ---------------------------------------------------------------------------

// pathResponse describes the canned response for one probe path.
type pathResponse struct {
	status int
	body   string
	cookie string // optional Set-Cookie header value
}

// newPathHandler builds an http.HandlerFunc that answers configured paths and
// 404s everything else (mirroring an app server that doesn't recognize a path).
func newPathHandler(responses map[string]pathResponse) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp, ok := responses[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if resp.cookie != "" {
			w.Header().Set("Set-Cookie", resp.cookie)
		}
		w.WriteHeader(resp.status)
		if resp.body != "" {
			fmt.Fprint(w, resp.body)
		}
	}
}

// parseTestServerAddr parses an httptest server URL into a netip.AddrPort.
func parseTestServerAddr(t *testing.T, serverURL string) netip.AddrPort {
	t.Helper()
	hostPort := strings.TrimPrefix(serverURL, "http://")
	host, portStr, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))
}

// dialTarget dials the httptest server and builds a matching plugins.Target.
func dialTarget(t *testing.T, server *httptest.Server, misconfigs bool) (net.Conn, plugins.Target) {
	t.Helper()
	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	return conn, plugins.Target{
		Host:       addr.Addr().String(),
		Address:    addr,
		Misconfigs: misconfigs,
	}
}

func TestWebCenterPlugin_Run_TableDriven(t *testing.T) {
	tests := []struct {
		name            string
		responses       map[string]pathResponse
		expectDetected  bool
		expectComponent string
		expectVersion   string
		expectCPE       string
	}{
		{
			name: "Content via idcplg PING_SERVER HDA body",
			responses: map[string]pathResponse{
				"/cs/idcplg": {status: http.StatusOK, body: hdaBody},
			},
			expectDetected:  true,
			expectComponent: componentContent,
			expectVersion:   "12.2.1.2.0",
			expectCPE:       "cpe:2.3:a:oracle:webcenter_content:12.2.1.2.0:*:*:*:*:*:*:*",
		},
		{
			name: "Content via Set-Cookie IdcLocale (no version, wildcard CPE)",
			responses: map[string]pathResponse{
				"/cs": {status: http.StatusOK, cookie: "IdcLocale=English-US; Path=/"},
			},
			expectDetected:  true,
			expectComponent: componentContent,
			expectVersion:   "",
			expectCPE:       "cpe:2.3:a:oracle:webcenter_content:*:*:*:*:*:*:*:*",
		},
		{
			name: "Content via Set-Cookie IntradocAuth (no version, wildcard CPE)",
			responses: map[string]pathResponse{
				"/cs": {status: http.StatusOK, cookie: "IntradocAuth=Internet; Path=/"},
			},
			expectDetected:  true,
			expectComponent: componentContent,
			expectVersion:   "",
			expectCPE:       "cpe:2.3:a:oracle:webcenter_content:*:*:*:*:*:*:*:*",
		},
		{
			name: "Content via title Oracle WebCenter Content",
			responses: map[string]pathResponse{
				"/cs": {status: http.StatusOK, body: `<html><head><title>Oracle WebCenter Content</title></head></html>`},
			},
			expectDetected:  true,
			expectComponent: componentContent,
			expectVersion:   "",
			expectCPE:       "cpe:2.3:a:oracle:webcenter_content:*:*:*:*:*:*:*:*",
		},
		{
			name: "Content via title Content Server",
			responses: map[string]pathResponse{
				"/cs": {status: http.StatusOK, body: `<html><head><title>Content Server</title></head></html>`},
			},
			expectDetected:  true,
			expectComponent: componentContent,
			expectVersion:   "",
			expectCPE:       "cpe:2.3:a:oracle:webcenter_content:*:*:*:*:*:*:*:*",
		},
		{
			name: "Content via title Stellent",
			responses: map[string]pathResponse{
				"/cs": {status: http.StatusOK, body: `<html><head><title>Stellent Universal Content Management</title></head></html>`},
			},
			expectDetected:  true,
			expectComponent: componentContent,
			expectVersion:   "",
			expectCPE:       "cpe:2.3:a:oracle:webcenter_content:*:*:*:*:*:*:*:*",
		},
		{
			name: "Portal via /webcenter/ with branded title",
			responses: map[string]pathResponse{
				"/webcenter/": {status: http.StatusOK, body: `<html><head><title>Oracle WebCenter Portal</title></head></html>`},
			},
			expectDetected:  true,
			expectComponent: componentPortal,
			expectVersion:   "",
			expectCPE:       "cpe:2.3:a:oracle:webcenter_portal:*:*:*:*:*:*:*:*",
		},
		{
			name: "Sites via /sites/ with branded title",
			responses: map[string]pathResponse{
				"/sites/": {status: http.StatusOK, body: `<html><head><title>Oracle WebCenter Sites</title></head></html>`},
			},
			expectDetected:  true,
			expectComponent: componentSites,
			expectVersion:   "",
			expectCPE:       "cpe:2.3:a:oracle:webcenter_sites:*:*:*:*:*:*:*:*",
		},
		{
			name: "Sites via /cs/Satellite corroborated by a WebCenter family title",
			responses: map[string]pathResponse{
				"/cs/Satellite": {status: http.StatusOK, body: `<html><head><title>Oracle WebCenter (Sites Edition)</title></head></html>`},
			},
			expectDetected:  true,
			expectComponent: componentSites,
			expectVersion:   "",
			expectCPE:       "cpe:2.3:a:oracle:webcenter_sites:*:*:*:*:*:*:*:*",
		},
		{
			name: "precedence: Content and Portal markers both present -> Content wins",
			responses: map[string]pathResponse{
				"/cs/idcplg":  {status: http.StatusOK, body: hdaBody},
				"/webcenter/": {status: http.StatusOK, body: `<html><head><title>Oracle WebCenter Portal</title></head></html>`},
			},
			expectDetected:  true,
			expectComponent: componentContent,
			expectVersion:   "12.2.1.2.0",
			expectCPE:       "cpe:2.3:a:oracle:webcenter_content:12.2.1.2.0:*:*:*:*:*:*:*",
		},
		{
			name: "bare 200 on /webcenter/, /cs, /sites/ with no branded marker is not detected",
			responses: map[string]pathResponse{
				"/webcenter/": {status: http.StatusOK, body: `<html><head><title>Welcome</title></head></html>`},
				"/cs":         {status: http.StatusOK, body: `<html><head><title>Welcome</title></head></html>`},
				"/sites/":     {status: http.StatusOK, body: `<html><head><title>Welcome</title></head></html>`},
			},
			expectDetected: false,
		},
		{
			name: "reflection trap: idcplg error page echoes probe tokens but is not a valid HDA structure",
			responses: map[string]pathResponse{
				"/cs/idcplg": {status: http.StatusOK, body: `<html><body>Error: unknown IdcService=PING_SERVER requested via idcplg</body></html>`},
			},
			expectDetected: false,
		},
		{
			name: "generic Tomcat/Apache server with unrelated title is not detected",
			responses: map[string]pathResponse{
				"/cs":         {status: http.StatusOK, body: `<html><head><title>Apache Tomcat/9.0</title></head></html>`},
				"/webcenter/": {status: http.StatusOK, body: `<html><head><title>Apache Tomcat/9.0</title></head></html>`},
			},
			expectDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(newPathHandler(tt.responses))
			defer server.Close()

			conn, target := dialTarget(t, server, false)
			defer conn.Close()

			service, err := (&WebCenterPlugin{}).Run(conn, 5*time.Second, target)
			require.NoError(t, err)

			if !tt.expectDetected {
				assert.Nil(t, service, "expected no detection")
				return
			}

			require.NotNil(t, service, "expected detection")
			assert.Equal(t, tt.expectVersion, service.Version)

			var payload plugins.ServiceOracleWebCenter
			require.NoError(t, json.Unmarshal(service.Raw, &payload))
			assert.Equal(t, tt.expectComponent, payload.Component)
			require.Len(t, payload.CPEs, 1, "exactly one component CPE per host")
			assert.Equal(t, tt.expectCPE, payload.CPEs[0])
		})
	}
}

func TestWebCenterPlugin_Run_Negative(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	conn, target := dialTarget(t, server, false)
	defer conn.Close()

	service, err := (&WebCenterPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestWebCenterPlugin_SecurityFindings(t *testing.T) {
	// idcplg answers PING_SERVER anonymously with a valid HDA on a 2xx.
	anonHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cs/idcplg" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, hdaBody)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	t.Run("Misconfigs=true yields Low exposed and Medium anonymous Idc findings", func(t *testing.T) {
		server := httptest.NewServer(anonHandler)
		defer server.Close()
		conn, target := dialTarget(t, server, true)
		defer conn.Close()

		service, err := (&WebCenterPlugin{}).Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 2)
		assert.Equal(t, "oracle-webcenter-exposed", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityLow, service.SecurityFindings[0].Severity)
		assert.Equal(t, "oracle-webcenter-content-idc-anonymous", service.SecurityFindings[1].ID)
		assert.Equal(t, plugins.SeverityMedium, service.SecurityFindings[1].Severity)
	})

	t.Run("Misconfigs=false yields no findings and no AnonymousAccess", func(t *testing.T) {
		server := httptest.NewServer(anonHandler)
		defer server.Close()
		conn, target := dialTarget(t, server, false)
		defer conn.Close()

		service, err := (&WebCenterPlugin{}).Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})

	t.Run("idcplg redirect to login is not anonymous: no Medium finding, no AnonymousAccess", func(t *testing.T) {
		// idcplg redirects to an SSO login surface but sets a Content Server
		// cookie, so the host is still classified (via the cookie) but the Idc
		// service did not answer anonymously and no 2xx surface was served.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/cs/idcplg" {
				w.Header().Set("Set-Cookie", "IdcLocale=English-US; Path=/")
				w.Header().Set("Location", "/oam/server/obrareq.cgi")
				w.WriteHeader(http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()
		conn, target := dialTarget(t, server, true)
		defer conn.Close()

		service, err := (&WebCenterPlugin{}).Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service, "cookie on redirect still classifies WebCenter Content")

		assert.False(t, service.AnonymousAccess, "a redirect to login is not anonymous access")
		assert.Empty(t, service.SecurityFindings, "no 2xx surface and no anonymous Idc response")
	})

	t.Run("non-2xx idcplg HDA response yields no findings even with Misconfigs=true", func(t *testing.T) {
		// A 500 error page happening to carry a valid HDA body must not be
		// treated as a reachable anonymous surface: evaluateFindings gates on
		// isSuccessStatus.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/cs/idcplg" {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, hdaBody)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()
		conn, target := dialTarget(t, server, true)
		defer conn.Close()

		service, err := (&WebCenterPlugin{}).Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service, "HDA body still classifies Content regardless of status code")

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}

func TestWebCenterPlugin_Metadata(t *testing.T) {
	plugin := &WebCenterPlugin{}
	assert.Equal(t, OracleWebCenter, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())

	// TP3: PortPriority broadened to cover Content (UCM), Portal, and Sites
	// default cleartext HTTP ports.
	for _, port := range []uint16{DefaultWebCenterPort, 8888, 8889, 7103, 7105, 7107, 7109} {
		assert.True(t, plugin.PortPriority(port), "expected TCP port %d to be in priority list", port)
	}
	for _, port := range []uint16{443, 80} {
		assert.False(t, plugin.PortPriority(port), "expected TLS/non-WebCenter port %d to not be in TCP priority list", port)
	}
}

func TestWebCenterTLSPlugin_Run_Positive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cs/idcplg" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, hdaBody)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	conn, target := dialTarget(t, server, false)
	defer conn.Close()

	service, err := (&WebCenterTLSPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.True(t, service.TLS)
	assert.Equal(t, "12.2.1.2.0", service.Version)

	var payload plugins.ServiceOracleWebCenter
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "Content", payload.Component)
	require.Len(t, payload.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:webcenter_content:12.2.1.2.0:*:*:*:*:*:*:*", payload.CPEs[0])
}

func TestWebCenterTLSPlugin_Run_Negative(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	conn, target := dialTarget(t, server, false)
	defer conn.Close()

	service, err := (&WebCenterTLSPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestWebCenterTLSPlugin_Run_SecurityFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cs/idcplg" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, hdaBody)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	conn, target := dialTarget(t, server, true)
	defer conn.Close()

	service, err := (&WebCenterTLSPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	assert.True(t, service.TLS)
	assert.True(t, service.AnonymousAccess)
	require.Len(t, service.SecurityFindings, 2, "exposed + idc-anonymous findings (CheckTLS is a no-op on a non-TLS test conn)")
	assert.Equal(t, "oracle-webcenter-exposed", service.SecurityFindings[0].ID)
	assert.Equal(t, "oracle-webcenter-content-idc-anonymous", service.SecurityFindings[1].ID)
}

func TestWebCenterTLSPlugin_Metadata(t *testing.T) {
	plugin := &WebCenterTLSPlugin{}
	assert.Equal(t, OracleWebCenter, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())

	// TP3: PortPriority broadened to cover Content (general HTTPS + SSL),
	// Portal SSL, and Sites SSL default ports.
	for _, port := range []uint16{443, 16201, 16301, 16251, 8788, 8789, 7104, 7106, 7108, 7110} {
		assert.True(t, plugin.PortPriority(port), "expected TLS port %d to be in priority list", port)
	}
	for _, port := range []uint16{DefaultWebCenterPort, 80} {
		assert.False(t, plugin.PortPriority(port), "expected TCP/non-WebCenter port %d to not be in TLS priority list", port)
	}
}

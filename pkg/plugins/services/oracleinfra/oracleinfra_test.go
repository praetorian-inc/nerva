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

package oracleinfra

import (
	"context"
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

// ---------------------------------------------------------------------------
// pure-helper unit tests (no socket)
// ---------------------------------------------------------------------------

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{"simple title", `<html><head><title>ILOM Web Interface</title></head></html>`, "ILOM Web Interface"},
		{"title with surrounding whitespace", `<title>  Some Title  </title>`, "Some Title"},
		{"no title element", `<html><body>hello</body></html>`, ""},
		{"empty body", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractTitle(tt.body))
		})
	}
}

func TestIsSuccessStatus(t *testing.T) {
	tests := []struct {
		name string
		code int
		want bool
	}{
		{"200 is success", http.StatusOK, true},
		{"299 boundary is success", 299, true},
		{"300 is not success", http.StatusMultipleChoices, false},
		{"199 is not success", 199, false},
		{"404 is not success", http.StatusNotFound, false},
		{"401 is not success", http.StatusUnauthorized, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isSuccessStatus(tt.code))
		})
	}
}

func TestCPEVersion(t *testing.T) {
	assert.Equal(t, "*", cpeVersion(""))
	assert.Equal(t, "5.1.0.21", cpeVersion("5.1.0.21"))
}

func TestIsOracleRedfish(t *testing.T) {
	tests := []struct {
		name string
		root redfishServiceRoot
		want bool
	}{
		{"vendor oracle", redfishServiceRoot{Vendor: "Oracle"}, true},
		{"vendor oracle mixed case", redfishServiceRoot{Vendor: "ORACLE Corporation"}, true},
		{
			"oem oracle key",
			redfishServiceRoot{Oem: map[string]json.RawMessage{"Oracle": json.RawMessage(`{}`)}},
			true,
		},
		{
			"oem oracle key case-insensitive",
			redfishServiceRoot{Oem: map[string]json.RawMessage{"oracle": json.RawMessage(`{}`)}},
			true,
		},
		{"product full name ILOM", redfishServiceRoot{Product: "Oracle Integrated Lights Out Manager"}, true},
		{"product bare ILOM token", redfishServiceRoot{Product: "ILOM"}, true},
		{"dell idrac", redfishServiceRoot{Vendor: "Dell", Product: "iDRAC9"}, false},
		{
			"hpe ilo (Oem.Hpe, not Oem.Oracle)",
			redfishServiceRoot{Vendor: "HPE", Product: "iLO 5", Oem: map[string]json.RawMessage{"Hpe": json.RawMessage(`{}`)}},
			false,
		},
		{"supermicro", redfishServiceRoot{Vendor: "Supermicro", Product: "SMCIPMITool"}, false},
		{"empty", redfishServiceRoot{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isOracleRedfish(tt.root))
		})
	}
}

func TestIsILOMWebMarker(t *testing.T) {
	assert.True(t, isILOMWebMarker("Oracle Integrated Lights Out Manager", ""))
	assert.True(t, isILOMWebMarker("", "Sun-ILOM-Web-Server/1.0"))
	assert.True(t, isILOMWebMarker("", "sun-ilom-web-server/1.0")) // case-insensitive Server header
	assert.False(t, isILOMWebMarker("Apache Tomcat", "nginx"))
	assert.False(t, isILOMWebMarker("", ""))
}

func TestFetchILOMFirmware(t *testing.T) {
	t.Run("empty managers path short-circuits", func(t *testing.T) {
		assert.Equal(t, "", fetchILOMFirmware(http.DefaultClient, "http://unused.invalid", "", ""))
	})

	t.Run("collection fetch transport error returns empty", func(t *testing.T) {
		// Port 0 with an unroutable host guarantees a dial failure.
		assert.Equal(t, "", fetchILOMFirmware(http.DefaultClient, "http://127.0.0.1:0", "", "/redfish/v1/Managers"))
	})

	t.Run("malformed collection json returns empty", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `not json`)
		}))
		defer srv.Close()
		assert.Equal(t, "", fetchILOMFirmware(srv.Client(), srv.URL, "", "/redfish/v1/Managers"))
	})

	t.Run("no members returns empty", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"Members":[]}`)
		}))
		defer srv.Close()
		assert.Equal(t, "", fetchILOMFirmware(srv.Client(), srv.URL, "", "/redfish/v1/Managers"))
	})

	t.Run("member with empty odata id returns empty", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"Members":[{"@odata.id":""}]}`)
		}))
		defer srv.Close()
		assert.Equal(t, "", fetchILOMFirmware(srv.Client(), srv.URL, "", "/redfish/v1/Managers"))
	})

	t.Run("manager fetch with malformed body returns empty", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/redfish/v1/Managers":
				fmt.Fprint(w, `{"Members":[{"@odata.id":"/redfish/v1/Managers/1"}]}`)
			default:
				w.WriteHeader(http.StatusInternalServerError) // empty body -> json.Unmarshal fails
			}
		}))
		defer srv.Close()
		assert.Equal(t, "", fetchILOMFirmware(srv.Client(), srv.URL, "", "/redfish/v1/Managers"))
	})

	t.Run("full happy path resolves firmware version", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/redfish/v1/Managers":
				fmt.Fprint(w, `{"Members":[{"@odata.id":"/redfish/v1/Managers/1"}]}`)
			case "/redfish/v1/Managers/1":
				fmt.Fprint(w, `{"FirmwareVersion":"5.1.0.21"}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		assert.Equal(t, "5.1.0.21", fetchILOMFirmware(srv.Client(), srv.URL, "", "/redfish/v1/Managers"))
	})
}

func TestHasODIAgentToken(t *testing.T) {
	assert.True(t, hasODIAgentToken("ODI-1battery agent alive"))
	assert.True(t, hasODIAgentToken("<p>OracleDIAgent running</p>"))
	assert.True(t, hasODIAgentToken("Oracle Data Integrator standalone agent"))
	assert.False(t, hasODIAgentToken("OK"))
	assert.False(t, hasODIAgentToken("<html><body>404 not found</body></html>"))
	assert.False(t, hasODIAgentToken(""))
	// Regression (LAB-5055 self-reflection fix): a server that merely reflects
	// the lowercase probe path in its body must NOT be classified as ODI. Only
	// the mixed-case "OracleDIAgent" identity string (or "ODI-" / a
	// case-insensitive "oracle data integrator") is accepted; the lowercase
	// "oraclediagent" echo of our own request path is deliberately rejected.
	assert.False(t, hasODIAgentToken("no route for /oraclediagent/agentping"))
}

func TestParseODIVersion(t *testing.T) {
	assert.Equal(t, "12.2.1.4.0", parseODIVersion("agent alive; Oracle Data Integrator 12.2.1.4.0"))
	assert.Equal(t, "", parseODIVersion("agent alive"))
	assert.Equal(t, "", parseODIVersion("version 12.2.1")) // not five-part, degrades to wildcard
}

func TestIsODIConsole(t *testing.T) {
	assert.True(t, isODIConsole("Oracle Data Integrator Console"))
	// Regression (review fix): isODIConsole dropped the body arg and no longer
	// accepts the generic ADF /afr/ static prefix on its own -- it is emitted
	// by every Oracle ADF/WebLogic app, so a title-like string carrying only
	// "/afr/" must NOT classify as the ODI console.
	assert.False(t, isODIConsole("/afr/partition/x"))
	assert.False(t, isODIConsole("System Administration"))
	assert.False(t, isODIConsole(""))
}

func TestHasOvirtPresence(t *testing.T) {
	tests := []struct {
		name string
		ev   olvmEvidence
		want bool
	}{
		{"location marker", olvmEvidence{rootLocation: "/ovirt-engine/webadmin"}, true},
		{"body marker", olvmEvidence{rootBody: "welcome to ovirt-engine"}, true},
		{"api 401 challenge is presence", olvmEvidence{apiStatus: http.StatusUnauthorized}, true},
		{"api 404 is not presence", olvmEvidence{apiStatus: http.StatusNotFound}, false},
		{"no markers", olvmEvidence{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasOvirtPresence(tt.ev))
		})
	}
}

func TestHasOLVMBranding(t *testing.T) {
	tests := []struct {
		name string
		ev   olvmEvidence
		want bool
	}{
		{"title branding", olvmEvidence{rootTitle: "Oracle Linux Virtualization Manager"}, true},
		{"body branding", olvmEvidence{rootBody: "OLVM release notes"}, true},
		{"api body branding", olvmEvidence{apiBody: "olvm rest api"}, true},
		{"generic ovirt title only", olvmEvidence{rootTitle: "oVirt Engine"}, false},
		{"empty", olvmEvidence{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasOLVMBranding(tt.ev))
		})
	}
}

func TestEvaluateOLVM(t *testing.T) {
	tests := []struct {
		name string
		ev   olvmEvidence
		want bool
	}{
		{"ovirt+oracle brand", olvmEvidence{rootBody: "ovirt-engine", rootTitle: "Oracle Linux Virtualization Manager"}, true},
		{"api401+olvm brand", olvmEvidence{apiStatus: http.StatusUnauthorized, apiBody: "OLVM realm"}, true},
		{"upstream ovirt no brand", olvmEvidence{rootBody: "ovirt-engine", rootTitle: "oVirt Engine"}, false},
		{"brand without ovirt presence", olvmEvidence{rootTitle: "Oracle Linux Virtualization Manager"}, false},
		{"empty", olvmEvidence{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, evaluateOLVM(tt.ev))
		})
	}
}

func TestMatchVBoxSOAP(t *testing.T) {
	assert.True(t, matchVBoxSOAP(`<vbox:IVirtualBox_getVersionResponse xmlns:vbox="http://www.virtualbox.org/"><returnval>7.0.14</returnval></vbox:IVirtualBox_getVersionResponse>`))
	assert.True(t, matchVBoxSOAP(`<SOAP-ENV:Fault xmlns:vbox="http://www.virtualbox.org/"><faultstring>vbox:InvalidObjectFault</faultstring></SOAP-ENV:Fault>`))
	assert.True(t, matchVBoxSOAP(`<SOAP-ENV:Fault xmlns:vbox="http://www.virtualbox.org/"><faultstring>vbox:RuntimeFault</faultstring></SOAP-ENV:Fault>`))
	assert.False(t, matchVBoxSOAP(`<SOAP-ENV:Fault>generic gSOAP error</SOAP-ENV:Fault>`))
	assert.False(t, matchVBoxSOAP(""))
	// Regression (LAB-5055 self-reflection fix): the vbox namespace alone is
	// insufficient -- it is also present in our own POSTed SOAP request body
	// (vboxSOAPBody), so a server that merely echoes our request verbatim
	// (namespace present, no response/fault element) must NOT match.
	assert.False(t, matchVBoxSOAP(vboxSOAPBody))
	// Regression (review fix): the vbox namespace TOGETHER WITH a generic
	// SOAP-ENV:Fault/faultstring -- but NO vbox-specific element
	// (getVersionResponse/InvalidObjectFault/RuntimeFault) -- must NOT match.
	// This is the core "request-echoing SOAP server" regression: a server that
	// wraps our submitted vbox namespace in its own generic fault handler
	// (rather than emitting a vbox-specific fault type) must not be classified
	// as VirtualBox.
	assert.False(t, matchVBoxSOAP(`<SOAP-ENV:Fault xmlns:vbox="http://www.virtualbox.org/"><faultstring>Internal Server Error</faultstring></SOAP-ENV:Fault>`))
}

func TestCPEBuilders(t *testing.T) {
	assert.Equal(t, "cpe:2.3:o:oracle:integrated_lights_out_manager_firmware:5.1.0.21:*:*:*:*:*:*:*", buildILOMCPE("5.1.0.21"))
	assert.Equal(t, "cpe:2.3:o:oracle:integrated_lights_out_manager_firmware:*:*:*:*:*:*:*:*", buildILOMCPE(""))
	assert.Equal(t, "cpe:2.3:a:oracle:data_integrator:12.2.1.4.0:*:*:*:*:*:*:*", buildODICPE("12.2.1.4.0"))
	assert.Equal(t, "cpe:2.3:a:oracle:data_integrator:*:*:*:*:*:*:*:*", buildODICPE(""))
	assert.Equal(t, "cpe:2.3:a:ovirt:ovirt-engine:*:*:*:*:*:*:*:*", buildOLVMCPE(""))
	assert.Equal(t, "cpe:2.3:a:oracle:vm_virtualbox:*:*:*:*:*:*:*:*", buildVBoxCPE())
}

func TestFindingDefinitions(t *testing.T) {
	t.Run("ilom finding", func(t *testing.T) {
		f := ilomFinding()
		assert.Equal(t, "oracle-ilom-exposed", f.ID)
		assert.Equal(t, plugins.SeverityMedium, f.Severity)
		assert.Equal(t, "Oracle ILOM management surface responded without credentials", f.Evidence)
		assert.NotContains(t, strings.ToLower(f.Evidence), "certificate")
		assert.NotContains(t, strings.ToLower(f.Evidence), "firmwareversion")
	})

	t.Run("odi finding", func(t *testing.T) {
		f := odiFinding()
		assert.Equal(t, "oracle-odi-exposed", f.ID)
		assert.Equal(t, plugins.SeverityLow, f.Severity)
		assert.Equal(t, "Oracle Data Integrator endpoint responded without credentials", f.Evidence)
	})

	t.Run("olvm finding", func(t *testing.T) {
		f := olvmFinding()
		assert.Equal(t, "oracle-olvm-exposed", f.ID)
		assert.Equal(t, plugins.SeverityLow, f.Severity)
		assert.Equal(t, "Oracle Linux Virtualization Manager engine responded without credentials", f.Evidence)
	})

	t.Run("vbox finding", func(t *testing.T) {
		f := vboxFinding()
		assert.Equal(t, "oracle-virtualbox-websrv-exposed", f.ID)
		assert.Equal(t, plugins.SeverityLow, f.Severity)
		assert.Equal(t, "VirtualBox web service responded to an unauthenticated SOAP request", f.Evidence)
	})

	// None of the four findings should ever be mistaken for (or reference) the
	// existing, separate IPMI plugin/finding -- this package covers HTTP/SOAP
	// surfaces only, never UDP/623 IPMI.
	for _, f := range []plugins.SecurityFinding{ilomFinding(), odiFinding(), olvmFinding(), vboxFinding()} {
		assert.NotContains(t, strings.ToLower(f.ID), "ipmi")
		assert.NotContains(t, strings.ToLower(f.Description), "ipmi")
		assert.NotContains(t, strings.ToLower(f.Evidence), "ipmi")
	}
}

// --- createHTTPClient single-dial guard (unit) ---

// TestCreateHTTPClient_DialContextGuardRefusesSecondDial is a focused unit test
// for the PR #384 re-review fix: the *http.Transport returned by
// createHTTPClient hands out its single wrapped net.Conn on the first
// DialContext call, then refuses (a clean, non-fatal error) any subsequent
// dial rather than handing the same socket to a second concurrent caller,
// which would otherwise corrupt the connection / race on it.
func TestCreateHTTPClient_DialContextGuardRefusesSecondDial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	client := createHTTPClient(conn, 5*time.Second)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok, "createHTTPClient must configure an *http.Transport")

	gotConn, err := transport.DialContext(context.Background(), "tcp", "ignored:0")
	require.NoError(t, err, "the first dial must succeed and hand out the wrapped conn")
	assert.Same(t, conn, gotConn)

	_, err = transport.DialContext(context.Background(), "tcp", "ignored:0")
	require.Error(t, err, "a second dial must be refused rather than handing out the same conn again")
}

// ---------------------------------------------------------------------------
// integration tests (httptest + real conn)
// ---------------------------------------------------------------------------

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

// dialTestServer dials an httptest server and returns the connection along
// with a Target populated from the server's address, mirroring how the
// scanner constructs Target for real connections.
func dialTestServer(t *testing.T, srv *httptest.Server, misconfigs bool) (net.Conn, plugins.Target) {
	t.Helper()
	addr := parseTestServerAddr(t, srv.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(srv.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn, plugins.Target{Host: addr.Addr().String(), Address: addr, Misconfigs: misconfigs}
}

// --- ILOM ---

func TestInfraPlugin_ILOM_RedfishOracleDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redfish/v1/":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"Vendor":"Oracle","Product":"Oracle Integrated Lights Out Manager","Oem":{"Oracle":{}},"Managers":{"@odata.id":"/redfish/v1/Managers"}}`)
		case "/redfish/v1/Managers":
			fmt.Fprint(w, `{"Members":[{"@odata.id":"/redfish/v1/Managers/1"}]}`)
		case "/redfish/v1/Managers/1":
			fmt.Fprint(w, `{"FirmwareVersion":"5.1.0.21"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, true)
	svc, err := (&InfraTLSPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, svc)

	assert.Equal(t, plugins.ProtoOracleILOM, svc.Protocol)
	assert.Equal(t, "5.1.0.21", svc.Version)
	assert.True(t, svc.AnonymousAccess)
	assert.True(t, svc.TLS)

	var payload plugins.ServiceOracleInfra
	require.NoError(t, json.Unmarshal(svc.Raw, &payload))
	assert.Equal(t, ProductILOM, payload.Product)
	assert.True(t, payload.Redfish)
	require.Len(t, payload.CPEs, 1)
	assert.Equal(t, "cpe:2.3:o:oracle:integrated_lights_out_manager_firmware:5.1.0.21:*:*:*:*:*:*:*", payload.CPEs[0])

	require.Len(t, svc.SecurityFindings, 1)
	assert.Equal(t, "oracle-ilom-exposed", svc.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityMedium, svc.SecurityFindings[0].Severity)
}

func TestInfraPlugin_GenericRedfishBMCNotILOM(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"dell idrac", `{"Vendor":"Dell","Product":"iDRAC9"}`},
		{"hpe ilo", `{"Vendor":"HPE","Product":"iLO 5","Oem":{"Hpe":{}}}`},
		{"supermicro", `{"Vendor":"Supermicro","Product":"SMCIPMITool"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/redfish/v1/" {
					fmt.Fprint(w, tt.body)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer srv.Close()

			conn, target := dialTestServer(t, srv, true)
			svc, err := (&InfraTLSPlugin{}).Run(conn, 5*time.Second, target)
			require.NoError(t, err)
			assert.Nil(t, svc, "generic non-Oracle Redfish BMC must not be classified as ILOM")
		})
	}
}

func TestInfraPlugin_ILOMBrandedWebFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redfish/v1/":
			w.WriteHeader(http.StatusNotFound) // Redfish disabled
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><head><title>Oracle Integrated Lights Out Manager</title></head></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, false)
	svc, err := (&InfraPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, svc)

	assert.Equal(t, plugins.ProtoOracleILOM, svc.Protocol)
	assert.Equal(t, "", svc.Version) // no Redfish -> no firmware

	var payload plugins.ServiceOracleInfra
	require.NoError(t, json.Unmarshal(svc.Raw, &payload))
	assert.False(t, payload.Redfish)
}

func TestInfraPlugin_ILOMBrandedWebFallbackViaServerHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redfish/v1/":
			w.WriteHeader(http.StatusNotFound)
		case "/":
			w.Header().Set("Server", "Sun-ILOM-Web-Server/1.0")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, false)
	svc, err := (&InfraPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, plugins.ProtoOracleILOM, svc.Protocol)
}

// --- ODI ---

func TestInfraPlugin_ODI_AgentPingWithToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oraclediagent/agentping":
			fmt.Fprint(w, `ODI-1battery agent alive; Oracle Data Integrator 12.2.1.4.0`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, true)
	svc, err := (&InfraPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, svc)

	assert.Equal(t, plugins.ProtoOracleODI, svc.Protocol)
	assert.Equal(t, "12.2.1.4.0", svc.Version)
	assert.True(t, svc.AnonymousAccess)

	var payload plugins.ServiceOracleInfra
	require.NoError(t, json.Unmarshal(svc.Raw, &payload))
	assert.Equal(t, ProductODI, payload.Product)
	require.Len(t, payload.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:data_integrator:12.2.1.4.0:*:*:*:*:*:*:*", payload.CPEs[0])

	require.Len(t, svc.SecurityFindings, 1)
	assert.Equal(t, "oracle-odi-exposed", svc.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityLow, svc.SecurityFindings[0].Severity)
}

func TestInfraPlugin_ODI_ConsoleOnlyOracleTitle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/odiconsole/":
			fmt.Fprint(w, `<html><head><title>Oracle Data Integrator Console</title></head></html>`)
		default:
			w.WriteHeader(http.StatusNotFound) // agentping 404 -> no token branch
		}
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, false)
	svc, err := (&InfraPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, plugins.ProtoOracleODI, svc.Protocol)
	assert.Equal(t, "", svc.Version) // console-only path carries no version signal

	var payload plugins.ServiceOracleInfra
	require.NoError(t, json.Unmarshal(svc.Raw, &payload))
	assert.True(t, payload.Console)
}

// TestInfraPlugin_ODI_ConsoleBranded404NotDetected is a regression test for the
// isODIConsole/detectODI review fix: a branded ADF 404 error page (carrying the
// "Oracle Data Integrator" title text on a 404 status) must not be classified
// as ODI -- detectODI now requires a non-404 status on the console path.
func TestInfraPlugin_ODI_ConsoleBranded404NotDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/odiconsole/":
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<html><head><title>Oracle Data Integrator Console</title></head><body>404 Not Found</body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, false)
	svc, err := (&InfraPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, svc, "a branded ADF 404 page on /odiconsole/ must not be classified as ODI")
}

func TestInfraPlugin_ODIBareStatusWithoutTokenNotDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oraclediagent/agentping":
			fmt.Fprint(w, `OK`) // bare 200, no ODI-specific token
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, false)
	svc, err := (&InfraPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, svc, "a bare 200 on the agent endpoint without an ODI-specific token must not be classified as ODI")
}

// TestInfraPlugin_ODI_ReflectedProbePathNotDetected is a regression test for the
// LAB-5055 self-reflection fix: a server that reflects the requested probe path
// ("/oraclediagent/agentping", lowercase) back in its body with a non-404 status
// must not be classified as ODI. Before the fix, hasODIAgentToken accepted the
// reflective lowercase "oraclediagent" token, which any server echoing the
// unmatched request path back (e.g. a generic "no route for <path>" 200/404
// handler) would trivially satisfy, producing a false positive.
func TestInfraPlugin_ODI_ReflectedProbePathNotDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oraclediagent/agentping":
			fmt.Fprintf(w, "no route for %s", r.URL.Path) // reflects the lowercase probe path, non-404
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, false)
	svc, err := (&InfraPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, svc, "a server that merely reflects the lowercase probe path must not be classified as ODI")
}

// TestInfraPlugin_ODI_AgentPingOracleDIAgentToken confirms the positive path
// still works after the self-reflection fix: a genuine agentping body carrying
// the mixed-case "OracleDIAgent" identity string (which our lowercase probe
// path cannot reflect) is classified as ODI with anonymous access.
func TestInfraPlugin_ODI_AgentPingOracleDIAgentToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oraclediagent/agentping":
			fmt.Fprint(w, `OracleDIAgent alive`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, true)
	svc, err := (&InfraPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, plugins.ProtoOracleODI, svc.Protocol)
	assert.True(t, svc.AnonymousAccess)
}

// TestInfraPlugin_ODI_NonSuccessTokenResponseAnonFalse is a regression test for
// the finishInfra review fix: a product detected via a non-404/non-2xx
// (auth-gated) token response still emits the service and CPE, but
// AnonymousAccess must remain false and no exposure finding must be appended.
func TestInfraPlugin_ODI_NonSuccessTokenResponseAnonFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oraclediagent/agentping":
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `ODI-1battery agent alive`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, true)
	svc, err := (&InfraPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, svc, "a non-404/non-2xx token response must still emit the service/CPE")

	assert.Equal(t, plugins.ProtoOracleODI, svc.Protocol)
	assert.False(t, svc.AnonymousAccess)

	var payload plugins.ServiceOracleInfra
	require.NoError(t, json.Unmarshal(svc.Raw, &payload))
	require.Len(t, payload.CPEs, 1)

	assert.Empty(t, svc.SecurityFindings, "no exposure finding when the response was not a genuine 2xx")
}

// --- OLVM ---

func TestInfraPlugin_OLVM_BrandedViaTitleAndBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ovirt-engine/":
			fmt.Fprint(w, `<html><head><title>Oracle Linux Virtualization Manager</title></head><body>ovirt-engine</body></html>`)
		case "/ovirt-engine/api":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, true)
	svc, err := (&InfraTLSPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, svc)

	assert.Equal(t, plugins.ProtoOracleOLVM, svc.Protocol)
	assert.Equal(t, "", svc.Version) // OLVM version lives behind auth -> wildcard

	var payload plugins.ServiceOracleInfra
	require.NoError(t, json.Unmarshal(svc.Raw, &payload))
	assert.Equal(t, ProductOLVM, payload.Product)
	require.Len(t, payload.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:ovirt:ovirt-engine:*:*:*:*:*:*:*:*", payload.CPEs[0])

	require.Len(t, svc.SecurityFindings, 1)
	assert.Equal(t, "oracle-olvm-exposed", svc.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityLow, svc.SecurityFindings[0].Severity)
}

func TestInfraPlugin_OLVM_BrandedViaAPIBodyOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ovirt-engine/api":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `Oracle Linux Virtualization Manager REST API`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, false)
	svc, err := (&InfraTLSPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, plugins.ProtoOracleOLVM, svc.Protocol)
}

func TestInfraPlugin_UpstreamOVirtNotOLVM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ovirt-engine/":
			fmt.Fprint(w, `<html><head><title>oVirt Engine</title></head><body>ovirt-engine</body></html>`)
		case "/ovirt-engine/api":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, true)
	svc, err := (&InfraTLSPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, svc, "generic upstream oVirt without Oracle/OLVM branding must not be classified as OLVM")
}

// TestInfraPlugin_OLVM_401ChallengeAnonFalse is a regression test for the
// finishInfra review fix: OLVM detected via a 401 API challenge (presence)
// plus Oracle/OLVM branding -- but not a genuine 2xx on the root surface --
// still emits the service and CPE, but AnonymousAccess must remain false and
// no exposure finding must be appended.
func TestInfraPlugin_OLVM_401ChallengeAnonFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ovirt-engine/":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `<html><head><title>Oracle Linux Virtualization Manager</title></head></html>`)
		case "/ovirt-engine/api":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, true)
	svc, err := (&InfraPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, svc, "a 401 challenge + branding must still emit the service/CPE")

	assert.Equal(t, plugins.ProtoOracleOLVM, svc.Protocol)
	assert.False(t, svc.AnonymousAccess)

	var payload plugins.ServiceOracleInfra
	require.NoError(t, json.Unmarshal(svc.Raw, &payload))
	require.Len(t, payload.CPEs, 1)

	assert.Empty(t, svc.SecurityFindings, "no exposure finding when the root surface answered with a 401 challenge")
}

// --- VirtualBox web service ---

func TestVBoxWebPlugin_DetectedViaFault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vbox="http://www.virtualbox.org/"><SOAP-ENV:Body><SOAP-ENV:Fault><faultstring>vbox:InvalidObjectFault</faultstring></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>`)
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, true)
	svc, err := (&VBoxWebPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, svc)

	assert.Equal(t, plugins.ProtoVirtualBoxWeb, svc.Protocol)
	assert.Equal(t, "", svc.Version)
	// Regression (PR #384 re-review fix): VBoxWebPlugin.Run now sets
	// service.AnonymousAccess alongside the finding under Misconfigs=true.
	assert.True(t, svc.AnonymousAccess)

	var payload plugins.ServiceVirtualBoxWeb
	require.NoError(t, json.Unmarshal(svc.Raw, &payload))
	require.Len(t, payload.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:vm_virtualbox:*:*:*:*:*:*:*:*", payload.CPEs[0])

	require.Len(t, svc.SecurityFindings, 1)
	assert.Equal(t, "oracle-virtualbox-websrv-exposed", svc.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityLow, svc.SecurityFindings[0].Severity)
}

func TestVBoxWebPlugin_DetectedViaGetVersionSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vbox="http://www.virtualbox.org/"><SOAP-ENV:Body><vbox:IVirtualBox_getVersionResponse><returnval>7.0.14</returnval></vbox:IVirtualBox_getVersionResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>`)
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, false)
	svc, err := (&VBoxWebPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, plugins.ProtoVirtualBoxWeb, svc.Protocol)
	assert.False(t, svc.AnonymousAccess)  // Misconfigs=false -> AnonymousAccess stays false
	assert.Empty(t, svc.SecurityFindings) // Misconfigs=false -> no findings
}

func TestVBoxWebPlugin_GenericGSOAPNotDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><SOAP-ENV:Fault><faultstring>generic error</faultstring></SOAP-ENV:Fault></SOAP-ENV:Body></SOAP-ENV:Envelope>`)
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, true)
	svc, err := (&VBoxWebPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, svc, "generic gSOAP/other-namespace SOAP fault must not be classified as VirtualBox")
}

// TestVBoxWebPlugin_EchoOfRequestBodyNotDetected is a regression test for the
// LAB-5055 self-reflection fix: a server that echoes our own POSTed SOAP
// request body (vboxSOAPBody) back verbatim carries the vbox namespace -- via
// vboxSOAPBody's own xmlns:vbox declaration -- but no response/fault element,
// and must not be classified as VirtualBox.
func TestVBoxWebPlugin_EchoOfRequestBodyNotDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, vboxSOAPBody) // echoes our own POSTed SOAP request body verbatim
	}))
	defer srv.Close()

	conn, target := dialTestServer(t, srv, true)
	svc, err := (&VBoxWebPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, svc, "a server that echoes our request body verbatim must not be classified as VirtualBox")
}

// ---------------------------------------------------------------------------
// Misconfigs gating
// ---------------------------------------------------------------------------

func TestMisconfigsGating(t *testing.T) {
	ilomHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redfish/v1/":
			fmt.Fprint(w, `{"Vendor":"Oracle","Managers":{"@odata.id":""}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	odiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oraclediagent/agentping":
			fmt.Fprint(w, `ODI-1battery agent alive`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	olvmHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ovirt-engine/":
			fmt.Fprint(w, `<title>Oracle Linux Virtualization Manager</title>ovirt-engine`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	vboxHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `<SOAP-ENV:Fault xmlns:vbox="http://www.virtualbox.org/"><faultstring>vbox:InvalidObjectFault</faultstring></SOAP-ENV:Fault>`)
	})

	tests := []struct {
		name      string
		handler   http.HandlerFunc
		run       func(conn net.Conn, target plugins.Target) (*plugins.Service, error)
		findingID string
		wantSev   plugins.Severity
	}{
		{"ilom", ilomHandler, func(c net.Conn, tg plugins.Target) (*plugins.Service, error) {
			return (&InfraPlugin{}).Run(c, 5*time.Second, tg)
		}, "oracle-ilom-exposed", plugins.SeverityMedium},
		{"odi", odiHandler, func(c net.Conn, tg plugins.Target) (*plugins.Service, error) {
			return (&InfraPlugin{}).Run(c, 5*time.Second, tg)
		}, "oracle-odi-exposed", plugins.SeverityLow},
		{"olvm", olvmHandler, func(c net.Conn, tg plugins.Target) (*plugins.Service, error) {
			return (&InfraPlugin{}).Run(c, 5*time.Second, tg)
		}, "oracle-olvm-exposed", plugins.SeverityLow},
		{"vbox", vboxHandler, func(c net.Conn, tg plugins.Target) (*plugins.Service, error) {
			return (&VBoxWebPlugin{}).Run(c, 5*time.Second, tg)
		}, "oracle-virtualbox-websrv-exposed", plugins.SeverityLow},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/misconfigs=true", func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			conn, target := dialTestServer(t, srv, true)
			svc, err := tt.run(conn, target)
			require.NoError(t, err)
			require.NotNil(t, svc)
			require.Len(t, svc.SecurityFindings, 1)
			assert.Equal(t, tt.findingID, svc.SecurityFindings[0].ID)
			assert.Equal(t, tt.wantSev, svc.SecurityFindings[0].Severity)
			for _, f := range svc.SecurityFindings {
				assert.NotContains(t, strings.ToLower(f.ID), "ipmi")
			}
		})

		t.Run(tt.name+"/misconfigs=false", func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			conn, target := dialTestServer(t, srv, false)
			svc, err := tt.run(conn, target)
			require.NoError(t, err)
			require.NotNil(t, svc)
			assert.False(t, svc.AnonymousAccess)
			assert.Empty(t, svc.SecurityFindings)
		})
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestInfraPlugin_Metadata(t *testing.T) {
	p := &InfraPlugin{}
	assert.Equal(t, "oracle_infra", p.Name())
	assert.Equal(t, plugins.TCP, p.Type())
	assert.Equal(t, -1, p.Priority())
	assert.True(t, p.PortPriority(DefaultODIAgentPort))
	assert.True(t, p.PortPriority(80))
	assert.False(t, p.PortPriority(443))
}

func TestInfraTLSPlugin_Metadata(t *testing.T) {
	p := &InfraTLSPlugin{}
	assert.Equal(t, "oracle_infra", p.Name())
	assert.Equal(t, plugins.TCPTLS, p.Type())
	assert.Equal(t, -1, p.Priority())
	assert.True(t, p.PortPriority(443))
	assert.True(t, p.PortPriority(8443))
	assert.False(t, p.PortPriority(80))
}

func TestVBoxWebPlugin_Metadata(t *testing.T) {
	p := &VBoxWebPlugin{}
	assert.Equal(t, plugins.ProtoVirtualBoxWeb, p.Name())
	assert.Equal(t, plugins.TCP, p.Type())
	assert.Equal(t, -1, p.Priority())
	assert.True(t, p.PortPriority(DefaultVBoxWebPort))
	assert.False(t, p.PortPriority(80))
}

// ---------------------------------------------------------------------------
// TLS parity
// ---------------------------------------------------------------------------

// TestInfraTLSPlugin_ParityOverPlainConn verifies that InfraTLSPlugin.Run,
// exercised over a plain (non-TLS) mock connection, detects the same product
// as InfraPlugin against an identical server, and that plugins.CheckTLS is a
// safe no-op when the underlying conn is not a *tls.Conn (i.e. it must not
// panic and must not inject spurious generic TLS findings alongside the
// product-specific finding).
func TestInfraTLSPlugin_ParityOverPlainConn(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redfish/v1/":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"Vendor":"Oracle","Managers":{"@odata.id":""}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	plainConn, plainTarget := dialTestServer(t, srv, true)
	plainSvc, err := (&InfraPlugin{}).Run(plainConn, 5*time.Second, plainTarget)
	require.NoError(t, err)
	require.NotNil(t, plainSvc)

	tlsConn, tlsTarget := dialTestServer(t, srv, true)
	tlsSvc, err := (&InfraTLSPlugin{}).Run(tlsConn, 5*time.Second, tlsTarget)
	require.NoError(t, err)
	require.NotNil(t, tlsSvc)

	// Detection parity: same product/version regardless of transport.
	assert.Equal(t, plainSvc.Protocol, tlsSvc.Protocol)
	assert.Equal(t, plainSvc.Version, tlsSvc.Version)

	// Transport-specific TLS flag differs...
	assert.False(t, plainSvc.TLS)
	assert.True(t, tlsSvc.TLS)

	// ...but CheckTLS is a no-op on a non-*tls.Conn: exactly the product
	// finding is present, no additional generic TLS findings were appended.
	require.Len(t, plainSvc.SecurityFindings, 1)
	require.Len(t, tlsSvc.SecurityFindings, 1)
	assert.Equal(t, plainSvc.SecurityFindings[0].ID, tlsSvc.SecurityFindings[0].ID)
}

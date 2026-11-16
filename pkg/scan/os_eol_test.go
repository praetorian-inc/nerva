package scan

import (
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

type osEvidencePlugin struct{ protocol plugins.Protocol }

func (p osEvidencePlugin) Name() string             { return "snmp" }
func (p osEvidencePlugin) Type() plugins.Protocol   { return p.protocol }
func (p osEvidencePlugin) Priority() int            { return 1 }
func (p osEvidencePlugin) PortPriority(uint16) bool { return true }
func (p osEvidencePlugin) Run(_ net.Conn, _ time.Duration, target plugins.Target) (*plugins.Service, error) {
	return plugins.CreateServiceFrom(target, plugins.ServiceSNMP{Description: "FreeBSD 12.4-RELEASE"}, false, "", p.protocol), nil
}

func TestPluginRunner_EnrichesSerializedOSResults(t *testing.T) {
	for _, protocol := range []plugins.Protocol{plugins.TCP, plugins.UDP} {
		client, server := net.Pipe()
		target := plugins.Target{Address: netip.MustParseAddrPort("127.0.0.1:161")}
		result, err := simplePluginRunner(client, target, &Config{Misconfigs: true}, osEvidencePlugin{protocol})
		server.Close()
		if err != nil {
			t.Fatal(err)
		}
		result.EnrichFindings()
		output, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		for _, expected := range []string{`"cpes":["cpe:2.3:o:freebsd:freebsd:12.4:`, `"id":"os-eol"`, `"title":"Vendor-Unsupported Operating System"`, "FreeBSD 12.4-RELEASE"} {
			if !strings.Contains(string(output), expected) {
				t.Fatalf("missing %s in %s", expected, output)
			}
		}
	}
}

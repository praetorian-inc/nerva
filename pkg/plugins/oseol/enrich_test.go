package oseol

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestEnrich_OSInventoryAndEOL(t *testing.T) {
	oldNow := now
	now = func() time.Time { return date(2026, time.July, 1) }
	t.Cleanup(func() { now = oldNow })
	tests := []struct {
		name, protocol, metadata, cpe, finding, evidence string
	}{
		{"ubuntu ssh", "ssh", `{"banner":"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10"}`, "canonical:ubuntu_linux:16.04:", "os-eol", "OpenSSH_7.2"},
		{"centos http", "http", `{"response_headers":{"Server":["Apache/2.4.6 (CentOS)"]}}`, "centos:centos:7:", "os-eol", "CentOS"},
		{"fedora package", "ssh", `{"banner":"SSH-2.0-OpenSSH_9.0p1-1.fc38"}`, "fedoraproject:fedora:38:", "os-eol", ".fc38"},
		{"freebsd ftp", "ftp", `{"banner":"220 FreeBSD 12.4-RELEASE FTP server"}`, "freebsd:freebsd:12.4:", "os-eol", "FreeBSD 12.4"},
		{"cisco snmp", "snmp", `{"description":"Cisco IOS XE Software, Version 17.3.5, C9300 switch"}`, "cisco:ios_xe:17.3.5:", "os-eol", "17.3.5"},
		{"old fedora", "ftp", `{"banner":"220 FTP Fedora release 20"}`, "fedoraproject:fedora:20:", "os-eol", "Fedora"},
		{"old freebsd", "ftp", `{"banner":"220 FTP FreeBSD 8.4-RELEASE"}`, "freebsd:freebsd:8.4:", "os-eol", "FreeBSD"},
		{"iosxe extended banner", "snmp", `{"description":"Cisco IOS Software [IOS XE], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.6.5, RELEASE SOFTWARE"}`, "cisco:ios_xe:17.6.5:", "os-eol", "17.6.5"},
		{"windows iis6", "http", `{"response_headers":{"Server":["Microsoft-IIS/6.0"]}}`, "", "os-eol", "Server 2003"},
		{"windows smb", "smb", `{"os_version":"5.2.3790"}`, "", "os-eol", "NTLM version 5.2.3790"},
		{"windows rdp", "rdp", `{"fingerprint":"Windows Server 2003"}`, "microsoft:windows_server_2003:*:", "rdp-eol-os", "signature inference"},
		{"supported ubuntu", "https", `{"response_headers":{"Server":["Apache/2.4.58 (Ubuntu)"]}}`, "canonical:ubuntu_linux:24.04:", "", ""},
		{"unlisted ubuntu", "ssh", `{"banner":"Ubuntu 99.99"}`, "canonical:ubuntu_linux:99.99:", "", ""},
		{"stream not linux", "snmp", `{"description":"CentOS Stream 9"}`, "centos:centos_stream:9:", "", ""},
		{"freebsd release not openssh", "ssh", `{"banner":"SSH-2.0-OpenSSH_9.5 FreeBSD-20231004"}`, "", "", ""},
		{"iis inference cannot override explicit OS", "http", `{"response_headers":{"Server":["Microsoft-IIS/6.0 Ubuntu 24.04"]}}`, "canonical:ubuntu_linux:24.04:", "", ""},
		{"iis10 ambiguous", "http", `{"response_headers":{"Server":["Microsoft-IIS/10.0"]}}`, "", "", ""},
		{"nt10 ambiguous", "smb", `{"os_version":"10.0.17763"}`, "", "", ""},
		{"windows signature ambiguous", "rdp", `{"fingerprint":"Windows Server 2016 or 2019"}`, "", "", ""},
		{"cisco AP exception", "snmp", `{"description":"Cisco IOS XE Software, Version 17.3.5 Aironet access point"}`, "cisco:ios_xe:17.3.5:", "", ""},
		{"cisco unknown device", "http", `{"cpes":["cpe:2.3:o:cisco:ios_xe:17.3.5:*:*:*:*:*:*:*"]}`, "cisco:ios_xe:17.3.5:", "", ""},
		{"conflicting families", "ftp", `{"banner":"FreeBSD 12.4-RELEASE Ubuntu 24.04"}`, "", "", ""},
		{"generic linux", "http", `{"cpes":["cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"]}`, "", "", ""},
		{"fedora cpe", "http", `{"cpes":["cpe:2.3:o:fedoraproject:fedora:38:*:*:*:*:*:*:*"]}`, "fedoraproject:fedora:38:", "os-eol", "cpe:2.3"},
		{"freebsd phpinfo", "http", `{"fingerprint_metadata":{"php":{"system":"FreeBSD host 12.4-RELEASE FreeBSD 12.4-RELEASE"}}}`, "freebsd:freebsd:12.4:", "os-eol", "12.4"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := &plugins.Service{Protocol: tc.protocol, Raw: json.RawMessage(tc.metadata)}
			Enrich(service, true)
			if tc.cpe != "" && !strings.Contains(string(service.Raw), tc.cpe) {
				t.Fatalf("missing CPE %s in %s", tc.cpe, service.Raw)
			}
			if tc.finding == "" {
				if len(service.SecurityFindings) != 0 {
					t.Fatalf("unexpected findings: %+v", service.SecurityFindings)
				}
			} else {
				if len(service.SecurityFindings) != 1 || service.SecurityFindings[0].ID != tc.finding {
					t.Fatalf("findings: %+v", service.SecurityFindings)
				}
				if !strings.Contains(service.SecurityFindings[0].Description, tc.evidence) {
					t.Fatalf("lost evidence: %+v", service.SecurityFindings)
				}
				if !strings.Contains(service.SecurityFindings[0].Description, "https://") {
					t.Fatal("missing lifecycle source")
				}
			}
			before, _ := json.Marshal(service)
			Enrich(service, true)
			after, _ := json.Marshal(service)
			if string(before) != string(after) {
				t.Fatalf("not idempotent:\n%s\n%s", before, after)
			}
		})
	}
}

func TestEnrich_NoMisconfigsStillRecordsOS(t *testing.T) {
	service := &plugins.Service{Protocol: "ftp", Raw: json.RawMessage(`{"banner":"FreeBSD 12.4-RELEASE FTP server","cpes":["cpe:2.3:a:proftpd:proftpd:1.3:*:*:*:*:*:*:*"],"extra":"keep"}`)}
	Enrich(service, false)
	if len(service.SecurityFindings) != 0 {
		t.Fatal("findings without --misconfigs")
	}
	for _, expected := range []string{"freebsd:freebsd:12.4:", "proftpd:proftpd:1.3:", `"extra":"keep"`} {
		if !strings.Contains(string(service.Raw), expected) {
			t.Fatalf("missing %s in %s", expected, service.Raw)
		}
	}
}

func TestEnrich_ConflictingReleasesDoNotEmitEOL(t *testing.T) {
	service := &plugins.Service{Protocol: "ssh", Raw: json.RawMessage(`{"banner":"Ubuntu 24.04","cpes":["cpe:2.3:o:canonical:ubuntu_linux:16.04:*:*:*:*:*:*:*"]}`)}
	Enrich(service, true)
	if len(service.SecurityFindings) != 0 {
		t.Fatalf("conflict emitted %+v", service.SecurityFindings)
	}
}

func TestEnrich_Telnet(t *testing.T) {
	raw, _ := json.Marshal(map[string]string{"server_data": hex.EncodeToString([]byte("FreeBSD 12.4-RELEASE login:"))})
	service := &plugins.Service{Protocol: "telnet", Raw: raw}
	Enrich(service, true)
	if len(service.SecurityFindings) != 1 {
		t.Fatalf("findings: %+v", service.SecurityFindings)
	}
}

func TestEnrich_LifecycleBoundary(t *testing.T) {
	oldNow := now
	t.Cleanup(func() { now = oldNow })
	for _, tc := range []struct {
		at   time.Time
		want bool
	}{
		{date(2024, time.May, 21), false},
		{date(2024, time.May, 22), true},
	} {
		now = func() time.Time { return tc.at }
		service := &plugins.Service{Protocol: "snmp", Raw: json.RawMessage(`{"description":"Fedora 38"}`)}
		Enrich(service, true)
		if (len(service.SecurityFindings) > 0) != tc.want {
			t.Fatalf("at %s: %+v", tc.at, service.SecurityFindings)
		}
	}
}

package oseol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestIdentifyVersionIndependentBanners(t *testing.T) {
	for _, tc := range []struct{ text, product, version string }{
		{"Windows Server 2099", "windows_server_2099", "*"},
		{"windows server 2099 r2", "windows_server_2099_r2", "*"},
		{"Windows Server 2008 R3", "windows_server_2008_r3", "*"},
		{"Ubuntu 99.99", "ubuntu_linux", "99.99"},
		{"Fedora release 999", "fedora", "999"},
		{"SSH-2.0-OpenSSH_99.1 Debian-1+deb99u1", "debian_linux", "99"},
	} {
		t.Run(tc.text, func(t *testing.T) {
			observed := identifyText(tc.text)
			if len(observed) != 1 || observed[0].product != tc.product || observed[0].version != tc.version {
				t.Fatalf("unexpected identity: %+v", observed)
			}
			if finding := observed[0].finding(nil); finding != nil {
				t.Fatalf("unknown release must remain inventory: %+v", finding)
			}
		})
	}
}

func TestFutureWindowsReleaseNeedsOnlyLifecycleData(t *testing.T) {
	original, originalNow := lifecycleData, now
	t.Cleanup(func() { lifecycleData, now = original, originalNow })
	end := "2100-01-01"
	lifecycleData = lifecycleSnapshot{Products: map[string]lifecycleProduct{
		"windows-server": {Source: "https://feed.example", VendorURL: "https://vendor.example",
			Releases: map[string]*string{"2099": &end}},
	}}
	now = func() time.Time { return date(2100, time.January, 2) }
	service := &plugins.Service{Protocol: "snmp", Raw: json.RawMessage(`{"description":"Windows Server 2099"}`)}
	Enrich(service, true)
	if !strings.Contains(string(service.Raw), "microsoft:windows_server_2099:*") || len(service.SecurityFindings) != 1 {
		t.Fatalf("new release required a code change: %+v, %s", service.SecurityFindings, service.Raw)
	}
}

func TestStructuredIdentityOutranksPackageInference(t *testing.T) {
	original := now
	now = func() time.Time { return date(2026, time.July, 1) }
	t.Cleanup(func() { now = original })
	service := &plugins.Service{Protocol: "ssh", Raw: json.RawMessage(`{"banner":"OpenSSH_7.2p2 Ubuntu-4ubuntu2.10","cpes":["cpe:2.3:o:canonical:ubuntu_linux:24.04:*:*:*:*:*:*:*"]}`)}
	Enrich(service, true)
	if len(service.SecurityFindings) != 0 || strings.Contains(string(service.Raw), "ubuntu_linux:16.04:") {
		t.Fatalf("package heuristic overrode the explicit OS CPE: %s %+v", service.Raw, service.SecurityFindings)
	}
}

func TestUnmappedStructuredOSSuppressesWindowsGuess(t *testing.T) {
	service := &plugins.Service{Protocol: "http", Raw: json.RawMessage(`{"response_headers":{"Server":["Microsoft-IIS/6.0"]},"cpes":["cpe:2.3:o:alpinelinux:alpine_linux:3.24:*:*:*:*:*:*:*"]}`)}
	Enrich(service, true)
	if len(service.SecurityFindings) != 0 || !strings.Contains(string(service.Raw), "alpine_linux:3.24:") {
		t.Fatalf("unmapped structured OS was replaced by a guess: %s %+v", service.Raw, service.SecurityFindings)
	}
}

func TestCPEAliasesAndReleaseMappings(t *testing.T) {
	for _, tc := range []struct{ cpe, canonical, feed, release string }{
		{"cpe:/o:canonical:ubuntu:20.04", "ubuntu_linux", "ubuntu", "20.04"},
		{"cpe:2.3:o:redhat:enterprise_linux_server:7.9:*:*:*:*:*:*:*", "enterprise_linux", "rhel", "7"},
		{"cpe:/o:centos:centos_stream:9", "centos_stream", "centos-stream", "9"},
		{"cpe:/o:microsoft:windows_server_2008_r2", "windows_server_2008_r2", "windows-server", "2008-r2"},
		{"cpe:/o:microsoft:windows_server_2099_r2", "windows_server_2099_r2", "windows-server", "2099-r2"},
		{"cpe:/o:cisco:ios_xe:17.9.4", "ios_xe", "cisco-ios-xe", "17.9"},
	} {
		t.Run(tc.cpe, func(t *testing.T) {
			observed, ok := identifyCPE(tc.cpe)
			if !ok || observed.product != tc.canonical {
				t.Fatalf("wrong canonical identity: %+v", observed)
			}
			definition := findProduct(observed.vendor, observed.product)
			if definition.feed != tc.feed || definition.release(observed.product, observed.version) != tc.release {
				t.Fatalf("wrong lifecycle mapping for %+v", observed)
			}
		})
	}
}

func TestMalformedOrUnreviewedCPEIsNotAnOSIdentity(t *testing.T) {
	for _, cpe := range []string{
		"cpe:2.3:o:canonical:ubuntu_linux:16.04", // Not a complete formatted CPE.
		"cpe:/o:canonical:fake_ubuntu_product:16.04",
		"cpe:/a:canonical:ubuntu_linux:16.04",
		"cpe:/a:redhat:openssl:1.el7",
		"cpe:/o:microsoft:windows_server_unknown:*",
		"cpe:/o:microsoft:windows_server_2008_evil:*",
		"cpe:/o:canonical:ubuntu_linux:*",
		"cpe:/o:canonical:ubuntu_linux:16.04:extra:fields:are:invalid",
	} {
		if observed, ok := identifyCPE(cpe); ok {
			t.Fatalf("accepted invalid/unreviewed CPE %q: %+v", cpe, observed)
		}
		if finding := Check(cpe); finding != nil {
			t.Fatalf("legacy checker bypassed structured parsing for %q: %+v", cpe, finding)
		}
	}
}

func TestBannerEvidenceIsBounded(t *testing.T) {
	if observed := identifyText(strings.Repeat("x", maxEvidenceBytes) + " Windows Server 2003"); len(observed) != 0 {
		t.Fatalf("matched evidence beyond the size bound: %+v", observed)
	}
}

func TestWindowsDecoderDoesNotChooseLastConflictingHeader(t *testing.T) {
	for _, headers := range [][]string{
		{"Microsoft-IIS/6.0", "Microsoft-IIS/8.0"},
		{"Microsoft-IIS/8.0", "Microsoft-IIS/6.0"},
		{"Microsoft-IIS/6.0", "Microsoft-IIS/10.0"},
		{"Microsoft-IIS/10.0", "Microsoft-IIS/6.0"},
	} {
		if evidence := identifyWindowsEvidence("http", nil, headers); evidence != nil {
			t.Fatalf("conflicting/ambiguous versions produced a candidate: %+v", evidence)
		}
	}
}

func TestLegacyCheckSharesConflictHandling(t *testing.T) {
	if finding := Check("Ubuntu 16.04", "Ubuntu 24.04"); finding != nil {
		t.Fatalf("legacy API bypassed shared conflict handling: %+v", finding)
	}
}

func TestPackageInferenceDoesNotOverrideExplicitDistroRelease(t *testing.T) {
	observed := identifyText("Apache/2.4.6 (Red Hat 8)")
	if len(observed) != 1 || observed[0].version != "8" {
		t.Fatalf("Apache inference overrode the stated release: %+v", observed)
	}
	if observed := identifyText("OpenSSH (CentOS Stream) package.el7"); len(observed) != 0 {
		t.Fatalf("CentOS Stream reused CentOS Linux lifecycle: %+v", observed)
	}
}

func TestUbuntuPackageReleaseSuffix(t *testing.T) {
	for _, banner := range []string{
		"SSH-2.0-OpenSSH_99.1p1 Ubuntu-1ubuntu0.16.04.1",
		"nginx/1.10.3-0ubuntu0.16.04.2",
		"SSH-2.0-OpenSSH_8.9p1 Ubuntu-1ubuntu0.16.04.1", // Explicit package release outranks shipped-version guesses.
	} {
		observed := identifyText(banner)
		if len(observed) != 1 || observed[0].product != "ubuntu_linux" || observed[0].version != "16.04" {
			t.Fatalf("lost Ubuntu package release in %q: %+v", banner, observed)
		}
	}
}

func TestConflictingELPackageReleases(t *testing.T) {
	for _, banner := range []string{
		"Red Hat Enterprise Linux packages: openssh.el7 openssl.el8",
		"CentOS packages: openssl.el8 openssh.el7",
	} {
		if finding := Check(banner); finding != nil {
			t.Fatalf("selected one conflicting package release: %+v", finding)
		}
	}
}

func TestWindowsDecoderRejectsMalformedNTLMVersions(t *testing.T) {
	for _, version := range []string{"6.1.7601oops", "6.1", "6.1.7601.1", "-6.1.7601"} {
		raw, _ := json.Marshal(version)
		metadata := map[string]json.RawMessage{"os_version": raw}
		if evidence := identifyWindowsEvidence("smb", metadata, nil); evidence != nil {
			t.Fatalf("malformed NTLM version %q produced %+v", version, evidence)
		}
	}
}

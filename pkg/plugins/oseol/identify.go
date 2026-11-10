package oseol

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// observation is an identification, not a claim that the host is unsupported.
// Lifecycle lookup is deliberately separate: an unlisted release is still inventory.
type observation struct {
	vendor, product, version string
	name, evidence, method   string
}

var osPatterns = []struct {
	pattern               *regexp.Regexp
	vendor, product, name string
}{
	{regexp.MustCompile(`(?i)\bUbuntu(?: Linux)?[ /]+(\d{2}\.\d{2})(?:\.\d+)?\b`), "canonical", "ubuntu_linux", "Ubuntu"},
	{regexp.MustCompile(`(?i)\bCentOS(?: Linux)?(?: release)?[ /]+(\d+(?:\.\d+)*)\b`), "centos", "centos", "CentOS Linux"},
	{regexp.MustCompile(`(?i)\bCentOS Stream(?: release)?[ /]+(\d+)\b`), "centos", "centos_stream", "CentOS Stream"},
	{regexp.MustCompile(`(?i)\bFedora(?: Linux| Core)?(?: release)?[ /]+(\d+)\b`), "fedoraproject", "fedora", "Fedora"},
	{regexp.MustCompile(`(?i)\bFreeBSD[ /]+(\d+\.\d+)(?:-RELEASE(?:-p\d+)?)?\b`), "freebsd", "freebsd", "FreeBSD"},
	{regexp.MustCompile(`(?i)\bDebian(?: GNU/Linux)?[ /]+(\d+(?:\.\d+)*)\b`), "debian", "debian_linux", "Debian"},
	{regexp.MustCompile(`(?i)\bRed Hat Enterprise Linux(?: Server)?(?: release)?[ /]+(\d+(?:\.\d+)*)\b`), "redhat", "enterprise_linux", "RHEL"},
	{regexp.MustCompile(`(?i)\bCisco IOS[ -]XE Software,?\s+Version\s+(\d+\.\d+(?:\.\d+)?[a-z]?)\b`), "cisco", "ios_xe", "Cisco IOS XE"},
	{regexp.MustCompile(`(?i)\bCisco Adaptive Security Appliance Software Version\s+(\d+\.\d+(?:\(\d+\))?(?:\d+)?)`), "cisco", "adaptive_security_appliance_software", "Cisco ASA"},
}

var iosXEBanner = regexp.MustCompile(`(?i)Cisco IOS Software\s*\[IOS XE[^\]]*\][^\r\n]{0,200}?\bVersion\s+(\d+\.\d+(?:\.\d+)?[a-z]?)\b`)

var windowsRelease = regexp.MustCompile(`(?i)\bWindows Server[ /]+(2003|2008|2012|2016|2019|2022|2025)( R2)?\b`)
var fedoraPackage = regexp.MustCompile(`(?i)\b(?:Fedora\b.*)?[^\s]*\.fc(\d+)\b`)
var iisVersion = regexp.MustCompile(`(?i)\bMicrosoft-IIS/(\d+\.\d+)\b`)
var versionToken = regexp.MustCompile(`^[0-9][0-9a-zA-Z._()\-]*$`)

func identifyText(text string) []observation {
	if len(text) > 4096 {
		text = text[:4096]
	}
	var found []observation
	if match := iosXEBanner.FindStringSubmatch(text); match != nil {
		found = append(found, observation{"cisco", "ios_xe", match[1], "Cisco IOS XE " + match[1], match[0], "reported release"})
	}
	for _, rule := range osPatterns {
		for _, match := range rule.pattern.FindAllStringSubmatch(text, -1) {
			found = append(found, observation{rule.vendor, rule.product, match[1], rule.name + " " + match[1], match[0], "reported release"})
		}
	}
	for _, match := range windowsRelease.FindAllStringSubmatch(text, -1) {
		product := "windows_server_" + match[1]
		if match[2] != "" {
			product += "_r2"
		}
		found = append(found, observation{"microsoft", product, "*", match[0], match[0], "reported release"})
	}
	if len(found) > 0 {
		return found
	}
	if match := fedoraPackage.FindStringSubmatch(text); match != nil {
		return []observation{{"fedoraproject", "fedora", match[1], "Fedora " + match[1], match[0], "Fedora package release marker"}}
	}
	// Existing distro-package heuristics are retained, but their basis is visible
	// in the proof rather than presented as a directly reported OS release.
	if rel, _ := identify(text); rel != nil {
		vendor, product := linuxProduct(rel.family)
		return []observation{{vendor, product, rel.version, rel.name, strings.TrimSpace(text), "banner/package inference"}}
	}
	return nil
}

func identifyCPE(value string) (observation, bool) {
	var part, vendor, product, version string
	if strings.HasPrefix(value, "cpe:2.3:") {
		fields := strings.Split(value, ":")
		if len(fields) != 13 {
			return observation{}, false
		}
		part, vendor, product, version = fields[2], fields[3], fields[4], fields[5]
	} else if strings.HasPrefix(value, "cpe:/") {
		fields := strings.Split(strings.TrimPrefix(value, "cpe:/"), ":")
		if len(fields) < 3 {
			return observation{}, false
		}
		part, vendor, product = fields[0], fields[1], fields[2]
		version = "*"
		if len(fields) > 3 {
			version = fields[3]
		}
	} else {
		return observation{}, false
	}
	if part != "o" && !(part == "a" && vendor == "cisco" && product == "firepower_threat_defense") {
		return observation{}, false
	}
	name := productName(vendor, product)
	if name == "" || (version != "*" && !versionToken.MatchString(version)) {
		return observation{}, false
	}
	if version == "*" && !strings.HasPrefix(product, "windows_server_") {
		return observation{}, false
	}
	return observation{vendor, product, version, name, value, "scanner CPE"}, true
}

func linuxProduct(f family) (string, string) {
	switch f {
	case familyUbuntu:
		return "canonical", "ubuntu_linux"
	case familyDebian:
		return "debian", "debian_linux"
	case familyRHEL:
		return "redhat", "enterprise_linux"
	case familyCentOS:
		return "centos", "centos"
	}
	return "", ""
}

func productName(vendor, product string) string {
	switch vendor + ":" + product {
	case "canonical:ubuntu_linux":
		return "Ubuntu"
	case "debian:debian_linux":
		return "Debian"
	case "redhat:enterprise_linux":
		return "RHEL"
	case "centos:centos":
		return "CentOS Linux"
	case "centos:centos_stream":
		return "CentOS Stream"
	case "fedoraproject:fedora":
		return "Fedora"
	case "freebsd:freebsd":
		return "FreeBSD"
	case "cisco:ios_xe":
		return "Cisco IOS XE"
	case "cisco:adaptive_security_appliance_software":
		return "Cisco ASA"
	case "cisco:firepower_threat_defense":
		return "Cisco FTD"
	}
	if vendor == "microsoft" && strings.HasPrefix(product, "windows_server_") {
		return strings.ReplaceAll(product, "_", " ")
	}
	return ""
}

func (o observation) cpe() string {
	part := "o"
	if o.product == "firepower_threat_defense" {
		part = "a"
	}
	return fmt.Sprintf("cpe:2.3:%s:%s:%s:%s:*:*:*:*:*:*:*", part, o.vendor, o.product, o.version)
}

func (o observation) lifecycle() (time.Time, string) {
	product, version := "", o.version
	switch o.vendor + ":" + o.product {
	case "canonical:ubuntu_linux":
		product, version = "ubuntu", ubuntuVersion(version)
	case "debian:debian_linux":
		product, version = "debian", major(version)
	case "redhat:enterprise_linux":
		product, version = "rhel", major(version)
	case "centos:centos":
		product, version = "centos", major(version)
	case "centos:centos_stream":
		product, version = "centos-stream", major(version)
	case "fedoraproject:fedora":
		product = "fedora"
	case "freebsd:freebsd":
		product = "freebsd"
	case "cisco:ios_xe":
		parts := strings.Split(version, ".")
		if len(parts) < 2 {
			return time.Time{}, ""
		}
		product, version = "cisco-ios-xe", strings.Join(parts[:2], ".")
	default:
		if o.vendor == "microsoft" && strings.HasPrefix(o.product, "windows_server_") {
			product = "windows-server"
			version = strings.ReplaceAll(strings.TrimPrefix(o.product, "windows_server_"), "_", "-")
		}
	}
	return lifecycleEnd(product, version)
}

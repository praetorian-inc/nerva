package oseol

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// productDefinition is reviewed identification policy, not downloaded lifecycle
// data. One entry owns CPE identity, aliases, banner grammar and release mapping.
// Patterns extract versions; they never enumerate supported/EOL releases.
type productDefinition struct {
	vendor, product, name string
	part, feed            string
	legacyCheck           bool
	aliases               []string
	normalizeRelease      func(string) string
	banners               []*regexp.Regexp
	productPattern        *regexp.Regexp // Release encoded in the CPE product name.
	productPrefix         string
	eligibleEvidence      func([]string) bool
}

var products = []productDefinition{
	{
		vendor: "canonical", product: "ubuntu_linux", name: "Ubuntu", part: "o", feed: "ubuntu", legacyCheck: true,
		aliases: []string{"canonical:ubuntu"}, normalizeRelease: ubuntuVersion,
		banners: []*regexp.Regexp{regexp.MustCompile(`(?i)\bUbuntu(?: Linux)?[ /]+(\d{2}\.\d{2})(?:\.\d+)?\b`)},
	},
	{
		vendor: "debian", product: "debian_linux", name: "Debian", part: "o", feed: "debian", legacyCheck: true,
		normalizeRelease: major,
		banners:          []*regexp.Regexp{regexp.MustCompile(`(?i)\bDebian(?: GNU/Linux)?[ /]+(\d+(?:\.\d+)*)\b`)},
	},
	{
		vendor: "redhat", product: "enterprise_linux", name: "RHEL", part: "o", feed: "rhel", legacyCheck: true,
		aliases: []string{"redhat:enterprise_linux_server"}, normalizeRelease: major,
		banners: []*regexp.Regexp{regexp.MustCompile(`(?i)\bRed Hat(?: Enterprise Linux)?(?: Server)?(?: release)?[ /]+(\d+(?:\.\d+)*)\b`)},
	},
	{
		vendor: "centos", product: "centos", name: "CentOS Linux", part: "o", feed: "centos", legacyCheck: true,
		normalizeRelease: major,
		banners:          []*regexp.Regexp{regexp.MustCompile(`(?i)\bCentOS(?: Linux)?(?: release)?[ /]+(\d+(?:\.\d+)*)\b`)},
	},
	{
		vendor: "centos", product: "centos_stream", name: "CentOS Stream", part: "o", feed: "centos-stream",
		normalizeRelease: major,
		banners:          []*regexp.Regexp{regexp.MustCompile(`(?i)\bCentOS Stream(?: release)?[ /]+(\d+)\b`)},
	},
	{
		vendor: "fedoraproject", product: "fedora", name: "Fedora", part: "o", feed: "fedora",
		banners: []*regexp.Regexp{regexp.MustCompile(`(?i)\bFedora(?: Linux| Core)?(?: release)?[ /]+(\d+)\b`)},
	},
	{
		vendor: "freebsd", product: "freebsd", name: "FreeBSD", part: "o", feed: "freebsd",
		banners: []*regexp.Regexp{regexp.MustCompile(`(?i)\bFreeBSD[ /]+(\d+\.\d+)(?:-RELEASE(?:-p\d+)?)?\b`)},
	},
	{
		vendor: "microsoft", name: "Windows Server", part: "o", feed: "windows-server",
		productPrefix:  "windows_server_",
		productPattern: regexp.MustCompile(`^windows_server_(\d{4}(?:_r\d+)?)$`),
		banners:        []*regexp.Regexp{regexp.MustCompile(`(?i)\bWindows Server[ /]+(\d{4}(?:[ _-]+R\d+)?)\b`)},
	},
	{
		vendor: "cisco", product: "ios_xe", name: "Cisco IOS XE", part: "o", feed: "cisco-ios-xe",
		normalizeRelease: minorRelease, eligibleEvidence: ciscoRouterOrSwitch,
		banners: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\bCisco IOS[ -]XE Software,?\s+Version\s+(\d+\.\d+(?:\.\d+)?[a-z]?)\b`),
			regexp.MustCompile(`(?i)Cisco IOS Software\s*\[IOS XE[^\]]*\][^\r\n]{0,200}?\bVersion\s+(\d+\.\d+(?:\.\d+)?[a-z]?)\b`),
		},
	},
	{
		vendor: "cisco", product: "adaptive_security_appliance_software", name: "Cisco ASA", part: "o",
		banners: []*regexp.Regexp{regexp.MustCompile(`(?i)\bCisco Adaptive Security Appliance Software Version\s+(\d+\.\d+(?:\(\d+\))?(?:\d+)?)`)},
	},
	{vendor: "cisco", product: "firepower_threat_defense", name: "Cisco FTD", part: "a"},
}

func findProduct(vendor, product string) *productDefinition {
	identity := strings.ToLower(vendor + ":" + product)
	for i := range products {
		definition := &products[i]
		if (definition.product != "" && identity == definition.vendor+":"+definition.product) || slices.Contains(definition.aliases, identity) {
			return definition
		}
		if strings.EqualFold(vendor, definition.vendor) && definition.productPattern != nil && definition.productPattern.MatchString(strings.ToLower(product)) {
			return definition
		}
	}
	return nil
}

func (p *productDefinition) identifyBanner(text string) []observation {
	var observations []observation
	for _, pattern := range p.banners {
		for _, match := range pattern.FindAllStringSubmatch(text, -1) {
			observations = append(observations, p.observed(match[1], match[0], "reported release"))
		}
	}
	return observations
}

func (p *productDefinition) observed(version, evidence, method string) observation {
	product := p.product
	if p.productPattern != nil {
		product = p.productPrefix + strings.Join(strings.Fields(strings.NewReplacer("_", " ", "-", " ").Replace(strings.ToLower(version))), "_")
		version = "*"
	}
	return observation{vendor: p.vendor, product: product, version: version, evidence: evidence, method: method}
}

func (p *productDefinition) release(product, version string) string {
	if p.productPattern != nil {
		match := p.productPattern.FindStringSubmatch(strings.ToLower(product))
		if match == nil {
			return ""
		}
		return strings.ReplaceAll(match[1], "_", "-")
	}
	if p.normalizeRelease != nil {
		return p.normalizeRelease(version)
	}
	return version
}

func (p *productDefinition) displayName(product string) string {
	if p.productPattern != nil {
		return p.name + " " + strings.ToUpper(strings.ReplaceAll(strings.TrimPrefix(product, p.productPrefix), "_", " "))
	}
	return p.name
}

func minorRelease(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) < 2 || major(parts[0]) == "" || major(parts[1]) == "" {
		return ""
	}
	return strings.Join(parts[:2], ".")
}

func ubuntuVersion(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) >= 2 && len(parts[0]) == 2 && len(parts[1]) == 2 {
		return minorRelease(version)
	}
	return ""
}

func major(version string) string {
	if i := strings.IndexAny(version, ".-"); i > 0 {
		version = version[:i]
	}
	if _, err := strconv.Atoi(version); err != nil {
		return ""
	}
	return version
}

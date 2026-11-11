package oseol

import (
	"regexp"
	"strings"
)

// Package versions are fallback evidence, not lifecycle facts. These reviewed
// Ubuntu mappings describe the packages shipped by each LTS; Debian Apache patch
// versions are deliberately not mapped because security updates change them.
var packageRules = []struct {
	feed, requiredToken string
	pattern             *regexp.Regexp
	releases            map[string]string
}{
	{feed: "fedora", pattern: regexp.MustCompile(`(?i)\b[^\s]*\.fc(\d+)\b`)},
	{feed: "debian", pattern: regexp.MustCompile(`(?i)\+deb(\d+)`)},
	{feed: "ubuntu", pattern: regexp.MustCompile(`(?i)ubuntu(?:0\.)?(\d{2}\.\d{2})\b`)},
	{
		feed: "ubuntu", requiredToken: "ubuntu", pattern: regexp.MustCompile(`(?i)OpenSSH_(\d+\.\d+)p`),
		releases: map[string]string{"6.6": "14.04", "7.2": "16.04", "7.6": "18.04", "8.2": "20.04", "8.9": "22.04", "9.6": "24.04"},
	},
	{
		feed: "ubuntu", pattern: regexp.MustCompile(`(?i)Apache/(\d+\.\d+\.\d+)\s*\(Ubuntu\)`),
		releases: map[string]string{"2.4.7": "14.04", "2.4.18": "16.04", "2.4.29": "18.04", "2.4.41": "20.04", "2.4.52": "22.04", "2.4.58": "24.04"},
	},
}

var elPackage = regexp.MustCompile(`(?i)\.el(\d+)(?:_\d+)?\b`)
var elFamilies = []struct {
	feed    string
	pattern *regexp.Regexp
}{
	{"centos", regexp.MustCompile(`(?i)\bCentOS(?: Linux)?\b`)},
	{"rhel", regexp.MustCompile(`(?i)\b(?:Red Hat(?: Enterprise Linux)?|RedHat)\b`)},
}
var elApache = regexp.MustCompile(`(?i)Apache/2\.4\.6\b`)

func identifyPackages(text string) []observation {
	var observations, inferred []observation
	for _, rule := range packageRules {
		if !strings.Contains(strings.ToLower(text), rule.requiredToken) {
			continue
		}
		for _, match := range rule.pattern.FindAllStringSubmatch(text, -1) {
			version := match[1]
			if rule.releases == nil {
				observations = append(observations, packageObservation(rule.feed, version, match[0]))
			} else if version = rule.releases[version]; version != "" {
				inferred = append(inferred, packageObservation(rule.feed, version, match[0]))
			}
		}
	}
	if len(observations) > 0 {
		return observations // Explicit distro release tags outrank shipped-package guesses.
	}
	return append(inferred, identifyELPackage(text)...)
}

func identifyELPackage(text string) []observation {
	// .elN is shared by rebuilds. Require an explicit distro name, and never
	// reinterpret CentOS Stream as CentOS Linux.
	if strings.Contains(strings.ToLower(text), "centos stream") {
		return nil
	}
	var versions []string
	for _, match := range elPackage.FindAllStringSubmatch(text, -1) {
		versions = append(versions, match[1])
	}
	if len(versions) == 0 && elApache.MatchString(text) {
		versions = []string{"7"} // RHEL/CentOS 7 shipped Apache 2.4.6.
	}
	var observations []observation
	for _, distro := range elFamilies {
		if !distro.pattern.MatchString(text) {
			continue
		}
		for _, version := range versions {
			observations = append(observations, packageObservation(distro.feed, version, text))
		}
	}
	return observations
}

func packageObservation(feed, version, text string) observation {
	for i := range products {
		if products[i].feed == feed {
			return products[i].observed(version, strings.TrimSpace(text), "package release inference")
		}
	}
	panic("unregistered package-inference product: " + feed)
}

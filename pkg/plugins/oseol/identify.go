package oseol

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Identification is independent of lifecycle coverage. An unknown release can
// be inventory without becoming an unsupported-OS finding.
type observation struct {
	vendor, product, version string
	evidence, method         string
}

const maxEvidenceBytes = 4096

var versionToken = regexp.MustCompile(`^[0-9][0-9a-zA-Z._()\-]*$`)
var cpeIdentityToken = regexp.MustCompile(`^[a-z0-9_.-]+$`)

// Prefer structured OS identity over package-version heuristics. Explicit,
// conflicting release statements still reach consistency checks and suppress a
// verdict. An unmapped but explicit OS CPE must not fall back to an IIS guess.
func identifyService(cpes, texts []string, protocol string) ([]observation, bool) {
	var observations []observation
	hasStructuredOS := false
	for _, cpe := range cpes {
		if observed, ok := identifyCPE(cpe); ok {
			observations = append(observations, observed)
			hasStructuredOS = true
			continue
		}
		part, _, _, version, valid := parseCPE(cpe)
		if valid && part == "o" && version != "*" {
			return nil, true
		}
	}
	structured := observations
	for _, text := range texts {
		observations = append(observations, serviceTextObservations(text, protocol, structured)...)
	}
	return observations, hasStructuredOS || len(observations) > 0
}

func serviceTextObservations(text, protocol string, structured []observation) []observation {
	if protocol == "rdp" && strings.Contains(strings.ToLower(text), " or ") {
		return nil
	}
	var observations []observation
	for _, observed := range identifyText(text) {
		weak := observed.method != "reported release" && observed.method != "scanner CPE"
		if len(structured) > 0 && weak && !corroboratesIdentity(observed, structured) {
			continue
		}
		if protocol == "rdp" {
			observed.method = "RDP negotiation signature inference"
		}
		observations = append(observations, observed)
	}
	return observations
}

func corroboratesIdentity(observed observation, structured []observation) bool {
	for _, explicit := range structured {
		if observed.vendor == explicit.vendor && observed.product == explicit.product && observed.version == explicit.version {
			return true
		}
	}
	return false
}

func identifyText(text string) []observation {
	if len(text) > maxEvidenceBytes {
		text = text[:maxEvidenceBytes]
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(text)), "cpe:") {
		if observed, ok := identifyCPE(strings.TrimSpace(text)); ok {
			return []observation{observed}
		}
		return nil
	}
	var found []observation
	for i := range products {
		product := &products[i]
		found = append(found, product.identifyBanner(text)...)
	}
	if len(found) > 0 {
		return found
	}
	for i := range products {
		product := &products[i]
		if product.packagePattern == nil {
			continue
		}
		if match := product.packagePattern.FindStringSubmatch(text); match != nil {
			return []observation{product.observed(match[1], match[0], "package release inference")}
		}
	}
	if rel, _ := identify(text); rel != nil {
		vendor, product := linuxProduct(rel.family)
		return []observation{{vendor: vendor, product: product, version: rel.version,
			evidence: strings.TrimSpace(text), method: "banner/package inference"}}
	}
	return nil
}

func identifyCPE(value string) (observation, bool) {
	part, vendor, product, version, valid := parseCPE(value)
	if !valid {
		return observation{}, false
	}
	definition := findProduct(vendor, product)
	if definition == nil || part != definition.part || (version == "*" && definition.productPattern == nil) {
		return observation{}, false
	}
	if definition.productPattern == nil {
		product = definition.product // Canonicalize only explicitly reviewed aliases.
	}
	return observation{vendor: definition.vendor, product: product, version: version, evidence: value, method: "scanner CPE"}, true
}

func parseCPE(value string) (part, vendor, product, version string, valid bool) {
	if len(value) > maxEvidenceBytes {
		return
	}
	fields := strings.Split(value, ":")
	switch {
	case len(fields) == 13 && strings.EqualFold(fields[0], "cpe") && fields[1] == "2.3":
		part, vendor, product, version = fields[2], fields[3], fields[4], fields[5]
	case len(fields) >= 4 && len(fields) <= 8 && strings.EqualFold(fields[0], "cpe") && strings.HasPrefix(fields[1], "/"):
		part, vendor, product, version = strings.TrimPrefix(fields[1], "/"), fields[2], fields[3], "*"
		if len(fields) >= 5 {
			version = fields[4]
		}
	default:
		return
	}
	part, vendor, product = strings.ToLower(part), strings.ToLower(vendor), strings.ToLower(product)
	valid = (part == "o" || part == "a") && cpeIdentityToken.MatchString(vendor) && cpeIdentityToken.MatchString(product) &&
		(version == "*" || versionToken.MatchString(version))
	return
}

func (o observation) cpe() string {
	definition := findProduct(o.vendor, o.product)
	return fmt.Sprintf("cpe:2.3:%s:%s:%s:%s:*:*:*:*:*:*:*", definition.part, o.vendor, o.product, o.version)
}

func (o observation) lifecycle() (time.Time, string) {
	definition := findProduct(o.vendor, o.product)
	if definition == nil {
		return time.Time{}, ""
	}
	return lifecycleEnd(definition.feed, definition.release(o.product, o.version))
}

package oseol

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// osEvidence can identify one release or a set of possible releases. Ambiguous
// evidence never creates an OS CPE; every candidate needs a known, expired cutoff.
// All OS/protocol decoders use this same assessment and finding construction.
type osEvidence struct {
	name, method, text string
	candidates         []string // Lifecycle feed/release, not CPE identities.
	ambiguous          bool
}

type supportAssessment struct {
	end    time.Time // First unsupported day.
	source string
}

func (e osEvidence) finding() *plugins.SecurityFinding {
	assessment, unsupported := assessLifecycle(e.candidates)
	if !unsupported {
		return nil
	}
	identification := "Detected " + e.name
	if e.ambiguous {
		identification = "Service suggests " + e.name + "; exact OS edition is unresolved"
	}
	return &plugins.SecurityFinding{
		ID: FindingID, Severity: plugins.SeverityLow,
		Description: fmt.Sprintf("%s (%s). Ordinary security support for all candidate releases ended by %s; paid extensions and device-specific exceptions are not established by this scan. Evidence: %s. Lifecycle: %s",
			identification, e.method, assessment.end.AddDate(0, 0, -1).Format(time.DateOnly), e.text, assessment.source),
		Evidence: e.text,
	}
}

func (o observation) finding(texts []string) *plugins.SecurityFinding {
	definition := findProduct(o.vendor, o.product)
	if definition == nil || (definition.eligibleEvidence != nil && !definition.eligibleEvidence(texts)) {
		return nil
	}
	name := definition.displayName(o.product)
	if o.version != "*" {
		name += " " + o.version
	}
	return (osEvidence{
		name: name, method: o.method, text: o.evidence,
		candidates: []string{definition.feed + "/" + definition.release(o.product, o.version)},
	}).finding()
}

func assessLifecycle(candidates []string) (supportAssessment, bool) {
	end, source := latestSupportEnd(candidates)
	return supportAssessment{end: end, source: source}, !end.IsZero() && !now().Before(end)
}

func latestSupportEnd(candidates []string) (time.Time, string) {
	var latest time.Time
	var sources []string
	for _, candidate := range candidates {
		product, version, valid := strings.Cut(candidate, "/")
		if !valid || product == "" || version == "" {
			return time.Time{}, ""
		}
		end, source := lifecycleEnd(product, version)
		if end.IsZero() {
			return time.Time{}, "" // Unknown is not proof of unsupported software.
		}
		if end.After(latest) {
			latest = end
		}
		if !slices.Contains(sources, source) {
			sources = append(sources, source)
		}
	}
	slices.Sort(sources)
	return latest, strings.Join(sources, "; ")
}

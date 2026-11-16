package oseol

import (
	"strings"
	"testing"
	"time"
)

func TestSharedAssessmentRequiresAllCandidatesToBeUnsupported(t *testing.T) {
	original := now
	now = func() time.Time { return date(2026, time.July, 1) }
	t.Cleanup(func() { now = original })
	for _, candidates := range [][]string{
		{"ubuntu/16.04", "debian/12"}, // One candidate still supported.
		{"ubuntu/16.04", "debian/999"},
		{"windows/7", "windows-server/2019"},
		{"fedora/38", "missing/1"},
		{},
	} {
		if _, unsupported := assessLifecycle(candidates); unsupported {
			t.Fatalf("uncertain/supported candidates classified EOL: %v", candidates)
		}
	}
}

func TestAllOSEvidenceUsesSharedFindingPolicy(t *testing.T) {
	original := now
	now = func() time.Time { return date(2026, time.July, 1) }
	t.Cleanup(func() { now = original })
	for _, candidate := range []string{"ubuntu/16.04", "debian/10", "fedora/38", "freebsd/12.4", "windows-server/2012", "cisco-ios-xe/17.3"} {
		finding := (osEvidence{name: candidate, method: "fixture", text: "observed version", candidates: []string{candidate}}).finding()
		if finding == nil || finding.ID != FindingID || finding.Evidence != "observed version" {
			t.Fatalf("shared evaluator failed for %s: %+v", candidate, finding)
		}
		if !strings.Contains(finding.Description, "Ordinary security support for all candidate releases ended by") || !strings.Contains(finding.Description, "https://") {
			t.Fatalf("OS-specific formatting bypassed the shared policy: %+v", finding)
		}
	}
}

func TestSupportSourcesAreDeterministicAndDeduplicated(t *testing.T) {
	end, sources := latestSupportEnd([]string{"windows-server/2012", "windows/8", "windows/8"})
	reversedEnd, reversedSources := latestSupportEnd([]string{"windows/8", "windows-server/2012"})
	if end.IsZero() || !end.Equal(reversedEnd) || sources != reversedSources {
		t.Fatal("candidate order changed the assessment")
	}
	if strings.Count(sources, "api/v1/products/windows)") != 1 {
		t.Fatalf("duplicate source citations: %s", sources)
	}
}

func TestProductRegistryOwnsUniqueCPEIdentities(t *testing.T) {
	seen := map[string]bool{}
	for _, definition := range products {
		if definition.feed != "" {
			if _, exists := lifecycleData.Products[definition.feed]; !exists {
				t.Fatalf("product %s has an unconfigured feed %s", definition.name, definition.feed)
			}
		}
		if definition.productPattern != nil {
			continue
		}
		for _, key := range append([]string{definition.vendor + ":" + definition.product}, definition.aliases...) {
			if seen[key] {
				t.Fatalf("duplicate product identity %s", key)
			}
			seen[key] = true
		}
	}
}

package oseol

import (
	"strings"
	"testing"
	"time"
)

func TestEmbeddedLifecycleSnapshot(t *testing.T) {
	snapshot, err := parseLifecycle(lifecycleJSON)
	if err != nil {
		t.Fatal(err)
	}
	for _, product := range []string{"ubuntu", "debian", "rhel", "centos", "centos-stream", "fedora", "freebsd", "windows-server", "windows", "cisco-ios-xe"} {
		if len(snapshot.Products[product].Releases) == 0 {
			t.Fatalf("missing lifecycle feed %s", product)
		}
	}
}

func TestLifecycleRejectsMalformedSnapshot(t *testing.T) {
	valid := `{"schema_version":1,"refreshed_at":"2026-11-10T00:00:00Z","products":{"example":{"source":"https://feed.example","vendor_url":"https://vendor.example","support":"Security","releases":{"1":{"end":"2020-01-01"}}}}}`
	for _, input := range []string{
		`{`, valid + `{}`,
		strings.Replace(valid, `"schema_version":1`, `"schema_version":2`, 1),
		strings.Replace(valid, `2026-11-10T00:00:00Z`, `yesterday`, 1),
		strings.Replace(valid, `2020-01-01`, `2020-02-31`, 1),
		strings.Replace(valid, `https://feed.example`, `http://feed.example`, 1),
		strings.Replace(valid, `"end":"2020-01-01"`, `"end":true`, 1),
	} {
		if _, err := parseLifecycle([]byte(input)); err == nil {
			t.Fatalf("accepted malformed snapshot: %s", input)
		}
	}
}

func TestLifecycleUnknownDateDoesNotBecomeUnsupported(t *testing.T) {
	snapshot, err := parseLifecycle([]byte(`{"schema_version":1,"refreshed_at":"2026-11-10T00:00:00Z","products":{"fedora":{"source":"https://feed.example","vendor_url":"https://vendor.example","support":"Security","releases":{"999":{"end":null}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	original := lifecycleData
	lifecycleData = snapshot
	t.Cleanup(func() { lifecycleData = original })
	end, _ := lifecycleEnd("fedora", "999")
	if !end.IsZero() {
		t.Fatalf("unknown cutoff returned %s", end)
	}
}

func TestCheckUsesFinalSupportedDay(t *testing.T) {
	original := now
	t.Cleanup(func() { now = original })
	firstUnsupported, _ := lifecycleEnd("ubuntu", "20.04")
	if firstUnsupported.IsZero() {
		t.Fatal("missing Ubuntu fixture")
	}
	now = func() time.Time { return firstUnsupported.Add(-time.Nanosecond) }
	if Check("Ubuntu 20.04") != nil {
		t.Fatal("reported EOL during the final supported day")
	}
	now = func() time.Time { return firstUnsupported }
	if Check("Ubuntu 20.04") == nil {
		t.Fatal("missing EOL after security support ended")
	}
}

func TestWindowsInferenceRequiresEveryCandidateCutoff(t *testing.T) {
	if end, _ := latestSupportEnd([]string{"windows/7", "windows-server/unknown"}); !end.IsZero() {
		t.Fatalf("unknown candidate produced a verdict: %s", end)
	}
}

func TestWindowsInferenceUsesLatestCandidate(t *testing.T) {
	serverEnd, _ := lifecycleEnd("windows-server", "2012")
	end, _ := latestSupportEnd([]string{"windows/8", "windows-server/2012"})
	if end.IsZero() || !end.Equal(serverEnd) {
		t.Fatalf("expected later server cutoff %s, got %s", serverEnd, end)
	}
}

func TestWindowsVersionUnsupportedFollowsRefreshedDates(t *testing.T) {
	original := now
	t.Cleanup(func() { now = original })
	end, _ := latestSupportEnd(legacyWindows["6.2"].candidates)
	if end.IsZero() {
		t.Fatal("missing Windows fixture")
	}
	now = func() time.Time { return end.Add(-time.Nanosecond) }
	if WindowsVersionUnsupported("6.2") {
		t.Fatal("legacy fingerprint list overrode the support date")
	}
	now = func() time.Time { return end }
	if !WindowsVersionUnsupported("6.2") || WindowsVersionUnsupported("10.0") {
		t.Fatal("incorrect known/ambiguous Windows support verdict")
	}
}

func TestServer2003UsesFinalServicePackSupport(t *testing.T) {
	end, source := (observation{vendor: "microsoft", product: "windows_server_2003", version: "*"}).lifecycle()
	spEnd, _ := lifecycleEnd("windows-server", "2003-sp2")
	if end.IsZero() || !end.Equal(spEnd) || source == "" {
		t.Fatalf("expected final SP support %s, got %s (%s)", spEnd, end, source)
	}
}

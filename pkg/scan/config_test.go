package scan

import (
	"strings"
	"sync"
	"testing"
)

func TestNormalizeDepth(t *testing.T) {
	tests := []struct {
		name         string
		scanDepth    string
		fastMode     bool
		wantDepth    string
		wantFastMode bool
		wantErr      bool
	}{
		{name: "empty is no-op", scanDepth: "", fastMode: false, wantDepth: "", wantFastMode: false},
		{name: "empty preserves existing FastMode", scanDepth: "", fastMode: true, wantDepth: "", wantFastMode: true},
		{name: "fast sets FastMode true", scanDepth: "fast", fastMode: false, wantDepth: "fast", wantFastMode: true},
		{name: "thorough sets FastMode false", scanDepth: "thorough", fastMode: true, wantDepth: "thorough", wantFastMode: false},
		{name: "Fast (mixed case) normalized", scanDepth: "Fast", fastMode: false, wantDepth: "fast", wantFastMode: true},
		{name: "THOROUGH (uppercase) normalized", scanDepth: "THOROUGH", fastMode: true, wantDepth: "thorough", wantFastMode: false},
		{name: "invalid value returns error", scanDepth: "medium", wantErr: true},
		{name: "invalid mixed case returns error", scanDepth: "Medium", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Config{ScanDepth: tt.scanDepth, FastMode: tt.fastMode}
			err := c.normalizeDepth()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for ScanDepth %q, got nil", tt.scanDepth)
				}
				if !strings.Contains(err.Error(), "invalid ScanDepth") {
					t.Fatalf("expected 'invalid ScanDepth' error, got %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.ScanDepth != tt.wantDepth {
				t.Errorf("ScanDepth = %q, want %q", c.ScanDepth, tt.wantDepth)
			}
			if c.FastMode != tt.wantFastMode {
				t.Errorf("FastMode = %v, want %v", c.FastMode, tt.wantFastMode)
			}
		})
	}
}

func TestNormalizeDepth_ConcurrentSafe(t *testing.T) {
	c := &Config{ScanDepth: "fast"}
	// Pre-normalize so concurrent calls are read-only
	if err := c.normalizeDepth(); err != nil {
		t.Fatalf("initial normalizeDepth failed: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.normalizeDepth(); err != nil {
				t.Errorf("concurrent normalizeDepth failed: %v", err)
			}
			if !c.FastMode {
				t.Errorf("FastMode should be true")
			}
		}()
	}
	wg.Wait()
}

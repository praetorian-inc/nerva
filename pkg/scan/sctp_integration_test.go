//go:build linux && integration

package scan

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestSCTPScanTargetRealConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping SCTP integration test in short mode")
	}

	config := Config{
		SCTP:           true,
		FastMode:       false,
		DefaultTimeout: 10 * time.Second,
		Verbose:        true,
	}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:3868"),
	}

	result, err := config.SCTPScanTarget(target)

	t.Logf("SCTP scan result: %+v, error: %v", result, err)

	if err != nil {
		if !containsAny(err.Error(), "connection refused", "SCTP dial failed", "SCTP connection failed", "SCTP scanning requires Linux") {
			t.Errorf("Unexpected error type: %v", err)
		}
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

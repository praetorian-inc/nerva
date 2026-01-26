package scan

import (
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestSCTPScanTargetSignature(t *testing.T) {
	var c Config
	var target plugins.Target

	// Verify SCTPScanTarget has correct signature
	_, _ = c.SCTPScanTarget(target)
}

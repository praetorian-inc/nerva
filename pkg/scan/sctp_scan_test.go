package scan

import (
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestSCTPScanTarget(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		target  plugins.Target
		wantErr bool
	}{
		{
			name: "fast mode returns nil for non-priority port",
			config: Config{
				SCTP:           true,
				FastMode:       true,
				DefaultTimeout: 5 * time.Second,
			},
			target: plugins.Target{
				Address: netip.MustParseAddrPort("127.0.0.1:12345"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.config.SCTPScanTarget(tt.target)

			if tt.wantErr {
				if err == nil {
					t.Error("SCTPScanTarget expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("SCTPScanTarget unexpected error: %v", err)
				}
			}
			_ = result
		})
	}
}

func TestSCTPScanTargetFastModeSkipsFullScan(t *testing.T) {
	config := Config{
		SCTP:           true,
		FastMode:       true,
		DefaultTimeout: 5 * time.Second,
	}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:54321"),
	}

	result, err := config.SCTPScanTarget(target)

	if err != nil {
		t.Errorf("FastMode SCTPScanTarget returned error: %v", err)
	}
	if result != nil {
		t.Errorf("FastMode SCTPScanTarget returned non-nil result for non-priority port")
	}
}

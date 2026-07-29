// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runner

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckConfig_ScanDepthValidation(t *testing.T) {
	tests := []struct {
		name        string
		scanDepth   string
		fastMode    bool
		wantErr     bool
		errContains string
	}{
		{name: "empty scan-depth is valid (legacy behavior)", scanDepth: "", wantErr: false},
		{name: "fast is valid", scanDepth: "fast", wantErr: false},
		{name: "thorough is valid", scanDepth: "thorough", wantErr: false},
		{name: "invalid value rejected", scanDepth: "medium", wantErr: true, errContains: "invalid --scan-depth"},
		{name: "scan-depth and --fast both set is valid (warns but does not error)", scanDepth: "thorough", fastMode: true, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := cliConfig{scanDepth: tt.scanDepth, fastMode: tt.fastMode}
			err := checkConfig(cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for scan-depth %q, got nil", tt.scanDepth)
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("expected error to contain %q, got %q", tt.errContains, err.Error())
				}
			} else if err != nil {
				t.Fatalf("expected no error for scan-depth %q, got %v", tt.scanDepth, err)
			}
		})
	}
}

func TestScanDepth_ResumeRoundTrip(t *testing.T) {
	// Simulate the original scan: --scan-depth=thorough is set and saved to a
	// state file on disk (as buildState + SaveState do in root.go's runScan).
	original := cliConfig{scanDepth: "thorough", timeout: 2000, workers: 50}
	state := buildState(original, nil, nil, nil, 0)

	stateFile := filepath.Join(t.TempDir(), "resume-state.json")
	if err := SaveState(stateFile, state); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// Load it back, as a resumed invocation would.
	loaded, err := LoadState(stateFile)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}
	if loaded.Config.ScanDepth != "thorough" {
		t.Fatalf("state file did not persist ScanDepth: got %q, want %q", loaded.Config.ScanDepth, "thorough")
	}

	// Simulate a resumed invocation where --scan-depth was NOT re-supplied on
	// the command line (the common case). The resume restore block in
	// root.go's runScan applies this same fallback.
	resumed := cliConfig{timeout: 2000, workers: 50}
	if resumed.scanDepth == "" {
		resumed.scanDepth = loaded.Config.ScanDepth
	}

	if resumed.scanDepth != "thorough" {
		t.Fatalf("resumed config did not restore ScanDepth: got %q, want %q", resumed.scanDepth, "thorough")
	}

	if err := checkConfig(resumed); err != nil {
		t.Fatalf("checkConfig rejected restored scanDepth %q: %v", resumed.scanDepth, err)
	}

	scanCfg := createScanConfig(resumed)
	if scanCfg.ScanDepth != "thorough" {
		t.Errorf("createScanConfig ScanDepth = %q, want %q", scanCfg.ScanDepth, "thorough")
	}
	if scanCfg.FastMode {
		t.Errorf("createScanConfig FastMode = true, want false for scan-depth=thorough")
	}
}

func TestCreateScanConfig_ScanDepthMapping(t *testing.T) {
	tests := []struct {
		name          string
		scanDepth     string
		fastMode      bool
		wantScanDepth string
		wantFastMode  bool
	}{
		{
			name:          "unset scan-depth falls back to --fast=false",
			scanDepth:     "",
			fastMode:      false,
			wantScanDepth: "",
			wantFastMode:  false,
		},
		{
			name:          "unset scan-depth falls back to --fast=true",
			scanDepth:     "",
			fastMode:      true,
			wantScanDepth: "",
			wantFastMode:  true,
		},
		{
			name:          "scan-depth=fast sets FastMode true regardless of --fast",
			scanDepth:     "fast",
			fastMode:      false,
			wantScanDepth: "fast",
			wantFastMode:  true,
		},
		{
			name:          "scan-depth=thorough sets FastMode false even if --fast was set",
			scanDepth:     "thorough",
			fastMode:      true,
			wantScanDepth: "thorough",
			wantFastMode:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := cliConfig{scanDepth: tt.scanDepth, fastMode: tt.fastMode, timeout: 2000, workers: 50}
			scanCfg := createScanConfig(cfg)
			if scanCfg.ScanDepth != tt.wantScanDepth {
				t.Errorf("ScanDepth = %q, want %q", scanCfg.ScanDepth, tt.wantScanDepth)
			}
			if scanCfg.FastMode != tt.wantFastMode {
				t.Errorf("FastMode = %v, want %v", scanCfg.FastMode, tt.wantFastMode)
			}
		})
	}
}

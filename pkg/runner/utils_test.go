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

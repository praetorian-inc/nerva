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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test Group 1: Checksum Computation

func TestComputeChecksum_Deterministic(t *testing.T) {
	state := &ScanState{
		Version:   1,
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Config:    StateConfig{TimeoutMs: 2000, Workers: 50},
		Targets:   StateTargets{OriginalCount: 10, Completed: []string{"1.1.1.1:80"}},
	}

	checksum1 := state.ComputeChecksum()
	checksum2 := state.ComputeChecksum()

	assert.Equal(t, checksum1, checksum2)
	assert.Len(t, checksum1, 64) // SHA256 hex = 64 chars
}

func TestComputeChecksum_DifferentForDifferentState(t *testing.T) {
	state1 := &ScanState{Version: 1, Config: StateConfig{TimeoutMs: 2000}}
	state2 := &ScanState{Version: 1, Config: StateConfig{TimeoutMs: 3000}}

	assert.NotEqual(t, state1.ComputeChecksum(), state2.ComputeChecksum())
}

func TestComputeChecksum_ExcludesChecksumField(t *testing.T) {
	state := &ScanState{Version: 1}
	before := state.ComputeChecksum()

	state.Checksum = "some-old-checksum"
	after := state.ComputeChecksum()

	assert.Equal(t, before, after)
}

// Test Group 2: Checksum Validation

func TestValidateChecksum_ValidChecksum(t *testing.T) {
	state := &ScanState{Version: 1}
	state.Checksum = state.ComputeChecksum()

	err := state.ValidateChecksum()
	assert.NoError(t, err)
}

func TestValidateChecksum_EmptyChecksum(t *testing.T) {
	state := &ScanState{Version: 1, Checksum: ""}

	err := state.ValidateChecksum()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no checksum")
}

func TestValidateChecksum_CorruptedChecksum(t *testing.T) {
	state := &ScanState{Version: 1}
	state.Checksum = "invalid-checksum-that-does-not-match"

	err := state.ValidateChecksum()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")
}

func TestValidateChecksum_TamperedState(t *testing.T) {
	state := &ScanState{Version: 1, Config: StateConfig{TimeoutMs: 2000}}
	state.Checksum = state.ComputeChecksum()

	// Tamper with state
	state.Config.TimeoutMs = 9999

	err := state.ValidateChecksum()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")
}

// Test Group 3: SaveState

func TestSaveState_CreatesFile(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "test-state.json")

	state := &ScanState{
		Version:   CurrentStateVersion,
		CreatedAt: time.Now().UTC(),
		Config:    StateConfig{TimeoutMs: 2000, Workers: 50},
		Targets:   StateTargets{OriginalCount: 100, Completed: []string{"1.1.1.1:80"}},
	}

	err := SaveState(filename, state)
	assert.NoError(t, err)

	// Verify file exists and is valid JSON
	data, err := os.ReadFile(filename)
	assert.NoError(t, err)

	var loaded ScanState
	err = json.Unmarshal(data, &loaded)
	assert.NoError(t, err)
	assert.Equal(t, CurrentStateVersion, loaded.Version)
}

func TestSaveState_SetsChecksum(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "test-state.json")

	state := &ScanState{Version: CurrentStateVersion}
	err := SaveState(filename, state)
	assert.NoError(t, err)

	data, _ := os.ReadFile(filename)
	var loaded ScanState
	json.Unmarshal(data, &loaded)

	assert.NotEmpty(t, loaded.Checksum)
	assert.NoError(t, loaded.ValidateChecksum())
}

func TestSaveState_UpdatesTimestamp(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "test-state.json")

	oldTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	state := &ScanState{Version: CurrentStateVersion, UpdatedAt: oldTime}

	err := SaveState(filename, state)
	assert.NoError(t, err)

	data, _ := os.ReadFile(filename)
	var loaded ScanState
	json.Unmarshal(data, &loaded)

	assert.True(t, loaded.UpdatedAt.After(oldTime))
}

func TestSaveState_AtomicWrite(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "test-state.json")

	state := &ScanState{Version: CurrentStateVersion}
	err := SaveState(filename, state)
	assert.NoError(t, err)

	// Verify no .tmp file left behind
	tmpFile := filename + ".tmp"
	_, err = os.Stat(tmpFile)
	assert.True(t, os.IsNotExist(err), "temp file should not exist after save")
}

// Test Group 4: LoadState

func TestLoadState_ValidFile(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "test-state.json")

	original := &ScanState{
		Version:   CurrentStateVersion,
		Config:    StateConfig{TimeoutMs: 2000, Workers: 50},
		Targets:   StateTargets{OriginalCount: 100, Completed: []string{"1.1.1.1:80"}},
	}
	SaveState(filename, original)

	loaded, err := LoadState(filename)
	assert.NoError(t, err)
	assert.Equal(t, original.Version, loaded.Version)
	assert.Equal(t, original.Config.TimeoutMs, loaded.Config.TimeoutMs)
	assert.Equal(t, original.Targets.Completed, loaded.Targets.Completed)
}

func TestLoadState_FileNotFound(t *testing.T) {
	_, err := LoadState("/nonexistent/path/state.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read state file")
}

func TestLoadState_InvalidJSON(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "invalid.json")
	os.WriteFile(filename, []byte("not valid json {{{"), 0644)

	_, err := LoadState(filename)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal")
}

func TestLoadState_CorruptedChecksum(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "corrupted.json")

	// Write file with invalid checksum
	state := &ScanState{Version: 1, Checksum: "bad-checksum"}
	data, _ := json.Marshal(state)
	os.WriteFile(filename, data, 0644)

	_, err := LoadState(filename)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")
}

func TestLoadState_RoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "roundtrip.json")

	original := &ScanState{
		Version:   CurrentStateVersion,
		CreatedAt: time.Now().UTC(),
		Config: StateConfig{
			TimeoutMs:   3000,
			FastMode:    true,
			UDP:         true,
			SCTP:        false,
			Verbose:     true,
			Workers:     100,
			MaxHostConn: 5,
			RateLimit:   50.5,
		},
		Targets: StateTargets{
			OriginalCount: 500,
			Completed:     []string{"1.1.1.1:80", "2.2.2.2:443|example.com"},
			Pending:       []string{"3.3.3.3:22"},
			InputFile:     "/path/to/input.txt",
		},
		Results: []plugins.Service{{IP: "1.1.1.1", Port: 80, Protocol: "http"}},
	}

	err := SaveState(filename, original)
	require.NoError(t, err)

	loaded, err := LoadState(filename)
	require.NoError(t, err)

	// Verify all fields preserved
	assert.Equal(t, original.Version, loaded.Version)
	assert.Equal(t, original.Config, loaded.Config)
	assert.Equal(t, original.Targets, loaded.Targets)
	assert.Equal(t, len(original.Results), len(loaded.Results))
}

// Test Group 5: GenerateStateFileName

func TestGenerateStateFileName_Format(t *testing.T) {
	ts := time.Date(2026, 3, 5, 14, 30, 45, 0, time.UTC)

	filename := GenerateStateFileName(ts)

	assert.Equal(t, "nerva-state-20260305-143045.json", filename)
}

func TestGenerateStateFileName_Deterministic(t *testing.T) {
	ts := time.Now()

	name1 := GenerateStateFileName(ts)
	name2 := GenerateStateFileName(ts)

	assert.Equal(t, name1, name2)
}

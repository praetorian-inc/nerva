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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// CurrentStateVersion is the schema version for state files
const CurrentStateVersion = 1

// ScanState represents the complete state of an interrupted scan
type ScanState struct {
	Version   int               `json:"version"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
	Config    StateConfig       `json:"config"`
	Targets   StateTargets      `json:"targets"`
	Results   []plugins.Service `json:"results"`
	Checksum  string            `json:"checksum,omitempty"`
}

// StateConfig stores scan configuration for resume
type StateConfig struct {
	TimeoutMs   int     `json:"timeout_ms"`
	FastMode    bool    `json:"fast_mode"`
	UDP         bool    `json:"udp"`
	SCTP        bool    `json:"sctp"`
	Verbose     bool    `json:"verbose"`
	Workers     int     `json:"workers,omitempty"`
	MaxHostConn int     `json:"max_host_conn,omitempty"`
	RateLimit   float64 `json:"rate_limit,omitempty"`
}

// StateTargets tracks target progress
type StateTargets struct {
	OriginalCount int      `json:"original_count"`
	Completed     []string `json:"completed"`
	Pending       []string `json:"pending"`
	InputFile     string   `json:"input_file,omitempty"`
}

// ComputeChecksum calculates SHA256 hash of state content (excluding checksum field)
func (s *ScanState) ComputeChecksum() string {
	// Create copy without checksum for hashing
	temp := *s
	temp.Checksum = ""

	data, _ := json.Marshal(temp)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// ValidateChecksum verifies the state file integrity
func (s *ScanState) ValidateChecksum() error {
	if s.Checksum == "" {
		return fmt.Errorf("state file has no checksum")
	}
	expected := s.ComputeChecksum()
	if s.Checksum != expected {
		return fmt.Errorf("state file corrupted: checksum mismatch")
	}
	return nil
}

// SaveState atomically writes state to file with checksum
// Uses temp file + rename pattern for atomic writes
func SaveState(filename string, state *ScanState) error {
	// Update timestamp
	state.UpdatedAt = time.Now().UTC()

	// Compute and set checksum
	state.Checksum = state.ComputeChecksum()

	// Marshal to JSON with indentation for readability
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	// Write to temp file first
	tempFile := filename + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename (POSIX guarantees atomicity)
	if err := os.Rename(tempFile, filename); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// LoadState reads and validates state from file
// Returns error if file not found, invalid JSON, or checksum mismatch
func LoadState(filename string) (*ScanState, error) {
	// Read file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	// Unmarshal JSON
	var state ScanState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state: %w", err)
	}

	// Validate checksum
	if err := state.ValidateChecksum(); err != nil {
		return nil, err
	}

	return &state, nil
}

// GenerateStateFileName generates a timestamped state file name
// Format: nerva-state-YYYYMMDD-HHMMSS.json
func GenerateStateFileName(t time.Time) string {
	return fmt.Sprintf("nerva-state-%s.json", t.Format("20060102-150405"))
}

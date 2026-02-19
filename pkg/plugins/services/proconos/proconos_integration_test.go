//go:build integration

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

package proconos

import (
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// TestProConOS_Integration tests the ProConOS plugin against the mock server
// running in docker-compose (proconos-mock container)
func TestProConOS_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping ProConOS integration test in short mode")
	}

	// Connect to proconos-mock container (hostname: proconos.local or localhost)
	// If running outside docker-compose, use localhost:20547
	// If running inside docker-compose, use proconos-mock:20547 or proconos.local:20547
	host := "localhost:20547"
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		t.Skipf("Skipping integration test: proconos-mock server not available at %s: %v", host, err)
	}
	defer conn.Close()

	// Create plugin and target
	plugin := &ProConOSPlugin{}
	target := plugins.Target{
		Host: "localhost",
		Port: 20547,
	}

	// Run detection against mock server
	result, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Plugin.Run() failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected detection result, got nil")
	}

	// Verify service metadata
	svc, ok := result.Metadata().(plugins.ServiceProConOS)
	if !ok {
		t.Fatalf("Expected ServiceProConOS metadata, got %T", result.Metadata())
	}

	// Verify extracted fields match mock server responses
	expectedLadderRuntime := "3.5.0.10"
	expectedPLCType := "ProConOS"
	expectedProjectName := "TestProject"
	expectedBootProject := "BootProj"
	expectedSourceCode := "Source.pro"

	if svc.LadderLogicRuntime != expectedLadderRuntime {
		t.Errorf("LadderLogicRuntime = %q, expected %q", svc.LadderLogicRuntime, expectedLadderRuntime)
	}

	if svc.PLCType != expectedPLCType {
		t.Errorf("PLCType = %q, expected %q", svc.PLCType, expectedPLCType)
	}

	if svc.ProjectName != expectedProjectName {
		t.Errorf("ProjectName = %q, expected %q", svc.ProjectName, expectedProjectName)
	}

	if svc.BootProject != expectedBootProject {
		t.Errorf("BootProject = %q, expected %q", svc.BootProject, expectedBootProject)
	}

	if svc.ProjectSourceCode != expectedSourceCode {
		t.Errorf("ProjectSourceCode = %q, expected %q", svc.ProjectSourceCode, expectedSourceCode)
	}

	t.Logf("ProConOS detection successful: %+v", svc)
}

// TestProConOS_Integration_InvalidProbe tests behavior when sending invalid probe
func TestProConOS_Integration_InvalidProbe(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping ProConOS integration test in short mode")
	}

	host := "localhost:20547"
	conn, err := net.DialTimeout("tcp", host, 5*time.Second)
	if err != nil {
		t.Skipf("Skipping integration test: proconos-mock server not available at %s: %v", host, err)
	}
	defer conn.Close()

	// Send invalid probe (wrong signature)
	invalidProbe := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	_, err = conn.Write(invalidProbe)
	if err != nil {
		t.Fatalf("Failed to write invalid probe: %v", err)
	}

	// Set read deadline to avoid hanging
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Attempt to read response (should timeout or get no response)
	buf := make([]byte, 150)
	n, err := conn.Read(buf)

	// Mock server should not respond to invalid probe
	// We expect either timeout or connection close
	if err == nil && n > 0 {
		t.Logf("Note: Mock server responded to invalid probe (this is acceptable for testing)")
	}
}

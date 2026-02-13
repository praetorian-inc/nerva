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

package bgp

import (
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// Task 4: validateMarker() tests
func TestValidateMarker_ValidMarker(t *testing.T) {
	// Valid: 16 bytes of 0xFF
	validMarker := make([]byte, 16)
	for i := range validMarker {
		validMarker[i] = 0xFF
	}
	
	if !validateMarker(validMarker) {
		t.Error("Expected valid marker to return true")
	}
}

func TestValidateMarker_InvalidLength(t *testing.T) {
	// Invalid: 15 bytes of 0xFF (too short)
	shortMarker := make([]byte, 15)
	for i := range shortMarker {
		shortMarker[i] = 0xFF
	}
	
	if validateMarker(shortMarker) {
		t.Error("Expected short marker to return false")
	}
}

func TestValidateMarker_InvalidByte(t *testing.T) {
	// Invalid: 16 bytes but byte 5 is 0xFE
	invalidMarker := make([]byte, 16)
	for i := range invalidMarker {
		invalidMarker[i] = 0xFF
	}
	invalidMarker[5] = 0xFE
	
	if validateMarker(invalidMarker) {
		t.Error("Expected marker with invalid byte to return false")
	}
}

func TestValidateMarker_EmptySlice(t *testing.T) {
	// Invalid: Empty slice
	if validateMarker([]byte{}) {
		t.Error("Expected empty slice to return false")
	}
}

// Task 5: validateHeader() tests
func TestValidateHeader_ValidHeader(t *testing.T) {
	// Valid header: length=29, type=0x01
	data := make([]byte, 30)
	// Fill marker
	for i := 0; i < 16; i++ {
		data[i] = 0xFF
	}
	// Length (big-endian): 29
	data[16] = 0x00
	data[17] = 0x1D // 29 in hex
	// Type: OPEN (0x01)
	data[18] = 0x01
	
	length, msgType, valid := validateHeader(data)
	if !valid {
		t.Error("Expected valid header to return true")
	}
	if length != 29 {
		t.Errorf("Expected length 29, got %d", length)
	}
	if msgType != 0x01 {
		t.Errorf("Expected type 0x01, got 0x%02x", msgType)
	}
}

func TestValidateHeader_TooShort(t *testing.T) {
	// Invalid: data too short (< 19 bytes)
	data := make([]byte, 18)
	
	_, _, valid := validateHeader(data)
	if valid {
		t.Error("Expected too short data to return false")
	}
}

func TestValidateHeader_LengthTooShort(t *testing.T) {
	// Invalid: length field < 19
	data := make([]byte, 30)
	for i := 0; i < 16; i++ {
		data[i] = 0xFF
	}
	data[16] = 0x00
	data[17] = 0x12 // 18
	data[18] = 0x01
	
	_, _, valid := validateHeader(data)
	if valid {
		t.Error("Expected length < 19 to return false")
	}
}

func TestValidateHeader_LengthTooLong(t *testing.T) {
	// Invalid: length field > 4096
	data := make([]byte, 30)
	for i := 0; i < 16; i++ {
		data[i] = 0xFF
	}
	data[16] = 0x10  // 4097 = 0x1001
	data[17] = 0x01
	data[18] = 0x01
	
	_, _, valid := validateHeader(data)
	if valid {
		t.Error("Expected length > 4096 to return false")
	}
}

func TestValidateHeader_InvalidType(t *testing.T) {
	// Invalid: type != 0x01
	data := make([]byte, 30)
	for i := 0; i < 16; i++ {
		data[i] = 0xFF
	}
	data[16] = 0x00
	data[17] = 0x1D // 29
	data[18] = 0x02 // INVALID type (should be 0x01)
	
	length, msgType, valid := validateHeader(data)
	if valid {
		t.Error("Expected invalid type to return false")
	}
	if length != 29 {
		t.Errorf("Expected length 29 even with invalid type, got %d", length)
	}
	if msgType != 0x02 {
		t.Errorf("Expected type 0x02, got 0x%02x", msgType)
	}
}

// Task 6: parseBGPOpen() tests
func TestParseBGPOpen_ValidVersion4(t *testing.T) {
	// Valid: byte 19 = 0x04
	data := make([]byte, 30)
	for i := 0; i < 16; i++ {
		data[i] = 0xFF
	}
	data[16] = 0x00
	data[17] = 0x1D // length 29
	data[18] = 0x01 // type OPEN
	data[19] = 0x04 // BGP version 4
	
	bgpData, err := parseBGPOpen(data)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if bgpData == nil {
		t.Fatal("Expected non-nil ServiceBGP")
	}
	if bgpData.Version != 4 {
		t.Errorf("Expected version 4, got %d", bgpData.Version)
	}
	if !bgpData.Detected {
		t.Error("Expected Detected to be true")
	}
}

func TestParseBGPOpen_InvalidVersion(t *testing.T) {
	// Invalid: byte 19 = 0x03
	data := make([]byte, 30)
	for i := 0; i < 16; i++ {
		data[i] = 0xFF
	}
	data[16] = 0x00
	data[17] = 0x1D
	data[18] = 0x01
	data[19] = 0x03 // BGP version 3 (invalid)
	
	bgpData, err := parseBGPOpen(data)
	if err == nil {
		t.Error("Expected error for unsupported version")
	}
	if bgpData != nil {
		t.Error("Expected nil ServiceBGP for invalid version")
	}
}

func TestParseBGPOpen_TooShort(t *testing.T) {
	// Invalid: data too short (< 29 bytes)
	data := make([]byte, 28)
	
	bgpData, err := parseBGPOpen(data)
	if err == nil {
		t.Error("Expected error for too short data")
	}
	if bgpData != nil {
		t.Error("Expected nil ServiceBGP for too short data")
	}
}

// Task 8: Docker integration test
func TestBGP(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "bgp-gobgp",
			Port:        179,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				if res == nil {
					return false
				}
				if res.Protocol != "bgp" {
					return false
				}
				metadata := res.Metadata()
				bgpData, ok := metadata.(plugins.ServiceBGP)
				if !ok {
					return false
				}
				return bgpData.Version == 4 && bgpData.Detected
			},
			RunConfig: dockertest.RunOptions{
				Repository: "osrg/gobgp",
				Tag:        "latest",
				Cmd: []string{
					"gobgpd",
					"-f", "/etc/gobgp/gobgpd.conf",
				},
			},
		},
	}

	p := &BGPPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("%s", err.Error())
			}
		})
	}
}

// Additional tests for interface methods to improve coverage
func TestBGPPlugin_PortPriority(t *testing.T) {
	p := &BGPPlugin{}
	
	if !p.PortPriority(179) {
		t.Error("Expected port 179 to have priority")
	}
	
	if p.PortPriority(80) {
		t.Error("Expected port 80 to not have priority")
	}
}

func TestBGPPlugin_Name(t *testing.T) {
	p := &BGPPlugin{}
	if p.Name() != "bgp" {
		t.Errorf("Expected name 'bgp', got '%s'", p.Name())
	}
}

func TestBGPPlugin_Type(t *testing.T) {
	p := &BGPPlugin{}
	if p.Type() != plugins.TCP {
		t.Errorf("Expected type TCP, got %v", p.Type())
	}
}

func TestBGPPlugin_Priority(t *testing.T) {
	p := &BGPPlugin{}
	if p.Priority() != 1000 {
		t.Errorf("Expected priority 1000, got %d", p.Priority())
	}
}

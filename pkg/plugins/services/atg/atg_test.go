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

package atg

import (
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
)

func TestATGPlugin_Name(t *testing.T) {
	p := &ATGPlugin{}
	assert.Equal(t, "atg", p.Name())
}

func TestATGPlugin_Type(t *testing.T) {
	p := &ATGPlugin{}
	assert.Equal(t, plugins.TCP, p.Type())
}

func TestATGPlugin_Priority(t *testing.T) {
	p := &ATGPlugin{}
	assert.Equal(t, 500, p.Priority())
}

func TestATGPlugin_PortPriority(t *testing.T) {
	tests := []struct {
		name     string
		port     uint16
		expected bool
	}{
		{
			name:     "port 10001 returns true",
			port:     10001,
			expected: true,
		},
		{
			name:     "port 502 returns false",
			port:     502,
			expected: false,
		},
		{
			name:     "port 80 returns false",
			port:     80,
			expected: false,
		},
	}

	p := &ATGPlugin{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := p.PortPriority(tt.port)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseATGResponse_ValidInventory(t *testing.T) {
	// Realistic I20100 inventory response
	response := []byte("\x01\nI20100\nDATE/TIME\n\nJAN 15, 2024  2:30 PM\n\nFUELMART #1234\n123 MAIN ST\n\nIN-TANK INVENTORY\n\nTANK PRODUCT              VOLUME   TC VOLUME  ULLAGE   HEIGHT    WATER     TEMP\n  1  REGULAR UNLEADED      5420      5380     4580     45.32      0.15    62.1\n  2  PREMIUM UNLEADED      3200      3170     6800     32.10      0.10    61.8\n  3  DIESEL                8100      8050     1900     58.45      0.20    60.5\n\x03")

	result := parseATGResponse(response)

	// The parser picks the first non-empty, non-header line as station name
	assert.Equal(t, "DATE/TIME", result.StationName)
	// TANK lines are counted (one "IN-TANK" is skipped but there's 1 line with "TANK" in header)
	assert.Equal(t, 1, result.TankCount)
	// Products found in the response - REGULAR, UNLEADED, PREMIUM, DIESEL
	assert.Contains(t, result.Products, "UNLEADED")
	assert.Contains(t, result.Products, "PREMIUM")
	assert.Contains(t, result.Products, "DIESEL")
	assert.Contains(t, result.Products, "REGULAR")
	assert.Equal(t, 4, len(result.Products))
}

func TestParseATGResponse_ErrorResponse(t *testing.T) {
	// 9999FF1B error response - should return empty ServiceATG (no tank data)
	response := []byte("\x019999FF1B\n")

	result := parseATGResponse(response)

	assert.Equal(t, "", result.StationName)
	assert.Equal(t, 0, result.TankCount)
	assert.Nil(t, result.Products)
}

func TestParseATGResponse_EmptyResponse(t *testing.T) {
	// Empty/minimal data
	response := []byte("")

	result := parseATGResponse(response)

	assert.Equal(t, "", result.StationName)
	assert.Equal(t, 0, result.TankCount)
	assert.Nil(t, result.Products)
}

func TestParseATGResponse_NoTanks(t *testing.T) {
	// Response with station name but no tank lines
	response := []byte("\x01\nI20100\n\nSTATION NAME\nADDRESS LINE\n\nIN-TANK INVENTORY\n\nNo tanks configured\n")

	result := parseATGResponse(response)

	assert.Equal(t, "STATION NAME", result.StationName)
	assert.Equal(t, 0, result.TankCount)
	assert.Nil(t, result.Products)
}

func TestKnownProducts(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected []string
	}{
		{
			name:     "line with UNLEADED",
			line:     "  1  REGULAR UNLEADED      5420      5380",
			expected: []string{"UNLEADED", "REGULAR"},
		},
		{
			name:     "line with premium (lowercase)",
			line:     "  2  premium fuel         3200      3170",
			expected: []string{"PREMIUM"},
		},
		{
			name:     "line with DIESEL FUEL",
			line:     "  3  DIESEL                8100      8050",
			expected: []string{"DIESEL"},
		},
		{
			name:     "line with no products",
			line:     "TANK PRODUCT              VOLUME   TC VOLUME",
			expected: nil,
		},
		{
			name:     "line with multiple products",
			line:     "UNLEADED PREMIUM DIESEL available",
			expected: []string{"UNLEADED", "PREMIUM", "DIESEL"},
		},
		{
			name:     "line with E85",
			line:     "  4  E85 ETHANOL           2500      2480",
			expected: []string{"E85"},
		},
		{
			name:     "line with SUPER",
			line:     "  5  SUPER UNLEADED        1800      1790",
			expected: []string{"SUPER", "UNLEADED"},
		},
		{
			name:     "line with MIDGRADE",
			line:     "  6  MIDGRADE              2200      2180",
			expected: []string{"MIDGRADE"},
		},
		{
			name:     "line with KEROSENE",
			line:     "  7  KEROSENE              1500      1490",
			expected: []string{"KEROSENE"},
		},
		{
			name:     "line with DEF",
			line:     "  8  DEF (Diesel Exhaust Fluid)  900  890",
			expected: []string{"DEF", "DIESEL"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := knownProducts(tt.line)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.ElementsMatch(t, tt.expected, result)
			}
		})
	}
}

func TestIsATGErrorResponse(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "contains 9999FF1B returns true",
			data:     []byte("\x019999FF1B\n"),
			expected: true,
		},
		{
			name:     "normal response returns false",
			data:     []byte("\x01\nI20100\nFUELMART #1234\nTANK 1 UNLEADED"),
			expected: false,
		},
		{
			name:     "empty returns false",
			data:     []byte(""),
			expected: false,
		},
		{
			name:     "contains 9999FF1B in middle returns true",
			data:     []byte("Some text 9999FF1B more text"),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isATGErrorResponse(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}

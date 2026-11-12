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

package mssql

import (
	"testing"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// TestBuildMSSQLCPE_WithVersion tests CPE generation with a known version
func TestBuildMSSQLCPE_WithVersion(t *testing.T) {
	testcases := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "SQL Server 2019",
			version:  "15.0.2000",
			expected: "cpe:2.3:a:microsoft:sql_server:15.0.2000:*:*:*:*:*:*:*",
		},
		{
			name:     "SQL Server 2017",
			version:  "14.0.1000",
			expected: "cpe:2.3:a:microsoft:sql_server:14.0.1000:*:*:*:*:*:*:*",
		},
		{
			name:     "SQL Server 2016",
			version:  "13.0.5026",
			expected: "cpe:2.3:a:microsoft:sql_server:13.0.5026:*:*:*:*:*:*:*",
		},
		{
			name:     "SQL Server 2014",
			version:  "12.0.6024",
			expected: "cpe:2.3:a:microsoft:sql_server:12.0.6024:*:*:*:*:*:*:*",
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := buildMSSQLCPE(tc.version)

			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

// TestBuildMSSQLCPE_WithoutVersion tests CPE generation with unknown version (wildcard)
func TestBuildMSSQLCPE_WithoutVersion(t *testing.T) {
	version := ""
	expected := "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*"

	result := buildMSSQLCPE(version)

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestCheckMSSQLEOL(t *testing.T) {
	tests := []struct {
		version string
		wantID  string
	}{
		{"9.0.1399\n", "mssql-eol"},
		{"9.0.1399", "mssql-eol"},
		{"16.0.1000\n", ""},
		{"16.0.1000", ""},
		{"", ""},
		{"invalid", ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.version, func(t *testing.T) {
			finding := checkMSSQLEOL(tt.version)
			if tt.wantID == "" {
				if finding != nil {
					t.Errorf("checkMSSQLEOL(%q) = %+v, want nil", tt.version, finding)
				}
				return
			}
			if finding == nil {
				t.Fatalf("checkMSSQLEOL(%q) = nil, want ID %q", tt.version, tt.wantID)
			}
			if finding.ID != tt.wantID {
				t.Errorf("finding.ID = %q, want %q", finding.ID, tt.wantID)
			}
		})
	}
}

func TestMSSQL(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "mssql",
			Port:        1433,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "mcr.microsoft.com/mssql/server",
				Tag:        "2019-latest",
				Env: []string{
					"ACCEPT_EULA=Y",
					"SA_PASSWORD=yourStrong(!)Password",
				},
			},
		},
	}

	p := &MSSQLPlugin{}

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

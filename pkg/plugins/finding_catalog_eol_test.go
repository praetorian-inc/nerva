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

package plugins

import "testing"

func TestEOLCatalogIDs(t *testing.T) {
	ids := []string{"openssh-eol", "esxi-eol", "snmp-eol", "bind-eol", "postgres-eol", "mssql-eol"}
	for _, id := range ids {
		f := SecurityFinding{ID: id, Severity: SeverityInfo}
		f.Enrich()
		if f.Title == "" {
			t.Errorf("%s: catalog miss (Title empty after Enrich)", id)
		}
		if f.Severity != SeverityLow {
			t.Errorf("%s: Severity = %q, want low (catalog-authoritative)", id, f.Severity)
		}
	}
	// rdp-eol-os still present
	f := SecurityFinding{ID: "rdp-eol-os"}
	f.Enrich()
	if f.Title == "" {
		t.Fatal("rdp-eol-os catalog entry missing")
	}
}

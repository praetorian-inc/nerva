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

package oseol

import (
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestCheck(t *testing.T) {
	orig := now
	now = func() time.Time { return date(2026, time.October, 15) }
	t.Cleanup(func() { now = orig })

	tests := []struct {
		name    string
		text    string
		wantID  string
		wantNil bool
	}{
		{
			name:   "centos7 http banner",
			text:   "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips",
			wantID: FindingID,
		},
		{
			name:   "centos7 cpe",
			text:   "cpe:2.3:o:centos:centos:7:*:*:*:*:*:*:*",
			wantID: FindingID,
		},
		{
			name:   "ubuntu1604 ssh",
			text:   "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10",
			wantID: FindingID,
		},
		{
			name:   "ubuntu2004 cpe",
			text:   "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:*:*:*:*",
			wantID: FindingID,
		},
		{
			name:   "debian10 ssh deb tag",
			text:   "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2",
			wantID: FindingID,
		},
		{
			name:   "debian11 cpe past lts",
			text:   "cpe:/o:debian:debian_linux:11",
			wantID: FindingID,
		},
		{
			name:   "rhel7 el suffix with distro name",
			text:   "OpenSSH_7.4-1.el7 (Red Hat Enterprise Linux)",
			wantID: FindingID,
		},
		{
			name:    "bare el7 suffix is unidentified family",
			text:    "OpenSSH_7.4-1.el7",
			wantNil: true,
		},
		{
			name:   "rhel7 el7_9 minor disttag",
			text:   "openssl-1.0.2k-25.el7_9 (Red Hat Enterprise Linux)",
			wantID: FindingID,
		},
		{
			name:   "ubuntu 20.04 with space",
			text:   "Ubuntu 20.04 LTS",
			wantID: FindingID,
		},
		{
			name:   "rhel7 cpe",
			text:   "cpe:2.3:o:redhat:enterprise_linux:7.9:*:*:*:*:*:*:*",
			wantID: FindingID,
		},
		{
			name:    "ubuntu2204 still in standard support",
			text:    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
			wantNil: true,
		},
		{
			name:    "debian12 still in lts",
			text:    "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
			wantNil: true,
		},
		{
			name:    "rhel8 still in maintenance",
			text:    "OpenSSH_8.0-1.el8",
			wantNil: true,
		},
		{
			name:    "ubuntu family without version is unidentified",
			text:    "Apache/2.4.41 (Ubuntu)",
			wantNil: true,
		},
		{
			name:    "centos family without version is unidentified",
			text:    "Apache/2.4.37 (CentOS)",
			wantNil: true,
		},
		{
			name:    "empty",
			text:    "",
			wantNil: true,
		},
		{
			name:    "unrelated banner",
			text:    "SSH-2.0-OpenSSH_8.9p1",
			wantNil: true,
		},
		{
			name:    "other os family fedora not in scope",
			text:    "cpe:2.3:o:fedoraproject:fedora:38:*:*:*:*:*:*:*",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Check(tt.text)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("Check(%q) = %+v, want nil", tt.text, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("Check(%q) = nil, want finding %s", tt.text, tt.wantID)
			}
			if got.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", got.ID, tt.wantID)
			}
			if got.Severity != plugins.SeverityHigh {
				t.Errorf("Severity = %q, want %q", got.Severity, plugins.SeverityHigh)
			}
			if got.Evidence == "" {
				t.Error("Evidence is empty")
			}
		})
	}
}

func TestCheck_DoesNotInventUnlistedVersion(t *testing.T) {
	orig := now
	now = func() time.Time { return date(2026, time.October, 15) }
	t.Cleanup(func() { now = orig })

	if got := Check("cpe:2.3:o:canonical:ubuntu_linux:12.04:*:*:*:*:*:*:*"); got != nil {
		t.Fatalf("unlisted Ubuntu 12.04 should not emit (not in researched table), got %+v", got)
	}
}

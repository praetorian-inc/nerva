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

// Package oseol identifies operating systems from service evidence and evaluates
// ordinary security support using an offline, periodically refreshed snapshot.
// Paid support entitlements are not inferred from unauthenticated banners.
package oseol

import (
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// FindingID is the stable non-RDP OS end-of-life finding ID.
const FindingID = "os-eol"

// Tests replace the clock; production uses time.Now.
var now = time.Now

// Check retains the original Linux-only API, using the same identification,
// conflict handling and assessment as Enrich instead of a parallel parser.
func Check(texts ...string) *plugins.SecurityFinding {
	observations, _ := identifyService(nil, texts, "")
	for _, observed := range consistentObservations(observations) {
		if findProduct(observed.vendor, observed.product).legacyCheck {
			if finding := observed.finding(texts); finding != nil {
				return finding
			}
		}
	}
	return nil
}

// WindowsVersionFinding adapts an NT version (major.minor or major.minor.build)
// to the shared evaluator and formatter. RDP retains its protocol severity policy.
func WindowsVersionFinding(version, evidence string) *plugins.SecurityFinding {
	identified := windowsVersionEvidence(version, evidence)
	if identified == nil {
		return nil
	}
	return identified.finding()
}

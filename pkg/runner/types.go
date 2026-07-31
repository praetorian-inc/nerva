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

import "github.com/praetorian-inc/nerva/pkg/scan"

// ScanDepth controls how many plugins nerva tries per target.
type ScanDepth string

const (
	// ScanDepthFast only tries plugins whose PortPriority matches the target
	// port, skipping the full plugin iteration for non-standard ports.
	// Equivalent to --fast. Fast but may miss services running on non-standard
	// ports. Banner-based pre-filtering is planned for a future release
	// (LAB-5301) and is not yet implemented.
	ScanDepthFast ScanDepth = scan.ScanDepthFast

	// ScanDepthThorough tries all plugins regardless of port (current default
	// behavior). Slowest but most complete.
	ScanDepthThorough ScanDepth = scan.ScanDepthThorough
)

type cliConfig struct {
	outputFile       string
	outputJSON       bool
	outputCSV        bool
	overwriteOutput  bool
	fastMode         bool
	scanDepth        string // --scan-depth flag; raw value, validated/normalized in checkConfig
	timeout          int
	useUDP           bool
	useSCTP          bool
	verbose          bool
	showErrors       bool
	showCapabilities bool
	workers          int
	maxHostConn      int
	rateLimit        float64
	// Resume support
	stateFile string
	resume    bool
	autoSave  int

	// Security misconfiguration detection
	misconfigs bool

	// Deep probing (admin paths, login detection)
	deep bool

	// Proxy
	proxy     string
	proxyAuth string
	dnsOrder  string
}

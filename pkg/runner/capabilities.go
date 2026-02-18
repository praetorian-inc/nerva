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
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/plugins/fingerprinters"
)

func printCapabilities() {
	fmt.Fprintln(os.Stdout, "HTTP Fingerprint Modules:")

	fps := fingerprinters.GetFingerprinters()
	fpNames := make([]string, 0, len(fps))
	for _, fp := range fps {
		fpNames = append(fpNames, fp.Name())
	}
	sort.Strings(fpNames)
	for _, name := range fpNames {
		fmt.Fprintf(os.Stdout, "  %s\n", name)
	}

	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "Detection Plugins:")

	type pluginEntry struct {
		name     string
		protocol string
		ports    []string
	}

	var entries []pluginEntry
	for _, pluginList := range plugins.Plugins {
		for _, p := range pluginList {
			var ports []string
			for port := 1; port <= 65535; port++ {
				if p.PortPriority(uint16(port)) {
					ports = append(ports, strconv.Itoa(port))
				}
			}
			entries = append(entries, pluginEntry{
				name:     p.Name(),
				protocol: p.Type().String(),
				ports:    ports,
			})
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].name < entries[j].name
	})

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, e := range entries {
		fmt.Fprintf(w, "  %s\t%s\t%s\n", e.name, e.protocol, strings.Join(e.ports, ", "))
	}
	w.Flush()
}

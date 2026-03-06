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
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

var inputFile string

// readTargets reads targets from file or stdin (original function)
func readTargets(inputFile string, verbose bool) ([]plugins.Target, error) {
	targetsList := make([]plugins.Target, 0)
	var readFile *os.File
	if len(inputFile) == 0 && len(targetList) == 0 {
		fi, _ := os.Stdin.Stat()
		if (fi.Mode() & os.ModeCharDevice) != 0 { // if no piped input
			return targetsList, errors.New("missing input of targets")
		}
		readFile = os.Stdin
	} else if len(targetList) > 0 {
		for _, target := range targetList {
			parsedTarget, err := parseTarget(target)
			if err == nil {
				targetsList = append(targetsList, parsedTarget)
			} else if verbose {
				fmt.Printf("%s\n", err)
			}
		}
	} else {
		file, err := os.Open(inputFile)
		if err != nil {
			return targetsList, err
		}
		readFile = file
	}
	if readFile != nil {
		defer readFile.Close()
	}

	scanner := bufio.NewScanner(readFile)
	for scanner.Scan() {
		parsedTarget, err := parseTarget(scanner.Text())
		if err == nil {
			targetsList = append(targetsList, parsedTarget)
		} else if verbose {
			fmt.Printf("%s\n", err)
		}
	}
	return targetsList, nil
}

// parseTarget parses a target string into a Target struct (original function)
func parseTarget(inputTarget string) (plugins.Target, error) {
	scanTarget := plugins.Target{}
	trimmed := strings.TrimSpace(inputTarget)

	// Use net.SplitHostPort to properly handle IPv6 addresses in [IPv6]:port format
	hostStr, portStr, err := net.SplitHostPort(trimmed)
	if err != nil {
		return plugins.Target{}, fmt.Errorf("invalid target: %s", inputTarget)
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return plugins.Target{}, fmt.Errorf("invalid port specified")
	}

	ip := net.ParseIP(hostStr)
	var isHostname = false
	if ip == nil {
		var addrs []net.IP
		addrs, err = net.LookupIP(hostStr)
		if err != nil {
			return plugins.Target{}, err
		}
		isHostname = true
		ip = addrs[0]
	}

	// use IPv4 representation if possible
	ipv4 := ip.To4()
	if ipv4 != nil {
		ip = ipv4
	}

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return plugins.Target{}, fmt.Errorf("invalid ip address specified %s", err)
	}
	targetAddr := netip.AddrPortFrom(addr, uint16(port))
	scanTarget.Address = targetAddr

	if isHostname {
		scanTarget.Host = hostStr
	}

	return scanTarget, nil
}

// TargetToString converts a target to its string representation
// Format: "ip:port" or "ip:port|hostname" if hostname is set
func TargetToString(target plugins.Target) string {
	base := fmt.Sprintf("%s:%d", target.Address.Addr().String(), target.Address.Port())
	if target.Host != "" {
		return base + "|" + target.Host
	}
	return base
}

// TargetsToStrings converts a slice of targets to string representations
// Added for scan resume functionality (PR #125)
func TargetsToStrings(targets []plugins.Target) []string {
	result := make([]string, len(targets))
	for i, t := range targets {
		result[i] = TargetToString(t)
	}
	return result
}

// StringToTarget converts a string back to a Target
// Supports formats: "ip:port" and "ip:port|hostname"
func StringToTarget(s string, verbose bool) (plugins.Target, error) {
	var addrStr, hostname string

	if idx := strings.Index(s, "|"); idx != -1 {
		addrStr = s[:idx]
		hostname = s[idx+1:]
	} else {
		addrStr = s
	}

	addrPort, err := netip.ParseAddrPort(addrStr)
	if err != nil {
		return plugins.Target{}, fmt.Errorf("invalid target %q: %w", s, err)
	}
	return plugins.Target{Address: addrPort, Host: hostname}, nil
}

// StringsToTargets converts string representations back to targets
// Invalid strings are logged and skipped if verbose is true
// Added for scan resume functionality (PR #125)
func StringsToTargets(strings []string, verbose bool) []plugins.Target {
	result := make([]plugins.Target, 0, len(strings))
	for _, s := range strings {
		target, err := StringToTarget(s, verbose)
		if err != nil {
			if verbose {
				log.Printf("skipping invalid target: %s\n", err)
			}
			continue
		}
		result = append(result, target)
	}
	return result
}

// FilterPendingTargets returns targets that are not in the completed set
// Added for scan resume functionality (PR #125)
func FilterPendingTargets(allTargets []plugins.Target, completed []string) []plugins.Target {
	completedSet := make(map[string]bool, len(completed))
	for _, c := range completed {
		completedSet[c] = true
	}

	pending := make([]plugins.Target, 0, len(allTargets)-len(completed))
	for _, t := range allTargets {
		if !completedSet[TargetToString(t)] {
			pending = append(pending, t)
		}
	}
	return pending
}

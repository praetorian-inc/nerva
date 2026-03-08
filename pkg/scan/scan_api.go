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

package scan

import (
	"context"
	"log"
	"net"
	"net/netip"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// ResolveTargets expands targets based on the DNSOrder strategy.
func ResolveTargets(targets []plugins.Target, config Config) []plugins.Target {
	var resolved []plugins.Target
	for _, t := range targets {
		if t.Host == "" || t.Address.Addr() != netip.IPv4Unspecified() {
			resolved = append(resolved, t)
			continue
		}

		if config.DNSOrder == "p" || config.DNSOrder == "pl" {
			// Do not resolve yet; pass the 0.0.0.0 target through.
			// The dialer will try the proxy using t.Host.
			resolved = append(resolved, t)
			continue
		}

		// Local resolution ("l" or "lp" or default)
		addrs, err := net.LookupIP(t.Host)
		if err != nil {
			if config.Verbose {
				log.Printf("dns lookup failed for %s: %v\n", t.Host, err)
			}
			if config.DNSOrder == "lp" {
				// Fall back to Proxy resolution by passing the 0.0.0.0 target
				resolved = append(resolved, t)
			}
			continue
		}

		// Expand target to one per IP
		for _, ip := range addrs {
			// prefer IPv4
			if ipv4 := ip.To4(); ipv4 != nil {
				ip = ipv4
			}
			if addr, ok := netip.AddrFromSlice(ip); ok {
				newTarget := plugins.Target{
					Host:    t.Host,
					Address: netip.AddrPortFrom(addr, t.Address.Port()),
				}
				resolved = append(resolved, newTarget)
			}
		}
	}
	return resolved
}

// TODO: integrate SCTP/UDP scan paths with worker pool. Currently sequential because:
// 1. Different return types (*Service vs []*Service) need separate scanFunc adapters
// 2. Different transport semantics (kernel SCTP, connectionless UDP)
// 3. Rarely used at scale — primary parallelism benefit is TCP fingerprinting
// SCTPScan performs SCTP scanning on all targets.
func SCTPScan(ctx context.Context, targets []plugins.Target, config Config) ([]plugins.Service, error) {
	var results []plugins.Service
	for _, target := range targets {
		select {
		case <-ctx.Done():
			return results, nil
		default:
		}
		result, err := config.SCTPScanTarget(target)
		if err == nil && result != nil {
			results = append(results, *result)
		}
		if config.Verbose && err != nil {
			log.Printf("%s\n", err)
		}
	}
	return results, nil
}

// UDPScan performs UDP scanning on all targets.
func UDPScan(ctx context.Context, targets []plugins.Target, config Config) ([]plugins.Service, error) {
	var results []plugins.Service
	for _, target := range targets {
		select {
		case <-ctx.Done():
			return results, nil
		default:
		}
		result, err := config.UDPScanTarget(target)
		if err == nil && result != nil {
			results = append(results, *result)
		}
		if config.Verbose && err != nil {
			log.Printf("%s\n", err)
		}
	}

	return results, nil
}

// ScanTargets fingerprints service(s) running given a list of targets.
func ScanTargets(ctx context.Context, targets []plugins.Target, config Config) ([]plugins.Service, error) {
	targets = ResolveTargets(targets, config)

	if config.SCTP {
		return SCTPScan(ctx, targets, config)
	}
	if config.UDP {
		return UDPScan(ctx, targets, config)
	}

	pool := NewScanPool(config)
	if config.OnProgress != nil {
		pool.WithProgress(config.OnProgress)
	}
	fn := func(target plugins.Target) ([]plugins.Service, error) {
		results, err := config.SimpleScanTarget(target)
		if err != nil {
			return nil, err
		}
		services := make([]plugins.Service, 0, len(results))
		for _, r := range results {
			if r != nil {
				services = append(services, *r)
			}
		}
		return services, nil
	}
	return pool.Run(ctx, targets, fn)
}

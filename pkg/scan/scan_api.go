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

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

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
	if config.SCTP {
		return SCTPScan(ctx, targets, config)
	}
	if config.UDP {
		return UDPScan(ctx, targets, config)
	}

	pool := NewScanPool(config)
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

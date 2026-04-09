// Copyright 2026 Praetorian Security, Inc.
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
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// scanFunc is the per-target scan function. It does not accept context.Context,
// so once a scan starts it runs to completion (bounded by Config.DefaultTimeout).
// Cancellation only prevents new targets from being dispatched.
type scanFunc func(plugins.Target) ([]plugins.Service, error)

// ProgressCallback is called after each target is scanned.
// Parameters: completed target, results for that target, total completed count.
// The callback is invoked from worker goroutines so it must be thread-safe.
type ProgressCallback func(target plugins.Target, results []plugins.Service, completedCount int64)

// ScanPool manages a pool of workers that concurrently scan targets.
type ScanPool struct {
	workers     int
	hostLimiter *HostLimiter  // nil if MaxHostConn <= 0
	rateLimiter *rate.Limiter // nil if RateLimit <= 0
	verbose     bool
	completed   atomic.Int64
	failed      atomic.Int64
	active      atomic.Int64
	total       atomic.Int64
	onProgress  ProgressCallback
}

// NewScanPool constructs a ScanPool from the provided Config.
func NewScanPool(config Config) *ScanPool {
	workers := config.Workers
	if workers <= 0 {
		workers = 1
	}

	p := &ScanPool{
		workers: workers,
		verbose: config.Verbose,
	}

	if config.MaxHostConn > 0 {
		p.hostLimiter = NewHostLimiter(config.MaxHostConn)
	}

	if config.RateLimit > 0 {
		p.rateLimiter = rate.NewLimiter(rate.Limit(config.RateLimit), 1)
	}

	return p
}

// WithProgress sets a callback to be invoked after each target is scanned.
// The callback is invoked from worker goroutines so it must be thread-safe.
func (p *ScanPool) WithProgress(cb ProgressCallback) *ScanPool {
	p.onProgress = cb
	return p
}

// Run distributes targets across workers, collects results, and returns all
// discovered services. It returns immediately with nil, nil if targets is empty.
func (p *ScanPool) Run(ctx context.Context, targets []plugins.Target, fn scanFunc) ([]plugins.Service, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	p.completed.Store(0)
	p.failed.Store(0)
	p.active.Store(0)
	p.total.Store(int64(len(targets)))

	bufSize := len(targets)
	if p.workers < bufSize {
		bufSize = p.workers
	}
	jobCh := make(chan plugins.Target, bufSize)
	resultCh := make(chan []plugins.Service, p.workers*2)

	var stopProgress func()
	if p.verbose {
		stopProgress = p.startProgressTicker(ctx, 2*time.Second)
	}

	var wg sync.WaitGroup
	for i := 0; i < p.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobCh {
				p.safeProcessTarget(ctx, target, fn, resultCh)
			}
		}()
	}

	// Feeder: send targets to jobCh, stop if ctx is cancelled.
	go func() {
		defer close(jobCh)
		for _, target := range targets {
			select {
			case <-ctx.Done():
				return
			case jobCh <- target:
			}
		}
	}()

	// Wait for all workers then close the result channel.
	go func() {
		wg.Wait()
		if stopProgress != nil {
			stopProgress()
		}
		close(resultCh)
	}()

	// Collect results.
	var results []plugins.Service
	for batch := range resultCh {
		results = append(results, batch...)
	}

	return results, nil
}

// safeProcessTarget wraps processTarget with a recover to prevent panics
// in individual plugin runs from crashing the entire process.
func (p *ScanPool) safeProcessTarget(ctx context.Context, target plugins.Target, fn scanFunc, resultCh chan<- []plugins.Service) {
	defer func() {
		if r := recover(); r != nil {
			p.failed.Add(1)
			log.Printf("recovered panic while scanning %s: %v", target.Address, r)
		}
	}()
	p.processTarget(ctx, target, fn, resultCh)
}

// processTarget executes a single scan, honouring host and rate limits.
// It is a separate method so deferred release calls are scoped correctly.
func (p *ScanPool) processTarget(ctx context.Context, target plugins.Target, fn scanFunc, resultCh chan<- []plugins.Service) {
	if p.hostLimiter != nil {
		release, err := p.hostLimiter.Acquire(ctx, target.Address.Addr().String())
		if err != nil {
			p.failed.Add(1)
			return
		}
		defer release()
	}

	if p.rateLimiter != nil {
		if err := p.rateLimiter.Wait(ctx); err != nil {
			p.failed.Add(1)
			return
		}
	}

	p.active.Add(1)
	services, err := fn(target)
	p.active.Add(-1)
	if err != nil {
		p.failed.Add(1)
		if p.verbose {
			log.Printf("scan error for %s: %s\n", target.Address, err)
		}
		return
	}

	if len(services) > 0 {
		resultCh <- services
	}

	p.completed.Add(1)
	if p.onProgress != nil {
		p.onProgress(target, services, p.completed.Load())
	}
}

// startProgressTicker logs scan progress every interval.
// The returned stop function halts the ticker and prints a final summary.
func (p *ScanPool) startProgressTicker(ctx context.Context, interval time.Duration) func() {
	ticker := time.NewTicker(interval)
	done := make(chan struct{})

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				completed := p.completed.Load()
				failed := p.failed.Load()
				total := p.total.Load()
				remaining := total - completed - failed
				active := p.active.Load()
				idle := int64(p.workers) - active
				fmt.Fprintf(log.Writer(), "[progress] %d/%d completed, %d failed, %d remaining | workers: %d active, %d idle\n",
					completed, total, failed, remaining, active, idle)
			}
		}
	}()

	return func() {
		close(done)
		completed := p.completed.Load()
		failed := p.failed.Load()
		total := p.total.Load()
		remaining := total - completed - failed
		active := p.active.Load()
		idle := int64(p.workers) - active
		fmt.Fprintf(log.Writer(), "[progress] %d/%d completed, %d failed, %d remaining | workers: %d active, %d idle\n",
			completed, total, failed, remaining, active, idle)
	}
}

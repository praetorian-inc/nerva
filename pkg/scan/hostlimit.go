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
	"sync"
	"sync/atomic"

	"golang.org/x/sync/semaphore"
)

// hostState tracks the semaphore and active count for a single host.
type hostState struct {
	sem    *semaphore.Weighted
	active int64
}

// HostLimiter enforces per-host concurrency limits for scan connections.
type HostLimiter struct {
	limit int64
	// hosts maps IP strings to their semaphore state. Entries are created lazily
	// and never removed. For typical scan workloads this is fine; each entry is
	// a semaphore + int64 (~40 bytes).
	hosts map[string]*hostState
	mu    sync.RWMutex
}

// NewHostLimiter creates a new HostLimiter with the given per-host limit.
func NewHostLimiter(maxPerHost int) *HostLimiter {
	return &HostLimiter{
		limit: int64(maxPerHost),
		hosts: make(map[string]*hostState),
	}
}

// getOrCreate returns the hostState for the given IP, creating it if it does not exist.
// Uses double-checked locking for performance.
func (h *HostLimiter) getOrCreate(hostIP string) *hostState {
	// Fast path: state already exists.
	h.mu.RLock()
	state, ok := h.hosts[hostIP]
	h.mu.RUnlock()
	if ok {
		return state
	}

	// Slow path: create the state.
	h.mu.Lock()
	defer h.mu.Unlock()

	// Double-check: another goroutine may have created it while we waited.
	if state, ok := h.hosts[hostIP]; ok {
		return state
	}

	state = &hostState{
		sem:    semaphore.NewWeighted(h.limit),
		active: 0,
	}
	h.hosts[hostIP] = state
	return state
}

// Acquire blocks until a connection slot is available for hostIP or ctx is cancelled.
// Returns a release function that must be called when the connection is complete.
func (h *HostLimiter) Acquire(ctx context.Context, hostIP string) (func(), error) {
	state := h.getOrCreate(hostIP)

	if err := state.sem.Acquire(ctx, 1); err != nil {
		return nil, err
	}

	atomic.AddInt64(&state.active, 1)

	return func() {
		atomic.AddInt64(&state.active, -1)
		state.sem.Release(1)
	}, nil
}

// ActiveCount returns the number of active connections to hostIP.
// Returns 0 if the host has never been used.
func (h *HostLimiter) ActiveCount(hostIP string) int {
	h.mu.RLock()
	state, ok := h.hosts[hostIP]
	h.mu.RUnlock()

	if !ok {
		return 0
	}

	return int(atomic.LoadInt64(&state.active))
}

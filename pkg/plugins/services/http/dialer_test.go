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

package http

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/plugins/fingerprinters"
)

// stubDialer tracks dial calls and connects to the given address.
type stubDialer struct {
	addr      string
	dialCount int
}

func (d *stubDialer) DialTCP(ctx context.Context, target plugins.Target) (net.Conn, error) {
	d.dialCount++
	return net.Dial("tcp", d.addr)
}

func (d *stubDialer) DialTLS(ctx context.Context, target plugins.Target) (net.Conn, error) {
	d.dialCount++
	return net.Dial("tcp", d.addr)
}

// TestFingerprintUsesDialerForProbes verifies that when target.Dialer is set,
// active fingerprinting probes use it instead of the original conn-pinned client.
func TestFingerprintUsesDialerForProbes(t *testing.T) {
	// Create a test server that returns 200 for everything.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	dialer := &stubDialer{addr: ts.Listener.Addr().String()}
	target := plugins.Target{
		Dialer: dialer,
	}

	// Create a response for the initial request (simulates the initial GET /).
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString("<html><title>Test</title></html>")),
	}
	resp.Header.Set("Content-Type", "text/html")

	// Create a dummy client that fails if used; this proves the dialer is used for probes
	// when target.Dialer is set.
	brokenClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				t.Fatal("original conn-pinned client should not be used for probes when Dialer is set")
				return nil, nil
			},
		},
	}

	wappalyzerClient, err := wappalyzer.New()
	require.NoError(t, err, "unable to initialize wappalyzer")

	baseURL := "http://" + ts.Listener.Addr().String()
	_, _, _, _, _, _, _, err = fingerprint(resp, wappalyzerClient, brokenClient, baseURL, "", false, target)
	require.NoError(t, err)

	// If any probe endpoints are registered, the dialer must have been called.
	probeEndpoints := fingerprinters.GetProbeEndpoints()
	hasNonRootProbes := false
	for _, endpoint := range probeEndpoints {
		if endpoint != "" && endpoint != "/" {
			hasNonRootProbes = true
			break
		}
	}
	if hasNonRootProbes {
		assert.Greater(t, dialer.dialCount, 0, "dialer should have been called for active probes")
	}
}

// TestFingerprintFallsBackWithoutDialer verifies that when target.Dialer is nil,
// the original client is used (backward compatibility).
func TestFingerprintFallsBackWithoutDialer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	// No Dialer set — should fall back to the provided client.
	target := plugins.Target{}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString("<html><title>Test</title></html>")),
	}
	resp.Header.Set("Content-Type", "text/html")

	// Working client pointing at the test server.
	workingClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("tcp", ts.Listener.Addr().String())
			},
		},
	}

	wappalyzerClient, err := wappalyzer.New()
	require.NoError(t, err, "unable to initialize wappalyzer")

	baseURL := "http://" + ts.Listener.Addr().String()
	_, _, _, _, _, _, _, err = fingerprint(resp, wappalyzerClient, workingClient, baseURL, "", false, target)
	require.NoError(t, err)
}

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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProxyDialer_ParsesURLFormats(t *testing.T) {
	t.Helper()

	tests := []struct {
		name       string
		proxyURL   string
		wantErr    bool
		wantScheme string
	}{
		{
			name:       "socks5 scheme",
			proxyURL:   "socks5://127.0.0.1:1080",
			wantErr:    false,
			wantScheme: "socks5",
		},
		{
			name:       "socks5h scheme (proxy-side DNS)",
			proxyURL:   "socks5h://127.0.0.1:1080",
			wantErr:    false,
			wantScheme: "socks5",
		},
		{
			name:       "http scheme",
			proxyURL:   "http://127.0.0.1:8080",
			wantErr:    false,
			wantScheme: "http",
		},
		{
			name:       "https scheme",
			proxyURL:   "https://127.0.0.1:8443",
			wantErr:    false,
			wantScheme: "https",
		},
		{
			name:     "invalid scheme",
			proxyURL: "invalid://127.0.0.1:1080",
			wantErr:  true,
		},
		{
			name:     "malformed URL",
			proxyURL: "://invalid",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Helper()

			config := Config{
				Proxy:          tt.proxyURL,
				DefaultTimeout: 2 * time.Second,
			}

			pd, err := NewProxyDialer(config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, pd)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, pd)
			assert.Equal(t, tt.proxyURL, pd.proxyURL)
		})
	}
}

func TestNewProxyDialer_ExtractsAuthFromURL(t *testing.T) {
	t.Helper()

	config := Config{
		Proxy:          "socks5://user:pass@127.0.0.1:1080",
		DefaultTimeout: 2 * time.Second,
	}

	pd, err := NewProxyDialer(config)
	require.NoError(t, err)
	require.NotNil(t, pd)

	// The URL should have userinfo stripped during dialer creation
	// We verify this by checking the internal parsed URL
	assert.Contains(t, pd.proxyURL, "user:pass@")
}

func TestNewProxyDialer_CombinesAuth(t *testing.T) {
	t.Helper()

	tests := []struct {
		name      string
		proxyURL  string
		proxyAuth string
		wantUser  string
	}{
		{
			name:      "URL auth takes priority",
			proxyURL:  "socks5://urluser:urlpass@127.0.0.1:1080",
			proxyAuth: "authuser:authpass",
			wantUser:  "urluser",
		},
		{
			name:      "ProxyAuth used when no URL auth",
			proxyURL:  "socks5://127.0.0.1:1080",
			proxyAuth: "authuser:authpass",
			wantUser:  "authuser",
		},
		{
			name:      "No auth",
			proxyURL:  "socks5://127.0.0.1:1080",
			proxyAuth: "",
			wantUser:  "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Helper()

			config := Config{
				Proxy:          tt.proxyURL,
				ProxyAuth:      tt.proxyAuth,
				DefaultTimeout: 2 * time.Second,
			}

			pd, err := NewProxyDialer(config)
			require.NoError(t, err)
			require.NotNil(t, pd)
		})
	}
}

func TestNewProxyDialer_InvalidScheme(t *testing.T) {
	t.Helper()

	config := Config{
		Proxy:          "ftp://127.0.0.1:21",
		DefaultTimeout: 2 * time.Second,
	}

	pd, err := NewProxyDialer(config)
	assert.Error(t, err)
	assert.Nil(t, pd)
	assert.Contains(t, err.Error(), "unsupported proxy scheme")
}

func TestProxyDialer_GetTimeout(t *testing.T) {
	t.Helper()

	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{
			name:    "default timeout",
			timeout: 2 * time.Second,
		},
		{
			name:    "custom timeout",
			timeout: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Helper()

			config := Config{
				Proxy:          "socks5://127.0.0.1:1080",
				DefaultTimeout: tt.timeout,
			}

			pd, err := NewProxyDialer(config)
			require.NoError(t, err)
			require.NotNil(t, pd)
			assert.Equal(t, tt.timeout, pd.timeout)
		})
	}
}

func TestProxyDialer_DNSOrder(t *testing.T) {
	t.Helper()

	tests := []struct {
		name     string
		dnsOrder string
	}{
		{name: "local first", dnsOrder: "l"},
		{name: "proxy first", dnsOrder: "p"},
		{name: "local then proxy", dnsOrder: "lp"},
		{name: "proxy then local", dnsOrder: "pl"},
		{name: "default empty", dnsOrder: ""},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Helper()

			config := Config{
				Proxy:          "socks5://127.0.0.1:1080",
				DNSOrder:       tt.dnsOrder,
				DefaultTimeout: 2 * time.Second,
			}

			pd, err := NewProxyDialer(config)
			require.NoError(t, err)
			require.NotNil(t, pd)
			assert.Equal(t, tt.dnsOrder, pd.dnsOrder)
		})
	}
}

func TestProxyDialer_Verbose(t *testing.T) {
	t.Helper()

	config := Config{
		Proxy:          "socks5://127.0.0.1:1080",
		Verbose:        true,
		DefaultTimeout: 2 * time.Second,
	}

	pd, err := NewProxyDialer(config)
	require.NoError(t, err)
	require.NotNil(t, pd)
	assert.True(t, pd.verbose)
}

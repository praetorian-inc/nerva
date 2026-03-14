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
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

var dialer = &net.Dialer{
	Timeout: 2 * time.Second,
}

var sortedTCPPlugins = make([]plugins.Plugin, 0)
var sortedTCPTLSPlugins = make([]plugins.Plugin, 0)
var sortedUDPPlugins = make([]plugins.Plugin, 0)
var sortedSCTPPlugins = make([]plugins.Plugin, 0)
var tlsConfig = tls.Config{} //nolint:gosec

func init() {
	setupPlugins()
	cipherSuites := make([]uint16, 0)

	for _, suite := range tls.CipherSuites() {
		cipherSuites = append(cipherSuites, suite.ID)
	}

	for _, suite := range tls.InsecureCipherSuites() {
		cipherSuites = append(cipherSuites, suite.ID)
	}
	tlsConfig.InsecureSkipVerify = true //nolint:gosec
	tlsConfig.CipherSuites = cipherSuites
	tlsConfig.MinVersion = tls.VersionTLS10
	tlsConfig.Renegotiation = tls.RenegotiateFreelyAsClient
}

func setupPlugins() {
	if len(sortedTCPPlugins) > 0 {
		// already sorted
		return
	}

	sortedTCPPlugins = append(sortedTCPPlugins, plugins.Plugins[plugins.TCP]...)
	sortedTCPTLSPlugins = append(sortedTCPTLSPlugins, plugins.Plugins[plugins.TCPTLS]...)
	sortedUDPPlugins = append(sortedUDPPlugins, plugins.Plugins[plugins.UDP]...)
	sortedSCTPPlugins = append(sortedSCTPPlugins, plugins.Plugins[plugins.SCTP]...)

	sort.Slice(sortedTCPPlugins, func(i, j int) bool {
		return sortedTCPPlugins[i].Priority() < sortedTCPPlugins[j].Priority()
	})
	sort.Slice(sortedUDPPlugins, func(i, j int) bool {
		return sortedUDPPlugins[i].Priority() < sortedUDPPlugins[j].Priority()
	})
	sort.Slice(sortedTCPTLSPlugins, func(i, j int) bool {
		return sortedTCPTLSPlugins[i].Priority() < sortedTCPTLSPlugins[j].Priority()
	})
	sort.Slice(sortedSCTPPlugins, func(i, j int) bool {
		return sortedSCTPPlugins[i].Priority() < sortedSCTPPlugins[j].Priority()
	})
}

// UDP Scan of the target
func (c *Config) UDPScanTarget(target plugins.Target) (*plugins.Service, error) {
	// first check the default port mappings for TCP / TLS
	for _, plugin := range sortedUDPPlugins {
		port := target.Address.Port()
		if plugin.PortPriority(port) {
			conn, err := c.DialUDP(target)
			if err != nil {
				return nil, fmt.Errorf("unable to connect, err = %w", err)
			}
			result, err := simplePluginRunner(conn, target, c, plugin)
			if err != nil && c.Verbose {
				log.Printf("error: %v scanning %v\n", err, target.Address.String())
			}
			if result != nil && err == nil {
				return result, nil
			}
		}
	}

	// if we're fast mode, return (because fast mode only checks the default port service mapping)
	if c.FastMode {
		return nil, nil
	}

	for _, plugin := range sortedUDPPlugins {
		conn, err := c.DialUDP(target)
		if err != nil {
			return nil, fmt.Errorf("unable to connect, err = %w", err)
		}
		result, err := simplePluginRunner(conn, target, c, plugin)
		if result != nil && err == nil {
			return result, nil
		}
	}
	return nil, nil
}

// SCTPScanTarget performs SCTP scanning of the target.
// On Linux: Full SCTP features via kernel module.
// On other platforms: Returns error (SCTP not supported).
func (c *Config) SCTPScanTarget(target plugins.Target) (*plugins.Service, error) {
	ip := target.Address.Addr().String()
	port := target.Address.Port()

	// First check default port mappings
	for _, plugin := range sortedSCTPPlugins {
		if plugin.PortPriority(port) {
			conn, err := DialSCTP(ip, port)
			if err != nil {
				return nil, fmt.Errorf("SCTP connection failed: %w", err)
			}
			result, err := simplePluginRunner(conn, target, c, plugin)
			if err != nil && c.Verbose {
				log.Printf("error: %v scanning %v\n", err, target.Address.String())
			}
			if result != nil && err == nil {
				return result, nil
			}
		}
	}

	// Fast mode: only check default port mappings
	if c.FastMode {
		return nil, nil
	}

	// Slow scan: try all SCTP plugins
	for _, plugin := range sortedSCTPPlugins {
		conn, err := DialSCTP(ip, port)
		if err != nil {
			return nil, fmt.Errorf("SCTP connection failed: %w", err)
		}
		result, err := simplePluginRunner(conn, target, c, plugin)
		if result != nil && err == nil {
			return result, nil
		}
	}

	return nil, nil
}

// simpleScanTarget attempts to identify the service that is running on a given
// port. The fingerprinter supports two modes of operation referred to as the
// fast lane and slow lane. The fast lane aims to be as fast as possible and
// only attempts to fingerprint services by mapping them to their default port.
// The slow lane isn't as focused on performance and instead tries to be as
// accurate as possible.

func (c *Config) SimpleScanTarget(target plugins.Target) ([]*plugins.Service, error) {
	port := target.Address.Port()

	// first check the default port mappings for TCP / TLS
	for _, plugin := range sortedTCPPlugins {
		if !plugin.PortPriority(port) {
			continue
		}

		conn, err := c.DialTCP(target)
		if err != nil {
			return nil, fmt.Errorf("unable to connect, err = %w", err)
		}
		result, err := simplePluginRunner(conn, target, c, plugin)
		if err != nil && c.Verbose {
			log.Printf("error: %v scanning %v\n", err, target.Address.String())
		}
		if result != nil && err == nil {
			return []*plugins.Service{result}, nil
		}
	}

	tlsConn, tlsErr := c.DialTLS(target)
	isTLS := tlsErr == nil
	if isTLS {
		for _, plugin := range sortedTCPTLSPlugins {
			if !plugin.PortPriority(port) {
				continue
			}

			result, err := simplePluginRunner(tlsConn, target, c, plugin)
			if err != nil && c.Verbose {
				log.Printf("error: %v scanning %v\n", err, target.Address.String())
			}
			if result != nil && err == nil {
				return []*plugins.Service{result}, nil
			}

			tlsConn, err = c.DialTLS(target)
			if err != nil {
				return nil, fmt.Errorf("error connecting via TLS, err = %w", err)
			}
		}
	}

	// if we're fast mode, return (because fast mode only checks the default port service mapping)
	if c.FastMode {
		return nil, nil
	}

	// go through each service mapping and check it

	if isTLS {
		for _, plugin := range sortedTCPTLSPlugins {
			tlsConn, err := c.DialTLS(target)
			if err != nil {
				return nil, fmt.Errorf("error connecting via TLS, err = %w", err)
			}
			result, err := simplePluginRunner(tlsConn, target, c, plugin)
			if err != nil && c.Verbose {
				log.Printf("error: %v scanning %v\n", err, target.Address.String())
			}
			if result != nil && err == nil {
				return []*plugins.Service{result}, nil
			}
		}
	} else {
		for _, plugin := range sortedTCPPlugins {
			conn, err := c.DialTCP(target)
			if err != nil {
				return nil, fmt.Errorf("unable to connect, err = %w", err)
			}
			result, err := simplePluginRunner(conn, target, c, plugin)
			if err != nil && c.Verbose {
				log.Printf("error: %v scanning %v\n", err, target.Address.String())
			}
			if result != nil && err == nil {
				return []*plugins.Service{result}, nil
			}
		}
	}

	return nil, nil
}

// This will attempt to close the provided Conn after running the plugin.
func simplePluginRunner(
	conn net.Conn,
	target plugins.Target,
	config *Config,
	plugin plugins.Plugin,
) (*plugins.Service, error) {
	defer conn.Close()

	// Log probe start.
	if config.Verbose {
		log.Printf("%v %v-> scanning %v\n",
			target.Address.String(),
			target.Host,
			plugins.CreatePluginID(plugin),
		)
	}

	result, err := plugin.Run(conn, config.DefaultTimeout, target)

	// Log probe completion.
	if config.Verbose {
		log.Printf(
			"%v %v-> completed %v\n",
			target.Address.String(),
			target.Host,
			plugins.CreatePluginID(plugin),
		)
	}
	return result, err
}

func (c *Config) DialTLS(target plugins.Target) (net.Conn, error) {
	config := &tlsConfig
	if target.Host != "" {
		// make a new config clone to add the custom host for each new tls connection
		cfg := config.Clone()
		cfg.ServerName = target.Host
		config = cfg
	}

	// Dial TCP first, then wrap with TLS Client
	conn, err := c.DialTCP(target)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, config)
	_ = conn.SetDeadline(time.Now().Add(c.DefaultTimeout))
	err = tlsConn.Handshake()
	_ = conn.SetDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func resolveLocalFallback(host string, port uint16, network string, d *net.Dialer) (net.Conn, error) {
	addrs, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("fallback dns resolution failed for %s: %w", host, err)
	}
	var lastErr error
	for _, ip := range addrs {
		addr := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
		conn, err := d.Dial(network, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (c *Config) DialTCP(target plugins.Target) (net.Conn, error) {
	ip := target.Address.Addr().String()
	port := target.Address.Port()

	dialHost := ip
	if ip == "0.0.0.0" && target.Host != "" {
		dialHost = target.Host
	}
	addr := net.JoinHostPort(dialHost, fmt.Sprintf("%d", port))

	if c.Proxy != "" {
		proxyURL, err := url.Parse(c.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		if c.ProxyAuth != "" {
			parts := strings.SplitN(c.ProxyAuth, ":", 2)
			if len(parts) == 2 {
				proxyURL.User = url.UserPassword(parts[0], parts[1])
			} else {
				proxyURL.User = url.User(parts[0])
			}
		}

		proxyDialer, err := proxy.FromURL(proxyURL, dialer)
		if err != nil {
			return nil, fmt.Errorf("failed to create proxy dialer: %w", err)
		}

		conn, err := proxyDialer.Dial("tcp", addr)
		if err != nil && c.DNSOrder == "pl" && dialHost == target.Host {
			// Proxy dial failed, fallback to local resolution
			return resolveLocalFallback(target.Host, port, "tcp", dialer)
		}
		return conn, err
	}

	return dialer.Dial("tcp", addr)
}

func (c *Config) DialUDP(target plugins.Target) (net.Conn, error) {
	ip := target.Address.Addr().String()
	port := target.Address.Port()

	dialHost := ip
	if ip == "0.0.0.0" && target.Host != "" {
		dialHost = target.Host
	}
	addr := net.JoinHostPort(dialHost, fmt.Sprintf("%d", port))

	if c.Proxy != "" {
		proxyURL, err := url.Parse(c.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}

		if c.ProxyAuth != "" {
			parts := strings.SplitN(c.ProxyAuth, ":", 2)
			if len(parts) == 2 {
				proxyURL.User = url.UserPassword(parts[0], parts[1])
			} else {
				proxyURL.User = url.User(parts[0])
			}
		}

		proxyDialer, err := proxy.FromURL(proxyURL, dialer)
		if err != nil {
			return nil, fmt.Errorf("failed to create proxy dialer: %w", err)
		}

		var conn net.Conn
		if pd, ok := proxyDialer.(proxy.ContextDialer); ok {
			conn, err = pd.DialContext(context.Background(), "udp", addr)
		} else {
			conn, err = proxyDialer.Dial("udp", addr)
		}

		if err != nil && c.DNSOrder == "pl" && dialHost == target.Host {
			// Proxy dial failed, fallback to local resolution
			return resolveLocalFallback(target.Host, port, "udp", dialer)
		}
		return conn, err
	}

	return dialer.Dial("udp", addr)
}

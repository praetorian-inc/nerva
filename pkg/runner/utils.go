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
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/scan"
)

func checkConfig(config *cliConfig) error {
	config.scanDepth = strings.ToLower(config.scanDepth)

	if len(config.outputFile) > 0 {
		_, err := os.Stat(config.outputFile)
		if !os.IsNotExist(err) && config.overwriteOutput {
			fmt.Printf("File: %s already exists. Overwrite? [Y/N] ", config.outputFile)
			_, _ = fmt.Scan(&userInput)
			if strings.ToLower(userInput)[0] != 'y' {
				return fmt.Errorf("Output file %s already exists", config.outputFile)
			}
		}
	}
	if config.outputJSON && config.outputCSV {
		return errors.New("Only one output format can be specified (JSON or CSV)")
	}

	if config.useUDP {
		if err := checkUDPScanAllowed(); err != nil {
			return err
		}
	}

	if config.showErrors && !(config.outputJSON || config.outputCSV) {
		return errors.New("showErrors requires results being output in JSON or CSV format")
	}

	if config.resume && config.stateFile == "" {
		return errors.New("--resume requires --state-file")
	}

	if config.scanDepth != "" {
		switch ScanDepth(config.scanDepth) {
		case ScanDepthFast, ScanDepthThorough:
		default:
			return fmt.Errorf("invalid --scan-depth value %q: must be %q or %q", config.scanDepth, ScanDepthFast, ScanDepthThorough)
		}
		if config.fastMode {
			fmt.Fprintln(os.Stderr, "[WRN] --fast is deprecated when --scan-depth is set; --scan-depth takes precedence")
		}
	}

	return nil
}

// openUDPSocket is the UDP permission probe. Tests replace it.
var openUDPSocket = listenLocalUDP

func listenLocalUDP() error {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return err
	}
	return c.Close()
}

func udpPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EPERM || errno == syscall.EACCES
	}
	return false
}

// checkUDPScanAllowed probes whether this process can open a UDP socket.
// Nerva UDP scans use connected datagram sockets (net.Dial("udp", ...)) and
// do not need root. Error only when the OS or sandbox denies datagram sockets.
func checkUDPScanAllowed() error {
	err := openUDPSocket()
	if err == nil || !udpPermissionDenied(err) {
		return nil
	}
	return fmt.Errorf("UDP scan permission denied: cannot open a UDP socket: %w", err)
}

func createScanConfig(config cliConfig) scan.Config {
	cfg := scan.Config{
		DefaultTimeout: time.Duration(config.timeout) * time.Millisecond,
		FastMode:       config.fastMode,
		UDP:            config.useUDP,
		SCTP:           config.useSCTP,
		Verbose:        config.verbose,
		Workers:        config.workers,
		MaxHostConn:    config.maxHostConn,
		RateLimit:      config.rateLimit,
		Proxy:          config.proxy,
		ProxyAuth:      config.proxyAuth,
		DNSOrder:       config.dnsOrder,
		Misconfigs:     config.misconfigs,
		Deep:           config.deep,
	}

	// --scan-depth, when set, takes precedence over --fast (validated in checkConfig).
	switch ScanDepth(config.scanDepth) {
	case ScanDepthFast:
		cfg.ScanDepth = string(ScanDepthFast)
		cfg.FastMode = true
	case ScanDepthThorough:
		cfg.ScanDepth = string(ScanDepthThorough)
		cfg.FastMode = false
	}

	return cfg
}

func isPriorityPort(port int) bool {
	protocols := []plugins.Protocol{plugins.UDP, plugins.TCP, plugins.TCPTLS, plugins.SCTP}
	for _, protocol := range protocols {
		if pluginList, exists := plugins.Plugins[protocol]; exists {
			for _, plugin := range pluginList {
				if plugin.PortPriority(uint16(port)) {
					return true
				}
			}
		}
	}
	return false
}

func DefaultPortRange() string {
	priorityPorts := make([]string, 0)
	var port int
	for port = 1; port <= 65535; port++ {
		if isPriorityPort(port) {
			priorityPorts = append(priorityPorts, strconv.Itoa(port))
		}
	}
	return strings.Join(priorityPorts, ",")
}

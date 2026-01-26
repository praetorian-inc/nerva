//go:build linux

// Copyright 2022 Praetorian Security, Inc.
// Licensed under the Apache License, Version 2.0

package scan

import (
	"fmt"
	"net"

	"github.com/ishidawataru/sctp"
)

// DialSCTP establishes an SCTP connection to the target.
// Linux-only: uses kernel SCTP via ishidawataru/sctp library.
func DialSCTP(ip string, port uint16) (net.Conn, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	addr := &sctp.SCTPAddr{
		IPAddrs: []net.IPAddr{{IP: parsedIP}},
		Port:    int(port),
	}

	conn, err := sctp.DialSCTP("sctp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("SCTP dial failed: %w", err)
	}

	return conn, nil
}

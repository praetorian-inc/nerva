//go:build !linux

// Copyright 2022 Praetorian Security, Inc.
// Licensed under the Apache License, Version 2.0

package scan

import (
	"errors"
	"net"
)

// ErrSCTPNotSupported indicates SCTP is not fully supported on this platform.
var ErrSCTPNotSupported = errors.New("SCTP scanning requires Linux; limited support on this platform")

// DialSCTP attempts SCTP connection on non-Linux platforms.
// Returns error with clear message about platform limitations.
func DialSCTP(ip string, port uint16) (net.Conn, error) {
	// TODO: Implement pion/sctp fallback for basic detection
	// For now, return clear error about platform limitation
	return nil, ErrSCTPNotSupported
}

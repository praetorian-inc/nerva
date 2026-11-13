// Copyright 2026 Praetorian Security, Inc.
// Licensed under the Apache License, Version 2.0.
// See LICENSE for license information.

package rat

import (
	"net"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"google.golang.org/protobuf/encoding/protowire"
)

const maxDiscoveryBytes = 2048

// DiscoveryPlugin implements only the unauthenticated LAN discovery exchange.
// Compatible forks may use the same protocol; it does not assert RustDesk vendor
// identity, unattended access, or installation state. No LoginRequest is sent.
type DiscoveryPlugin struct{}

func init() { plugins.RegisterPlugin(&DiscoveryPlugin{}) }

func (p *DiscoveryPlugin) Name() string                  { return "rat-detector" }
func (p *DiscoveryPlugin) Type() plugins.Protocol        { return plugins.UDP }
func (p *DiscoveryPlugin) Priority() int                 { return 90 }
func (p *DiscoveryPlugin) PortPriority(port uint16) bool { return port == 21119 }

func (p *DiscoveryPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	if timeout <= 0 {
		return nil, nil
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(discoveryProbe()); err != nil {
		return nil, err
	}
	response := make([]byte, maxDiscoveryBytes+1)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}
	return identifyDiscovery(target, response[:n]), nil
}

// discoveryProbe encodes RendezvousMessage.peer_discovery (22), cmd (1) = ping.
// Wire layout verified against upstream rendezvous.proto and src/lan.rs.
func discoveryProbe() []byte {
	return []byte{0xb2, 0x01, 0x06, 0x0a, 0x04, 'p', 'i', 'n', 'g'}
}

// identifyDiscovery rejects malformed/truncated protobufs, request echoes, and
// incomplete replies. It deliberately does not retain device IDs or usernames.
func identifyDiscovery(target plugins.Target, response []byte) *plugins.Service {
	if len(response) == 0 || len(response) > maxDiscoveryBytes {
		return nil
	}
	field, wireType, tagSize := protowire.ConsumeTag(response)
	if tagSize < 0 || field != 22 || wireType != protowire.BytesType {
		return nil
	}
	payload, size := protowire.ConsumeBytes(response[tagSize:])
	if size < 0 || tagSize+size != len(response) {
		return nil
	}
	fields, valid := discoveryFields(payload)
	if !valid || string(fields[1]) != "pong" || len(fields[3]) == 0 || len(fields[5]) == 0 || len(fields[6]) == 0 {
		return nil
	}
	service := plugins.CreateServiceFrom(target, plugins.ServiceRemoteAccess{
		Product:  plugins.ProtoRustDeskDiscovery,
		Evidence: "RendezvousMessage.peer_discovery: cmd=pong; id, hostname and platform present (values omitted)",
	}, false, "", plugins.UDP)
	// Discovery alone does not prove an exposed remote-control listener; do not
	// generate an *-exposed vulnerability finding, even with --misconfigs.
	return service
}

func discoveryFields(payload []byte) (fields [8][]byte, valid bool) {
	var seen [8]bool
	for len(payload) > 0 {
		field, wireType, tagSize := protowire.ConsumeTag(payload)
		if tagSize < 0 || field < 1 {
			return fields, false
		}
		payload = payload[tagSize:]
		if field > 7 {
			size := protowire.ConsumeFieldValue(field, wireType, payload)
			if size < 0 {
				return fields, false
			}
			payload = payload[size:]
			continue
		}
		if seen[field] || wireType != protowire.BytesType {
			return fields, false
		}
		value, size := protowire.ConsumeBytes(payload)
		if size < 0 || !validDiscoveryText(value) {
			return fields, false
		}
		seen[field] = true
		fields[field] = value
		payload = payload[size:]
	}
	return fields, true
}

func validDiscoveryText(value []byte) bool {
	if len(value) > 512 || !utf8.Valid(value) {
		return false
	}
	for _, r := range string(value) {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

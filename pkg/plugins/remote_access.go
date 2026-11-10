// Copyright 2026 Praetorian Security, Inc.
// Licensed under the Apache License, Version 2.0.
// See LICENSE for license information.

package plugins

const (
	ProtoSplashtop         = "splashtop"
	ProtoDameware          = "dameware"
	ProtoRealVNC           = "realvnc"
	ProtoNoMachine         = "nomachine"
	ProtoRadmin            = "radmin"
	ProtoNetSupport        = "netsupport"
	ProtoRustDeskDiscovery = "rustdesk-compatible-discovery"
)

// ServiceRemoteAccess is the shared metadata for protocol-confirmed remote-access
// listeners. Product identifies a family, not an edition, installation state,
// successful authentication, or proof that unattended access is enabled.
type ServiceRemoteAccess struct {
	Product  string `json:"product"`
	Evidence string `json:"evidence"`
}

func (s ServiceRemoteAccess) Type() string {
	switch s.Product {
	case ProtoSplashtop, ProtoDameware, ProtoRealVNC, ProtoNoMachine, ProtoRadmin, ProtoNetSupport, ProtoRustDeskDiscovery:
		return s.Product
	default:
		return ProtoUnknown
	}
}

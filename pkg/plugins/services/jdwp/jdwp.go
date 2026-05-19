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

package jdwp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type JDWPPlugin struct{}

const JDWP = "jdwp"

var (
	commonJDWPPorts = map[int]struct{}{
		3999:  {},
		5000:  {},
		5005:  {},
		8000:  {},
		8453:  {},
		8787:  {},
		8788:  {},
		9001:  {},
		18000: {},
	}
)

type JDWPPacket struct {
	Length     uint32
	ID         uint32
	Flags      byte
	CommandSet byte
	Command    byte
}

func init() {
	plugins.RegisterPlugin(&JDWPPlugin{})
}

func DetectJDWPVersion(conn net.Conn, timeout time.Duration) (*plugins.ServiceJDWP, error) {
	info := plugins.ServiceJDWP{}

	versionRequest := JDWPPacket{
		Length:     0x0B,
		ID:         0x01,
		Flags:      0x00,
		CommandSet: 0x01,
		Command:    0x01,
	}

	versionBuf := new(bytes.Buffer)
	err := binary.Write(versionBuf, binary.BigEndian, versionRequest)
	if err != nil {
		return nil, err
	}

	response, err := utils.SendRecv(conn, versionBuf.Bytes(), timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < 11 {
		return nil, nil
	}

	var versionResponse JDWPPacket
	responseBuf := bytes.NewBuffer(response)
	err = binary.Read(responseBuf, binary.BigEndian, &versionResponse)
	if err != nil {
		return nil, err
	}

	if versionResponse.Length != (uint32(len((response)))) { // #nosec G115 -- response bounded by 4096-byte Recv
		return nil, nil
	}

	var descriptionLength uint32
	err = binary.Read(responseBuf, binary.BigEndian, &descriptionLength)
	if err != nil {
		return nil, err
	}
	if descriptionLength > uint32(responseBuf.Len()) { // #nosec G115 -- responseBuf bounded by 4096-byte Recv
		return nil, nil
	}
	description := make([]byte, descriptionLength)
	err = binary.Read(responseBuf, binary.BigEndian, &description)
	if err != nil {
		return nil, err
	}

	var jdwpMajor int32
	err = binary.Read(responseBuf, binary.BigEndian, &jdwpMajor)
	if err != nil {
		return nil, err
	}
	var jdwpMinor int32
	err = binary.Read(responseBuf, binary.BigEndian, &jdwpMinor)
	if err != nil {
		return nil, err
	}

	var vmVersionLength uint32
	err = binary.Read(responseBuf, binary.BigEndian, &vmVersionLength)
	if err != nil {
		return nil, err
	}
	if vmVersionLength > uint32(responseBuf.Len()) { // #nosec G115 -- responseBuf bounded by 4096-byte Recv
		return nil, nil
	}
	vmVersion := make([]byte, vmVersionLength)
	err = binary.Read(responseBuf, binary.BigEndian, &vmVersion)
	if err != nil {
		return nil, err
	}

	var vmNameLength uint32
	err = binary.Read(responseBuf, binary.BigEndian, &vmNameLength)
	if err != nil {
		return nil, err
	}
	if vmNameLength > uint32(responseBuf.Len()) { // #nosec G115 -- responseBuf bounded by 4096-byte Recv
		return nil, nil
	}
	vmName := make([]byte, vmNameLength)
	err = binary.Read(responseBuf, binary.BigEndian, &vmName)
	if err != nil {
		return nil, err
	}

	info.Description = string(description)
	info.JdwpMajor = jdwpMajor
	info.JdwpMinor = jdwpMinor
	info.VMVersion = string(vmVersion)
	info.VMName = string(vmName)

	return &info, nil
}

func (p *JDWPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	requestBytes := []byte{
		// ascii "JDWP-Handshake"
		0x4a, 0x44, 0x57, 0x50, 0x2d, 0x48, 0x61, 0x6e, 0x64, 0x73, 0x68, 0x61, 0x6b, 0x65,
	}

	response, err := utils.SendRecv(conn, requestBytes, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	if !bytes.Equal(requestBytes, response) {
		return nil, nil
	}

	info, err := DetectJDWPVersion(conn, timeout)
	if err != nil {
		return nil, err
	}

	var service *plugins.Service
	if info == nil {
		service = plugins.CreateServiceFrom(target, plugins.ServiceJDWP{}, false, "", plugins.TCP)
		if target.Misconfigs {
			service.SecurityFindings = []plugins.SecurityFinding{jdwpExposedFinding("JDWP handshake succeeded")}
		}
	} else {
		service = plugins.CreateServiceFrom(target, info, false, info.VMVersion, plugins.TCP)
		if target.Misconfigs {
			service.SecurityFindings = []plugins.SecurityFinding{jdwpExposedFinding(fmt.Sprintf("JDWP handshake succeeded, VM: %s %s", info.VMName, info.VMVersion))}
		}
	}
	return service, nil
}

// jdwpExposedFinding returns a SecurityFinding for an exposed JDWP debug interface.
func jdwpExposedFinding(evidence string) plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "jdwp-exposed",
		Severity:    plugins.SeverityCritical,
		Description: "JDWP debug interface exposed — allows remote code execution without authentication",
		Evidence:    evidence,
	}
}

func (p *JDWPPlugin) PortPriority(port uint16) bool {
	_, ok := commonJDWPPorts[int(port)]
	return ok
}

func (p *JDWPPlugin) Name() string {
	return JDWP
}
func (p *JDWPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *JDWPPlugin) Priority() int {
	return 500
}

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

package snmp

import (
	"encoding/asn1"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const SNMP = "SNMP"

type SNMPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&SNMPPlugin{})
}

func (f *SNMPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	InitialConnectionPackage := []byte{
		0x30, 0x29, // package length
		0x02, 0x01, 0x00, // Version: 1
		0x04, 0x06, // Community
		0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // method: "public"
		0xa0, // PDU type: GET
		0x1c,
		0x02, 0x04, 0xff, 0xff, 0xff, 0xff, // Request ID: -1
		0x02, 0x01, 0x00, // Error status: no error
		0x02, 0x01, 0x00, // Error index
		0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, // Object ID
		0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
	}
	response, err := utils.SendRecv(conn, InitialConnectionPackage, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	description, ok := parseDescription(response)
	if ok {
		service := plugins.CreateServiceFrom(target, plugins.ServiceSNMP{Description: description}, false, description, plugins.UDP)
		if target.Misconfigs {
			service.SecurityFindings = []plugins.SecurityFinding{{
				ID:          "snmp-default-community",
				Severity:    plugins.SeverityHigh,
				Description: "SNMP service responds to default 'public' community string",
				Evidence:    "community_string=public",
			}}
		}
		return service, nil
	}
	return nil, nil
}

// parseDescription validates the response to our public-community sysDescr GET.
// ASN.1 lengths and varbind types are decoded, never inferred from byte offsets.
func parseDescription(response []byte) (string, bool) {
	var message struct {
		Version   int
		Community []byte
		PDU       asn1.RawValue
	}
	rest, err := asn1.Unmarshal(response, &message)
	if err != nil || len(rest) != 0 || message.Version != 0 || string(message.Community) != "public" || message.PDU.Class != 2 || message.PDU.Tag != 2 || !message.PDU.IsCompound {
		return "", false
	}
	sequence, err := asn1.Marshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: message.PDU.Bytes})
	if err != nil {
		return "", false
	}
	var pdu struct {
		RequestID   int64
		ErrorStatus int
		ErrorIndex  int
		Bindings    []struct {
			Name  asn1.ObjectIdentifier
			Value asn1.RawValue
		}
	}
	if rest, err = asn1.Unmarshal(sequence, &pdu); err != nil || len(rest) != 0 || pdu.RequestID != -1 || pdu.ErrorStatus != 0 {
		return "", false
	}
	for _, binding := range pdu.Bindings {
		if binding.Name.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 2, 1, 1, 1, 0}) && binding.Value.Class == 0 && binding.Value.Tag == 4 && !binding.Value.IsCompound {
			return string(binding.Value.Bytes), true
		}
	}
	return "", false
}

func (f *SNMPPlugin) Name() string {
	return SNMP
}
func (f *SNMPPlugin) PortPriority(i uint16) bool {
	return i == 161
}

func (f *SNMPPlugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (f *SNMPPlugin) Priority() int {
	return 81
}

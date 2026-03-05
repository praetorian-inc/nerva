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

package plugins

import (
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// type SupportedIPVersion uint64
type Protocol uint64

const (
	IP Protocol = iota + 1
	UDP
	TCP
	TCPTLS
	SCTP
)

const TypeService string = "service"

const (
	ProtoActiveMQOpenWire = "activemq-openwire"
	ProtoATG              = "atg"
	ProtoAMQP             = "amqp"
	ProtoBACnet           = "bacnet"
	ProtoBGP              = "bgp"
	ProtoCassandra        = "cassandra"
	ProtoChromaDB         = "chromadb"
	ProtoCODESYS          = "codesys"
	ProtoCrimsonV3        = "crimsonv3"
	ProtoCUPS             = "cups"
	ProtoCouchDB          = "couchdb"
	ProtoDB2              = "db2"
	ProtoDHCP             = "dhcp"
	ProtoDiameter         = "diameter"
	ProtoDNP3             = "dnp3"
	ProtoDNS              = "dns"
	ProtoDocker           = "docker"
	ProtoEcho             = "echo"
	ProtoEtherCAT         = "ethercat"
	ProtoElasticsearch    = "elasticsearch"
	ProtoEtcd             = "etcd"
	ProtoEthernetIP       = "ethernetip"
	ProtoFirebird         = "firebird"
	ProtoFox              = "fox"
	ProtoFTP              = "ftp"
	ProtoGESRTP           = "gesrtp"
	ProtoGit              = "git"
	ProtoGTPC             = "gtpc"
	ProtoGTPPrime         = "gtpprime"
	ProtoGTPU             = "gtpu"
	ProtoH323             = "h323"
	ProtoHARTIP           = "hartip"
	ProtoIAX2             = "iax2"
	ProtoHTTP             = "http"
	ProtoHTTP2            = "http2"
	ProtoHTTPS            = "https"
	ProtoIEC104           = "iec104"
	ProtoIKEv2            = "ikev2"
	ProtoIMAP             = "imap"
	ProtoIMAPS            = "imaps"
	ProtoIRC              = "irc"
	ProtoIRCS             = "ircs"
	ProtoInfluxDB         = "influxdb"
	ProtoIPMI             = "ipmi"
	ProtoIPP              = "ipp"
	ProtoIPSEC            = "ipsec"
	ProtoIUA              = "iua"
	ProtoJetDirect        = "jetdirect"
	ProtoJDWP             = "jdwp"
	ProtoKafka            = "kafka"
	ProtoKerberos         = "kerberos"
	ProtoKNXIP            = "knxip"
	ProtoKubernetes       = "kubernetes"
	ProtoL2TP             = "l2tp"
	ProtoLDAP             = "ldap"
	ProtoLDAPS            = "ldaps"
	ProtoLibreChat        = "librechat"
	ProtoM2UA             = "m2ua"
	ProtoM3UA             = "m3ua"
	ProtoMegaco           = "megaco"
	ProtoMGCP             = "mgcp"
	ProtoMemcached        = "memcached"
	ProtoMelsecQ          = "melsec-q"
	ProtoMilvus           = "milvus"
	ProtoMilvusMetrics    = "milvus-metrics"
	ProtoModbus           = "modbus"
	ProtoMongoDB          = "mongodb"
	ProtoMQTT             = "mqtt"
	ProtoMSSQL            = "mssql"
	ProtoMySQL            = "mysql"
	ProtoNATS             = "nats"
	ProtoNeo4j            = "neo4j"
	ProtoNRPE             = "nrpe"
	ProtoNetbios          = "netbios"
	ProtoNFS              = "nfs"
	ProtoNTP              = "ntp"
	ProtoOMRONFINS        = "omron-fins"
	ProtoOPCUA            = "opcua"
	ProtoOpenVPN          = "openvpn"
	ProtoOracle           = "oracle"
	ProtoPCOM             = "pcom"
	ProtoPFCP             = "pfcp"
	ProtoPinecone         = "pinecone"
	ProtoPCWorx           = "pcworx"
	ProtoPOP3             = "pop3"
	ProtoPOP3S            = "pop3s"
	ProtoPPTP             = "pptp"
	ProtoPostgreSQL       = "postgresql"
	ProtoProConOS         = "proconos"
	ProtoPROFINET         = "profinet"
	ProtoPulsar           = "pulsar"
	ProtoPulsarAdmin      = "pulsar-admin"
	ProtoRDP              = "rdp"
	ProtoRedis            = "redis"
	ProtoRedisTLS         = "redis"
	ProtoRMI              = "java-rmi"
	ProtoRPC              = "rpc"
	ProtoRsync            = "rsync"
	ProtoRtsp             = "rtsp"
	ProtoS7comm           = "s7comm"
	ProtoSAPNetWeaver     = "sap-netweaver"
	ProtoSCCP             = "sccp"
	ProtoSGsAP            = "sgsap"
	ProtoSIP              = "sip"
	ProtoSIPS             = "sips"
	ProtoSOCKS4           = "socks4"
	ProtoSOCKS5           = "socks5"
	ProtoSMB              = "smb"
	ProtoSMPP             = "smpp"
	ProtoSMTP             = "smtp"
	ProtoSMTPS            = "smtps"
	ProtoSNMP             = "snmp"
	ProtoSNPP             = "snpp"
	ProtoSonarQube        = "sonarqube"
	ProtoSSH              = "ssh"
	ProtoSSTP             = "sstp"
	ProtoStun             = "stun"
	ProtoSUA              = "sua"
	ProtoSVN              = "svn"
	ProtoSybase           = "sybase"
	ProtoTelnet           = "telnet"
	ProtoTFTP             = "tftp"
	ProtoTURN             = "turn"
	ProtoVNC              = "vnc"
	ProtoVMwareESXi       = "vmware-esxi"
	ProtoVMwareVCenter    = "vmware-vcenter"
	ProtoVMwareVSphere    = "vmware-vsphere"
	ProtoWireGuard        = "wireguard"
	ProtoXMPP             = "xmpp"
	ProtoX11              = "x11"
	ProtoX2AP             = "x2ap"
	ProtoZabbixAgent      = "zabbix-agent"
	ProtoZooKeeper        = "zookeeper"
	ProtoUnknown          = "unknown"
)

// Used as a key for maps to plugins.
// i.e.: map[Service] Plugin
type PluginID struct {
	name     string
	protocol Protocol
}

type Metadata interface {
	Type() string
}

func (e Service) Type() string { return TypeService }

func (e Service) Metadata() Metadata {
	switch e.Protocol {
	case ProtoElasticsearch:
		var p ServiceElasticsearch
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoCouchDB:
		var p ServiceCouchDB
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoCrimsonV3:
		var p ServiceCrimsonV3
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoCUPS:
		var p ServiceCUPS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoDiameter:
		var p ServiceDiameter
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoDNP3:
		var p ServiceDNP3
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoDocker:
		var p ServiceDocker
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoDB2:
		var p ServiceDB2
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoCassandra:
		var p ServiceCassandra
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoChromaDB:
		var p ServiceChromaDB
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoCODESYS:
		var p ServiceCODESYS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoEtcd:
		var p ServiceEtcd
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoEtherCAT:
		var p ServiceEtherCAT
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoEthernetIP:
		var p ServiceEthernetIP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoFirebird:
		var p ServiceFirebird
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoFTP:
		var p ServiceFTP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoFox:
		var p ServiceFox
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoGit:
		var p ServiceGit
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoGTPC:
		var p ServiceGTPC
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoGESRTP:
		var p ServiceGESRTP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoGTPPrime:
		var p ServiceGTPPrime
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoGTPU:
		var p ServiceGTPU
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoH323:
		var p ServiceH323
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoHARTIP:
		var p ServiceHARTIP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPostgreSQL:
		var p ServicePostgreSQL
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoProConOS:
		var p ServiceProConOS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPROFINET:
		var p ServicePROFINET
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoVNC:
		var p ServiceVNC
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoVMwareESXi, ProtoVMwareVCenter, ProtoVMwareVSphere:
		var p ServiceVMware
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoWireGuard:
		var p ServiceWireGuard
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoX2AP:
		var p ServiceX2AP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoXMPP:
		var p ServiceXMPP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoTelnet:
		var p ServiceTelnet
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRedis:
		var p ServiceRedis
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoHTTP:
		var p ServiceHTTP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoHTTPS:
		var p ServiceHTTPS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoHTTP2:
		var p ServiceHTTP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSMB:
		var p ServiceSMB
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSMPP:
		var p ServiceSMPP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRDP:
		var p ServiceRDP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRPC:
		var p ServiceRPC
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMSSQL:
		var p ServiceMSSQL
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoNetbios:
		var p ServiceNetbios
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoKafka:
		var p ServiceKafka
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoKerberos:
		var p ServiceKerberos
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoKNXIP:
		var p ServiceKNXIP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoKubernetes:
		var p ServiceKubernetes
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoL2TP:
		var p ServiceL2TP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoOracle:
		var p ServiceOracle
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoOMRONFINS:
		var p ServiceOMRONFINS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoOPCUA:
		var p ServiceOPCUA
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPCOM:
		var p ServicePCOM
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPinecone:
		var p ServicePinecone
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPCWorx:
		var p ServicePCWorx
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMySQL:
		var p ServiceMySQL
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSMTP:
		var p ServiceSMTP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSMTPS:
		var p ServiceSMTPS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoLDAP:
		var p ServiceLDAP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoModbus:
		var p ServiceModbus
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMongoDB:
		var p ServiceMongoDB
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoNATS:
		var p ServiceNATS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoNeo4j:
		var p ServiceNeo4j
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoNRPE:
		var p ServiceNRPE
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoLDAPS:
		var p ServiceLDAPS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoLibreChat:
		var p ServiceLibreChat
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoM2UA:
		var p ServiceM2UA
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoM3UA:
		var p ServiceM3UA
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSUA:
		var p ServiceSUA
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSSH:
		var p ServiceSSH
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSSTP:
		var p ServiceSSTP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSVN:
		var p ServiceSVN
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSybase:
		var p ServiceSybase
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoIMAP:
		var p ServiceIMAP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRMI:
		var p ServiceRMI
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRsync:
		var p ServiceRsync
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoRtsp:
		var p ServiceRtsp
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoS7comm:
		var p ServiceS7comm
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSCCP:
		var p ServiceSCCP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSGsAP:
		var p ServiceSGsAP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoIMAPS:
		var p ServiceIMAPS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoIRC:
		var p ServiceIRC
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoIRCS:
		var p ServiceIRCS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoInfluxDB:
		var p ServiceInfluxDB
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoIAX2:
		var p ServiceIAX2
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoIKEv2:
		var p ServiceIKEv2
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoIPP:
		var p ServiceIPP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoIUA:
		var p ServiceIUA
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoJetDirect:
		var p ServiceJetDirect
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMQTT:
		var p ServiceMQTT
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMelsecQ:
		var p ServiceMelsecQ
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMegaco:
		var p ServiceMegaco
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMGCP:
		var p ServiceMGCP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMemcached:
		var p ServiceMemcached
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMilvus:
		var p ServiceMilvus
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoMilvusMetrics:
		var p ServiceMilvusMetrics
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPOP3:
		var p ServicePOP3
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPOP3S:
		var p ServicePOP3S
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPPTP:
		var p ServicePPTP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPulsar:
		var p ServicePulsar
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPulsarAdmin:
		var p ServicePulsarAdmin
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSNPP:
		var p ServiceSNPP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoIEC104:
		var p ServiceIEC104
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoTFTP:
		var p ServiceTFTP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoTURN:
		var p ServiceTURN
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSIP:
		var p ServiceSIP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSIPS:
		var p ServiceSIPS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSOCKS4:
		var p ServiceSOCKS4
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSOCKS5:
		var p ServiceSOCKS5
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoSonarQube:
		var p ServiceSonarQube
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoActiveMQOpenWire:
		var p ServiceActiveMQOpenWire
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoATG:
		var p ServiceATG
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoAMQP:
		var p ServiceAMQP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoBACnet:
		var p ServiceBACnet
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoBGP:
		var p ServiceBGP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoZabbixAgent:
		var p ServiceZabbixAgent
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoZooKeeper:
		var p ServiceZooKeeper
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoNFS:
		var p ServiceNFS
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoPFCP:
		var p ServicePFCP
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoX11:
		var p ServiceX11
		_ = json.Unmarshal(e.Raw, &p)
		return p
	default:
		var p ServiceUnknown
		_ = json.Unmarshal(e.Raw, &p)
		return p
	}
}

type ServiceUnknown map[string]any

func (e ServiceUnknown) Type() string { return ProtoUnknown }

func (e ServiceUnknown) Map() map[string]any { return e }

func CreateServiceFrom(target Target, m Metadata, tls bool, version string, transport Protocol) *Service {
	service := Service{}
	b, _ := json.Marshal(m)

	service.Host = target.Host
	service.IP = target.Address.Addr().String()
	service.Port = int(target.Address.Port())
	service.Protocol = m.Type()
	service.Transport = strings.ToLower(transport.String())
	service.Raw = json.RawMessage(b)
	if version != "" {
		service.Version = version
	}
	service.TLS = tls

	return &service
}

type Target struct {
	Address netip.AddrPort
	Host    string
}

type Plugin interface {
	Run(net.Conn, time.Duration, Target) (*Service, error)
	PortPriority(uint16) bool
	Name() string
	Type() Protocol
	Priority() int
}

type Service struct {
	Host      string          `json:"host,omitempty"`
	IP        string          `json:"ip"`
	Port      int             `json:"port"`
	Protocol  string          `json:"protocol"`
	TLS       bool            `json:"tls"`
	Transport string          `json:"transport"`
	Version   string          `json:"version,omitempty"`
	Raw       json.RawMessage `json:"metadata"`
}

// HTTPFingerprint contains the full detection result from an HTTP fingerprinter,
// including version and metadata that were previously discarded by the pipeline.
type HTTPFingerprint struct {
	Technology string         `json:"technology"`
	Version    string         `json:"version,omitempty"`
	CPEs       []string       `json:"cpes,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

type ServiceHTTP struct {
	Status          string             `json:"status"`     // e.g. "200 OK"
	StatusCode      int                `json:"statusCode"` // e.g. 200
	ResponseHeaders http.Header        `json:"responseHeaders"`
	Technologies    []string           `json:"technologies,omitempty"`
	CPEs            []string           `json:"cpes,omitempty"`
	Fingerprints    []HTTPFingerprint  `json:"fingerprints,omitempty"`
}

func (e ServiceHTTP) Type() string { return ProtoHTTP }

type ServiceHTTPS struct {
	Status          string             `json:"status"`     // e.g. "200 OK"
	StatusCode      int                `json:"statusCode"` // e.g. 200
	ResponseHeaders http.Header        `json:"responseHeaders"`
	Technologies    []string           `json:"technologies,omitempty"`
	CPEs            []string           `json:"cpes,omitempty"`
	Fingerprints    []HTTPFingerprint  `json:"fingerprints,omitempty"`
}

func (e ServiceHTTPS) Type() string { return ProtoHTTPS }

type ServiceH323 struct {
	VendorID     string   `json:"vendorID,omitempty"`
	ProductName  string   `json:"productName,omitempty"`
	Version      string   `json:"version,omitempty"`
	TerminalType string   `json:"terminalType,omitempty"`
	CPEs         []string `json:"cpes,omitempty"`
}

func (e ServiceH323) Type() string { return ProtoH323 }

type ServiceHARTIP struct {
	Version       uint8  `json:"version"`       // HART-IP protocol version (0x01)
	MessageType   uint8  `json:"messageType"`   // Message type (0x01=Response, 0x03=Error, 0x0F=NAK)
	Status        uint8  `json:"status"`        // Status code
	StatusDesc    string `json:"statusDesc"`    // Status description (Success/Error/NAK)
	TransactionID uint16 `json:"transactionID"` // Transaction ID echoed from request
}

func (e ServiceHARTIP) Type() string { return ProtoHARTIP }

type ServiceRDP struct {
	OSFingerprint       string `json:"fingerprint,omitempty"` // e.g. Windows Server 2016 or 2019
	OSVersion           string `json:"osVersion,omitempty"`
	TargetName          string `json:"targetName,omitempty"`
	NetBIOSComputerName string `json:"netBIOSComputerName,omitempty"`
	NetBIOSDomainName   string `json:"netBIOSDomainName,omitempty"`
	DNSComputerName     string `json:"dnsComputerName,omitempty"`
	DNSDomainName       string `json:"dnsDomainName,omitempty"`
	ForestName          string `json:"forestName,omitempty"`
}

func (e ServiceRDP) Type() string { return ProtoRDP }

type ServiceRPC struct {
	Entries []RPCB `json:"entries"`
}

type RPCB struct {
	Program  int    `json:"program"`
	Version  int    `json:"version"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Owner    string `json:"owner"`
}

func (e ServiceRPC) Type() string { return ProtoRPC }

type ServiceSMB struct {
	SigningEnabled      bool   `json:"signingEnabled"`  // e.g. Is SMB Signing Enabled?
	SigningRequired     bool   `json:"signingRequired"` // e.g. Is SMB Signing Required?
	OSVersion           string `json:"osVersion"`
	NetBIOSComputerName string `json:"netBIOSComputerName,omitempty"`
	NetBIOSDomainName   string `json:"netBIOSDomainName,omitempty"`
	DNSComputerName     string `json:"dnsComputerName,omitempty"`
	DNSDomainName       string `json:"dnsDomainName,omitempty"`
	ForestName          string `json:"forestName,omitempty"`
}

func (e ServiceSMB) Type() string { return ProtoSMB }

type ServiceMySQL struct {
	PacketType   string   `json:"packetType"`     // the type of packet returned by the server (i.e. handshake or error)
	ErrorMessage string   `json:"errorMsg"`       // error message if the server returns an error packet
	ErrorCode    int      `json:"errorCode"`      // error code returned if the server returns an error packet
	CPEs         []string `json:"cpes,omitempty"` // Common Platform Enumeration identifiers for vulnerability tracking
}

func (e ServiceMySQL) Type() string { return ProtoMySQL }

func (e ServicePostgreSQL) Type() string { return ProtoPostgreSQL }

type ServicePostgreSQL struct {
	AuthRequired bool     `json:"authRequired"`
	CPEs         []string `json:"cpes,omitempty"`
}

type ServiceProConOS struct {
	LadderLogicRuntime string   `json:"ladderLogicRuntime,omitempty"` // Version from offset 13
	PLCType            string   `json:"plcType,omitempty"`            // PLC type from offset 45
	ProjectName        string   `json:"projectName,omitempty"`        // Project name from offset 78
	BootProject        string   `json:"bootProject,omitempty"`        // Boot project (variable offset)
	ProjectSourceCode  string   `json:"projectSourceCode,omitempty"`  // Source code file (variable offset)
	CPEs               []string `json:"cpes,omitempty"`
}

func (e ServiceProConOS) Type() string { return ProtoProConOS }

type ServicePOP3 struct {
	Banner string `json:"banner"`
}

func (e ServicePOP3) Type() string { return ProtoPOP3 }

type ServicePOP3S struct {
	Banner string `json:"banner"`
}

func (e ServicePOP3S) Type() string { return ProtoPOP3S }

type ServicePulsar struct {
	ProtocolVersion int      `json:"protocolVersion,omitempty"`
	CPEs            []string `json:"cpes,omitempty"`
}

func (e ServicePulsar) Type() string { return ProtoPulsar }

type ServicePulsarAdmin struct {
	Clusters []string `json:"clusters,omitempty"`
}

func (e ServicePulsarAdmin) Type() string { return ProtoPulsarAdmin }

type ServiceSNMP struct{}

func (e ServiceSNMP) Type() string { return ProtoSNMP }

type ServiceSNPP struct {
	Banner string `json:"banner"`
}

func (e ServiceSNPP) Type() string { return ProtoSNPP }

type ServiceSIP struct {
	Banner         string   `json:"banner,omitempty"`
	Server         string   `json:"server,omitempty"`
	AllowedMethods []string `json:"allowedMethods,omitempty"`
	CPEs           []string `json:"cpes,omitempty"`
}

func (e ServiceSIP) Type() string { return ProtoSIP }

type ServiceSIPS struct {
	Banner         string   `json:"banner,omitempty"`
	Server         string   `json:"server,omitempty"`
	AllowedMethods []string `json:"allowedMethods,omitempty"`
	CPEs           []string `json:"cpes,omitempty"`
}

func (e ServiceSIPS) Type() string { return ProtoSIPS }

type ServiceSOCKS5 struct {
	SelectedMethod  string   `json:"selectedMethod"`
	OfferedMethods  []string `json:"offeredMethods,omitempty"`
	AnonymousAccess bool     `json:"anonymousAccess"`
	CPEs            []string `json:"cpes,omitempty"`
}

func (e ServiceSOCKS5) Type() string { return ProtoSOCKS5 }

type ServiceSOCKS4 struct {
	Status          string   `json:"status"`
	SOCKS4a         bool     `json:"socks4a"`
	AnonymousAccess bool     `json:"anonymousAccess"`
	CPEs            []string `json:"cpes,omitempty"`
}

func (e ServiceSOCKS4) Type() string { return ProtoSOCKS4 }

type ServiceSonarQube struct {
	Status          string   `json:"status,omitempty"`
	AnonymousAccess bool     `json:"anonymousAccess,omitempty"`
	CPEs            []string `json:"cpes,omitempty"`
}

func (e ServiceSonarQube) Type() string { return ProtoSonarQube }

type ServiceSSTP struct {
	Server string   `json:"server,omitempty"` // Server header value (e.g., "Microsoft-HTTPAPI/2.0", "MikroTik-SSTP")
	Vendor string   `json:"vendor,omitempty"` // Identified vendor: "Microsoft", "MikroTik", or "Unknown"
	CPEs   []string `json:"cpes,omitempty"`   // Common Platform Enumeration identifiers
}

func (e ServiceSSTP) Type() string { return ProtoSSTP }

type ServiceNTP struct{}

func (e ServiceNTP) Type() string { return ProtoNTP }

type ServiceNetbios struct {
	NetBIOSName string `json:"netBIOSName"`
}

func (e ServiceNetbios) Type() string { return ProtoNetbios }

type ServiceIMAP struct {
	Banner string `json:"banner"`
}

func (e ServiceIMAP) Type() string { return ProtoIMAP }

type ServiceIMAPS struct {
	Banner string `json:"banner"`
}

func (e ServiceIMAPS) Type() string { return ProtoIMAPS }

type ServiceIRC struct {
	ServerName     string   `json:"serverName,omitempty"`
	NetworkName    string   `json:"networkName,omitempty"`
	Version        string   `json:"version,omitempty"`
	ServerSoftware string   `json:"serverSoftware,omitempty"`
	CreatedDate    string   `json:"createdDate,omitempty"`
	UserModes      string   `json:"userModes,omitempty"`
	ChannelModes   string   `json:"channelModes,omitempty"`
	UserCount      int      `json:"userCount,omitempty"`
	ChannelCount   int      `json:"channelCount,omitempty"`
	CPEs           []string `json:"cpes,omitempty"`
}

func (e ServiceIRC) Type() string { return ProtoIRC }

type ServiceIRCS struct {
	ServerName     string   `json:"serverName,omitempty"`
	NetworkName    string   `json:"networkName,omitempty"`
	Version        string   `json:"version,omitempty"`
	ServerSoftware string   `json:"serverSoftware,omitempty"`
	CreatedDate    string   `json:"createdDate,omitempty"`
	UserModes      string   `json:"userModes,omitempty"`
	ChannelModes   string   `json:"channelModes,omitempty"`
	UserCount      int      `json:"userCount,omitempty"`
	ChannelCount   int      `json:"channelCount,omitempty"`
	CPEs           []string `json:"cpes,omitempty"`
}

func (e ServiceIRCS) Type() string { return ProtoIRCS }

type ServiceInfluxDB struct {
	CPEs []string `json:"cpes,omitempty"` // Common Platform Enumeration identifiers for vulnerability tracking
}

func (e ServiceInfluxDB) Type() string { return ProtoInfluxDB }

type ServiceIKEv2 struct {
	ResponderSPI string `json:"responderSPI"`
	MessageID    string `json:"messageID"`
	Vendor       string `json:"vendor,omitempty"`
}

func (e ServiceIKEv2) Type() string { return "IKEv2" }

type ServiceIAX2 struct {
	Detected bool `json:"detected"`
}

func (e ServiceIAX2) Type() string { return ProtoIAX2 }

type ServiceIPSEC struct {
	ResponderISP string `json:"responderISP"`
	MessageID    string `json:"messageID"`
}

func (e ServiceIPSEC) Type() string { return ProtoIPSEC }

type ServiceIUA struct {
	InfoString   string `json:"infoString,omitempty"`
	ErrorCode    uint32 `json:"errorCode,omitempty"`
	MessageClass uint8  `json:"messageClass,omitempty"`
	MessageType  uint8  `json:"messageType,omitempty"`
}

func (e ServiceIUA) Type() string { return ProtoIUA }

type ServiceJetDirect struct {
	Manufacturer     string   `json:"manufacturer,omitempty"`
	Model            string   `json:"model,omitempty"`
	Firmware         string   `json:"firmware,omitempty"`
	RawID            string   `json:"rawId"`
	Status           string   `json:"status,omitempty"`
	FilesystemAccess bool     `json:"filesystemAccess,omitempty"`
	CPEs             []string `json:"cpes,omitempty"`
}

func (e ServiceJetDirect) Type() string { return ProtoJetDirect }

type ServicePPTP struct {
	Hostname            string `json:"hostname,omitempty"`
	VendorString        string `json:"vendorString,omitempty"`
	FirmwareRevision    uint16 `json:"firmwareRevision"`
	ProtocolVersion     string `json:"protocolVersion,omitempty"`
	FramingCapabilities uint32 `json:"framingCapabilities"`
	BearerCapabilities  uint32 `json:"bearerCapabilities"`
	MaxChannels         uint16 `json:"maxChannels"`
	ResultCode          uint8  `json:"resultCode"`
}

func (e ServicePPTP) Type() string { return ProtoPPTP }

type ServiceMSSQL struct {
	CPEs []string `json:"cpes,omitempty"` // Common Platform Enumeration identifiers for vulnerability tracking
}

func (e ServiceMSSQL) Type() string { return ProtoMSSQL }

type ServiceVNC struct{}

func (e ServiceVNC) Type() string { return ProtoVNC }

type ServiceVMware struct {
	ProductType   string   `json:"productType"`              // "esxi", "vcenter", or "vsphere"
	FullName      string   `json:"fullName,omitempty"`
	Build         string   `json:"build,omitempty"`
	ApiType       string   `json:"apiType,omitempty"`
	ApiVersion    string   `json:"apiVersion,omitempty"`
	OsType        string   `json:"osType,omitempty"`
	ProductLineId string   `json:"productLineId,omitempty"`
	CPEs          []string `json:"cpes,omitempty"`
}

func (e ServiceVMware) Type() string {
	switch e.ProductType {
	case "esxi":
		return ProtoVMwareESXi
	case "vcenter":
		return ProtoVMwareVCenter
	default:
		return ProtoVMwareVSphere
	}
}

type ServiceTelnet struct {
	ServerData string `json:"serverData"`
}

func (e ServiceTelnet) Type() string { return ProtoTelnet }

type ServiceTFTP struct {
	ErrorMessage string `json:"errorMessage,omitempty"`
}

func (e ServiceTFTP) Type() string { return ProtoTFTP }

type ServiceTURN struct {
	Software string `json:"software,omitempty"`
	Realm    string `json:"realm,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
}

func (e ServiceTURN) Type() string { return ProtoTURN }

type ServiceRedis struct {
	AuthRequired bool     `json:"authRequired:"`
	CPEs         []string `json:"cpes,omitempty"`
}

func (e ServiceRedis) Type() string { return ProtoRedis }

type ServiceElasticsearch struct {
	CPEs []string `json:"cpes,omitempty"` // Common Platform Enumeration identifiers for vulnerability tracking
}

func (e ServiceElasticsearch) Type() string { return ProtoElasticsearch }

type ServiceGTPC struct {
	Version string `json:"version"` // "GTPv1" or "GTPv2"
}

func (e ServiceGTPC) Type() string { return ProtoGTPC }

type ServiceGTPPrime struct{}

func (e ServiceGTPPrime) Type() string { return ProtoGTPPrime }

type ServiceGTPU struct{}

func (e ServiceGTPU) Type() string { return ProtoGTPU }

type ServicePFCP struct {
	RecoveryTimestamp uint32 `json:"recoveryTimestamp,omitempty"`
	NodeID            string `json:"nodeId,omitempty"`
}

func (e ServicePFCP) Type() string { return ProtoPFCP }

type ServiceFTP struct {
	Banner     string   `json:"banner"`
	Confidence string   `json:"confidence,omitempty"` // Detection confidence: "high", "medium", or "low"
	CPEs       []string `json:"cpes,omitempty"`
}

func (e ServiceFTP) Type() string { return ProtoFTP }

type ServiceFox struct {
	Version     string   `json:"version,omitempty"`     // Fox protocol version
	HostName    string   `json:"hostName,omitempty"`    // Device hostname
	HostAddress string   `json:"hostAddress,omitempty"` // Device IP address
	AppName     string   `json:"appName,omitempty"`     // Application name
	AppVersion  string   `json:"appVersion,omitempty"`  // Application version
	VMName      string   `json:"vmName,omitempty"`      // Virtual machine name
	VMVersion   string   `json:"vmVersion,omitempty"`   // VM version
	OSName      string   `json:"osName,omitempty"`      // Operating system name
	StationName string   `json:"stationName,omitempty"` // Station name
	BrandId     string   `json:"brandId,omitempty"`     // Brand identifier
	CPEs        []string `json:"cpes,omitempty"`        // Common Platform Enumeration identifiers for vulnerability tracking
}

func (e ServiceFox) Type() string { return ProtoFox }

type ServiceGESRTP struct {
	PLCName         string   `json:"plcName,omitempty"`
	DeviceIndicator uint8    `json:"deviceIndicator,omitempty"`
	CPEs            []string `json:"cpes,omitempty"`
}

func (e ServiceGESRTP) Type() string { return ProtoGESRTP }

// ServiceGit contains metadata extracted from a Git daemon ref advertisement.
type ServiceGit struct {
	ProtocolVersion int      `json:"protocolVersion,omitempty"` // 0=implicit, 1=explicit v1, 2=v2
	HeadRef         string   `json:"headRef,omitempty"`         // SHA-1 hash of HEAD
	Branches        []string `json:"branches,omitempty"`        // Branch names (without refs/heads/ prefix)
	Tags            []string `json:"tags,omitempty"`            // Tag names (without refs/tags/ prefix)
	Capabilities    []string `json:"capabilities,omitempty"`    // Server capabilities from ref advertisement
}

func (e ServiceGit) Type() string { return ProtoGit }

type ServiceSMPP struct {
	CPEs            []string `json:"cpes,omitempty"`            // Common Platform Enumeration identifiers for vulnerability tracking
	ProtocolVersion string   `json:"protocolVersion,omitempty"` // SMPP protocol version (e.g., "3.4", "5.0")
	SystemID        string   `json:"systemID,omitempty"`        // System ID from bind_transceiver_resp
	Vendor          string   `json:"vendor,omitempty"`          // Vendor identified from system_id
	Product         string   `json:"product,omitempty"`         // Product identified from system_id
}

func (e ServiceSMPP) Type() string { return ProtoSMPP }

type ServiceSMTP struct {
	Banner      string   `json:"banner"`
	AuthMethods []string `json:"auth_methods"`
}

func (e ServiceSMTP) Type() string { return ProtoSMTP }

type ServiceSMTPS struct {
	Banner      string   `json:"banner"`
	AuthMethods []string `json:"auth_methods"`
}

func (e ServiceSMTPS) Type() string { return ProtoSMTPS }

type ServiceStun struct {
	Info string `json:"info"`
}

func (e ServiceStun) Type() string { return ProtoStun }

type ServiceSSH struct {
	Banner              string `json:"banner"`
	PasswordAuthEnabled bool   `json:"passwordAuthEnabled"`
	Algo                string `json:"algo"`
	HostKey             string `json:"hostKey,omitempty"`
	HostKeyType         string `json:"hostKeyType,omitempty"`
	HostKeyFingerprint  string `json:"hostKeyFingerprint,omitempty"`
}

func (e ServiceSSH) Type() string { return ProtoSSH }

type ServiceSVN struct {
	MinVersion   int      `json:"minVersion"`
	MaxVersion   int      `json:"maxVersion"`
	AuthMechs    []string `json:"authMechs"`
	Capabilities []string `json:"capabilities"`
}

func (e ServiceSVN) Type() string { return ProtoSVN }

type ServiceSybase struct {
	CPEs    []string `json:"cpes,omitempty"`
	Version string   `json:"version,omitempty"`
}

func (e ServiceSybase) Type() string { return ProtoSybase }

type ServiceEthernetIP struct {
	VendorID    uint16   `json:"vendorId,omitempty"`
	VendorName  string   `json:"vendorName,omitempty"`
	DeviceType  uint16   `json:"deviceType,omitempty"`
	ProductCode uint16   `json:"productCode,omitempty"`
	Revision    string   `json:"revision,omitempty"`
	Serial      string   `json:"serial,omitempty"`
	ProductName string   `json:"productName,omitempty"`
	CPEs        []string `json:"cpes,omitempty"`
}

func (e ServiceEthernetIP) Type() string { return ProtoEthernetIP }

type ServiceLDAP struct{}

func (e ServiceLDAP) Type() string { return ProtoLDAP }

type ServiceLDAPS struct{}

func (e ServiceLDAPS) Type() string { return ProtoLDAPS }

type ServiceLibreChat struct {
	ConfigVersion string   `json:"configVersion,omitempty"`
	HasHealth     bool     `json:"hasHealth,omitempty"`
	CPEs          []string `json:"cpes,omitempty"`
}

func (e ServiceLibreChat) Type() string { return ProtoLibreChat }

type ServiceKafka struct{}

func (e ServiceKafka) Type() string { return ProtoKafka }

type ServiceKerberos struct {
	Realm     string `json:"realm,omitempty"`
	ErrorCode int    `json:"errorCode,omitempty"`
	ErrorText string `json:"errorText,omitempty"`
}

func (e ServiceKerberos) Type() string { return ProtoKerberos }

type ServiceKNXIP struct {
	DeviceName      string   `json:"deviceName"`                // Friendly name (30 chars max)
	KNXAddress      string   `json:"knxAddress"`                // Individual address "area.line.device"
	SerialNumber    string   `json:"serialNumber"`              // 6-byte hex string
	MACAddress      string   `json:"macAddress"`                // XX:XX:XX:XX:XX:XX
	KNXMedium       string   `json:"knxMedium,omitempty"`       // "TP1", "PL110", "RF", "IP"
	ServiceFamilies []string `json:"serviceFamilies,omitempty"` // ["Core", "Tunnelling", "Routing"]
}

func (e ServiceKNXIP) Type() string { return ProtoKNXIP }

type ServiceKubernetes struct {
	CPEs         []string `json:"cpes,omitempty"`
	GitVersion   string   `json:"gitVersion,omitempty"`
	GitCommit    string   `json:"gitCommit,omitempty"`
	BuildDate    string   `json:"buildDate,omitempty"`
	GoVersion    string   `json:"goVersion,omitempty"`
	Platform     string   `json:"platform,omitempty"`
	Distribution string   `json:"distribution,omitempty"` // k3s, gke, eks, aks, openshift, minikube, vanilla
	Vendor       string   `json:"vendor,omitempty"`       // kubernetes, rancher, google, aws, azure, redhat
}

func (e ServiceKubernetes) Type() string { return ProtoKubernetes }

type ServiceL2TP struct {
	ProtocolVersion  string `json:"protocolVersion,omitempty"`
	HostName         string `json:"hostName,omitempty"`
	VendorName       string `json:"vendorName,omitempty"`
	FirmwareRevision uint16 `json:"firmwareRevision,omitempty"`
	AssignedTunnelID uint16 `json:"assignedTunnelId,omitempty"`
	FramingCaps      uint32 `json:"framingCaps,omitempty"`
	BearerCaps       uint32 `json:"bearerCaps,omitempty"`
}

func (e ServiceL2TP) Type() string { return ProtoL2TP }

type ServiceOracle struct {
	Info string `json:"info"`
}

func (e ServiceOracle) Type() string { return ProtoOracle }

type ServicePCOM struct {
	Model     string   `json:"model,omitempty"`
	HWVersion string   `json:"hwVersion,omitempty"`
	OSVersion string   `json:"osVersion,omitempty"`
	UnitID    string   `json:"unitId,omitempty"`
	CPEs      []string `json:"cpes,omitempty"`
}

func (e ServicePCOM) Type() string { return ProtoPCOM }

type ServicePinecone struct {
	CPEs       []string `json:"cpes,omitempty"`       // Common Platform Enumeration with wildcard version
	APIVersion string   `json:"apiVersion,omitempty"` // Pinecone API version from x-pinecone-api-version header
}

func (e ServicePinecone) Type() string { return ProtoPinecone }

type ServiceOpenVPN struct{}

func (e ServiceOpenVPN) Type() string { return ProtoOpenVPN }

type ServiceWireGuard struct {
	DetectionMethod string `json:"detection_method"` // "response", "differential", "heuristic"
	Confidence      string `json:"confidence"`       // "high", "medium", "low"
}

func (e ServiceWireGuard) Type() string { return ProtoWireGuard }

type ServiceXMPP struct {
	StreamID       string   `json:"streamId,omitempty"`
	ServerFrom     string   `json:"serverFrom,omitempty"`
	AuthMechanisms []string `json:"authMechanisms,omitempty"`
	TLSSupport     string   `json:"tlsSupport,omitempty"`
	Compression    []string `json:"compression,omitempty"`
	CapsNode       string   `json:"capsNode,omitempty"`
	CapsVer        string   `json:"capsVer,omitempty"`
	ServerSoftware string   `json:"serverSoftware,omitempty"`
	CPEs           []string `json:"cpes,omitempty"`
}

func (e ServiceXMPP) Type() string { return ProtoXMPP }

type ServiceOMRONFINS struct {
	ControllerModel   string   `json:"controllerModel,omitempty"`
	ControllerVersion string   `json:"controllerVersion,omitempty"`
	CPEs              []string `json:"cpes,omitempty"`
}

func (e ServiceOMRONFINS) Type() string { return ProtoOMRONFINS }

type ServiceOPCUA struct {
	ApplicationName string   `json:"applicationName,omitempty"` // Server application name
	ProductURI      string   `json:"productUri,omitempty"`      // Product URI from server
	SecurityModes   []string `json:"securityModes,omitempty"`   // None, Sign, SignAndEncrypt
	CPEs            []string `json:"cpes,omitempty"`
}

func (e ServiceOPCUA) Type() string { return ProtoOPCUA }

type ServicePCWorx struct {
	PLCType         string   `json:"plcType,omitempty"`
	FirmwareVersion string   `json:"firmwareVersion,omitempty"`
	FirmwareDate    string   `json:"firmwareDate,omitempty"`
	FirmwareTime    string   `json:"firmwareTime,omitempty"`
	ModelNumber     string   `json:"modelNumber,omitempty"`
	CPEs            []string `json:"cpes,omitempty"`
}

func (e ServicePCWorx) Type() string { return ProtoPCWorx }

type ServiceMQTT struct{}

func (e ServiceMQTT) Type() string { return ProtoMQTT }

type ServiceMegaco struct {
	Version   string `json:"version,omitempty"`
	MID       string `json:"mid,omitempty"`
	Profile   string `json:"profile,omitempty"`
	ErrorCode int    `json:"errorCode,omitempty"`
}

func (e ServiceMegaco) Type() string { return ProtoMegaco }

type ServiceMemcached struct {
	Version string   `json:"version,omitempty"`
	CPEs    []string `json:"cpes,omitempty"`
}

func (e ServiceMemcached) Type() string { return ProtoMemcached }

type ServiceMGCP struct {
	ResponseCode int      `json:"responseCode,omitempty"`
	Endpoints    []string `json:"endpoints,omitempty"`
	Packages     []string `json:"packages,omitempty"`
}

func (e ServiceMGCP) Type() string { return ProtoMGCP }

type ServiceMelsecQ struct {
	CPUModel string   `json:"cpuModel,omitempty"`
	CPEs     []string `json:"cpes,omitempty"`
}

func (e ServiceMelsecQ) Type() string { return ProtoMelsecQ }

type ServiceMilvus struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceMilvus) Type() string { return ProtoMilvus }

type ServiceMilvusMetrics struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceMilvusMetrics) Type() string { return ProtoMilvusMetrics }

type ServiceModbus struct {
	VendorName  string   `json:"vendorName,omitempty"`  // Object ID 0x00: Vendor name
	ProductCode string   `json:"productCode,omitempty"` // Object ID 0x01: Product code
	Revision    string   `json:"revision,omitempty"`    // Object ID 0x02: Major.Minor revision
	VendorURL   string   `json:"vendorUrl,omitempty"`   // Object ID 0x03: Vendor URL
	ProductName string   `json:"productName,omitempty"` // Object ID 0x04: Product name
	ModelName   string   `json:"modelName,omitempty"`   // Object ID 0x05: Model name
	CPEs        []string `json:"cpes,omitempty"`        // Common Platform Enumeration identifiers
}

func (e ServiceModbus) Type() string { return ProtoModbus }

type ServiceMongoDB struct {
	MaxWireVersion int      `json:"maxWireVersion,omitempty"` // Wire protocol version (indicates capabilities, NOT precise version; e.g., wire 21 = MongoDB 7.0.x)
	MinWireVersion int      `json:"minWireVersion,omitempty"` // Minimum wire protocol version supported
	ServerType     string   `json:"serverType,omitempty"`     // "mongod" or "mongos"
	CPEs           []string `json:"cpes,omitempty"`
}

func (e ServiceMongoDB) Type() string { return ProtoMongoDB }

type ServiceNeo4j struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceNeo4j) Type() string { return ProtoNeo4j }

type ServiceNRPE struct {
	CommandArgsEnabled *bool    `json:"commandArgsEnabled,omitempty"`
	CPEs               []string `json:"cpes,omitempty"`
}

func (e ServiceNRPE) Type() string { return ProtoNRPE }

type ServiceNATS struct {
	ServerID     string   `json:"serverId,omitempty"`
	ServerName   string   `json:"serverName,omitempty"`
	AuthRequired bool     `json:"authRequired"`
	TLSRequired  bool     `json:"tlsRequired"`
	TLSAvailable bool     `json:"tlsAvailable,omitempty"`
	JetStream    bool     `json:"jetStream,omitempty"`
	Headers      bool     `json:"headers,omitempty"`
	Proto        int      `json:"proto,omitempty"`
	MaxPayload   int64    `json:"maxPayload,omitempty"`
	GoVersion    string   `json:"goVersion,omitempty"`
	GitCommit    string   `json:"gitCommit,omitempty"`
	Cluster      string   `json:"cluster,omitempty"`
	Domain       string   `json:"domain,omitempty"`
	ConnectURLs  []string `json:"connectUrls,omitempty"`
	ClientIP     string   `json:"clientIp,omitempty"`
	LDM          bool     `json:"ldm,omitempty"`
	CPEs         []string `json:"cpes,omitempty"`
}

func (e ServiceNATS) Type() string { return ProtoNATS }

type ServiceRtsp struct {
	ServerInfo string `json:"serverInfo"`
}

func (e ServiceRtsp) Type() string { return ProtoRtsp }

type ServiceS7comm struct {
	PLCType         string   `json:"plcType,omitempty"`         // "S7-300", "S7-400", "S7-1200", "S7-1500"
	ModuleType      string   `json:"moduleType,omitempty"`      // Module type identifier from SZL
	OrderCode       string   `json:"orderCode,omitempty"`       // 6ES7 XXX-XXXXX-XXXX
	SerialNumber    string   `json:"serialNumber,omitempty"`    // Hardware serial number
	FirmwareVersion string   `json:"firmwareVersion,omitempty"` // V1.2.3 format
	ProtectionLevel uint8    `json:"protectionLevel,omitempty"` // 1=none, 2=read, 3=full
	ModuleName      string   `json:"moduleName,omitempty"`      // PLC module name
	PlantID         string   `json:"plantId,omitempty"`         // Plant/system identifier
	CPEs            []string `json:"cpes,omitempty"`            // CPE identifiers
}

func (e ServiceS7comm) Type() string { return ProtoS7comm }

type ServicePROFINET struct {
	DeviceName string   `json:"deviceName,omitempty"`
	DeviceType string   `json:"deviceType,omitempty"`
	Vendor     string   `json:"vendor,omitempty"`
	CPEs       []string `json:"cpes,omitempty"`
}

func (e ServicePROFINET) Type() string { return ProtoPROFINET }

type ServiceDNS struct{}

func (e ServiceDNS) Type() string { return ProtoDNS }

type ServiceDHCP struct {
	Option string `json:"option"`
}

func (e ServiceDHCP) Type() string { return ProtoDHCP }

type ServiceCouchDB struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceCouchDB) Type() string { return ProtoCouchDB }

type ServiceCUPS struct {
	ServerHeader string   `json:"serverHeader,omitempty"`
	CPEs         []string `json:"cpes,omitempty"`
}

func (e ServiceCUPS) Type() string { return ProtoCUPS }

type ServiceDiameter struct {
	CPEs    []string `json:"cpes,omitempty"`
	Version string   `json:"version,omitempty"`
	Vendor  string   `json:"vendor,omitempty"`
	Product string   `json:"product,omitempty"`
}

func (e ServiceDiameter) Type() string { return ProtoDiameter }

type ServiceDNP3 struct {
	SourceAddress      uint16   `json:"sourceAddress,omitempty"`      // DNP3 source address
	DestinationAddress uint16   `json:"destinationAddress,omitempty"` // DNP3 destination address
	DeviceRole         string   `json:"deviceRole,omitempty"`         // "master" or "outstation"
	FunctionCode       uint8    `json:"functionCode,omitempty"`       // Function code used in detection
	CPEs               []string `json:"cpes,omitempty"`               // Common Platform Enumeration identifiers
}

func (e ServiceDNP3) Type() string { return ProtoDNP3 }

type ServiceDocker struct {
	ApiVersion string   `json:"apiVersion,omitempty"` // Docker API version (e.g., "1.43")
	Os         string   `json:"os,omitempty"`         // Operating system (e.g., "linux")
	Arch       string   `json:"arch,omitempty"`       // Architecture (e.g., "amd64")
	CPEs       []string `json:"cpes,omitempty"`       // Common Platform Enumeration identifiers
}

func (e ServiceDocker) Type() string { return ProtoDocker }

type ServiceDB2 struct {
	ServerName string   `json:"serverName,omitempty"` // DB2 instance name
	CPEs       []string `json:"cpes,omitempty"`
}

func (e ServiceDB2) Type() string { return ProtoDB2 }

type ServiceIPP struct {
	PrinterMakeAndModel string   `json:"printerMakeAndModel,omitempty"`
	FirmwareVersion     string   `json:"firmwareVersion,omitempty"`
	PrinterState        string   `json:"printerState,omitempty"`
	IPPVersions         []string `json:"ippVersions,omitempty"`
	PrinterName         string   `json:"printerName,omitempty"`
	PrinterURI          string   `json:"printerUri,omitempty"`
	CPEs                []string `json:"cpes,omitempty"`
}

func (e ServiceIPP) Type() string { return ProtoIPP }

type ServiceCassandra struct {
	Product          string   `json:"product,omitempty"`          // "Apache Cassandra", "ScyllaDB", "DataStax Enterprise"
	CQLVersion       string   `json:"cqlVersion,omitempty"`       // CQL version from SUPPORTED response (e.g., "3.4.5")
	ProtocolVersions []string `json:"protocolVersions,omitempty"` // Native protocol versions (e.g., ["3/v3", "4/v4", "5/v5"])
	Compression      []string `json:"compression,omitempty"`      // Compression algorithms (e.g., ["lz4", "snappy", "zstd"])
	Confidence       string   `json:"confidence,omitempty"`       // Version detection confidence ("high", "medium", "low")
	CPEs             []string `json:"cpes,omitempty"`
}

func (e ServiceCassandra) Type() string { return ProtoCassandra }

type ServiceChromaDB struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceChromaDB) Type() string { return ProtoChromaDB }

type ServiceCODESYS struct {
	Version     string   `json:"version,omitempty"`
	DeviceName  string   `json:"deviceName,omitempty"`
	VendorName  string   `json:"vendorName,omitempty"`
	OSType      string   `json:"osType,omitempty"`
	OSName      string   `json:"osName,omitempty"`
	AuthEnabled bool     `json:"authEnabled,omitempty"`
	CPEs        []string `json:"cpes,omitempty"`
}

func (e ServiceCODESYS) Type() string { return ProtoCODESYS }

type ServiceCrimsonV3 struct {
	Manufacturer string   `json:"manufacturer,omitempty"`
	Model        string   `json:"model,omitempty"`
	CPEs         []string `json:"cpes,omitempty"`
}

func (e ServiceCrimsonV3) Type() string { return ProtoCrimsonV3 }

type ServiceEtcd struct {
	CPEs           []string `json:"cpes,omitempty"`
	ClusterVersion string   `json:"clusterVersion,omitempty"`
	PortType       string   `json:"portType,omitempty"` // "client" or "peer"
}

func (e ServiceEtcd) Type() string { return ProtoEtcd }

type ServiceEcho struct{}

func (e ServiceEcho) Type() string { return ProtoEcho }

type ServiceEtherCAT struct {
	WorkingCounter uint16 `json:"workingCounter"` // Number of slaves that processed the request
	DatagramCount  int    `json:"datagramCount"`  // Number of datagrams in response
}

func (e ServiceEtherCAT) Type() string { return ProtoEtherCAT }

type ServiceFirebird struct {
	ProtocolVersion int32    `json:"protocol_version,omitempty"`
	CPEs            []string `json:"cpes,omitempty"`
}

func (e ServiceFirebird) Type() string { return ProtoFirebird }

type ServiceIPMI struct{}

func (e ServiceIPMI) Type() string { return ProtoIPMI }

type ServiceIEC104 struct{}

func (e ServiceIEC104) Type() string { return ProtoIEC104 }

type ServiceRsync struct{}

func (e ServiceRsync) Type() string { return ProtoRsync }

type ServiceJDWP struct {
	Description string `json:"description"`
	JdwpMajor   int32  `json:"jdwpMajor"`
	JdwpMinor   int32  `json:"jdwpMinor"`
	VMVersion   string `json:"VMVersion"`
	VMName      string `json:"VMName"`
}

func (e ServiceJDWP) Type() string { return ProtoJDWP }

type ServiceRMI struct {
	Endpoint string   `json:"endpoint,omitempty"`
	CPEs     []string `json:"cpes,omitempty"`
}

func (e ServiceRMI) Type() string { return ProtoRMI }

type ServiceM2UA struct {
	InfoString   string `json:"infoString,omitempty"`
	ErrorCode    uint32 `json:"errorCode,omitempty"`
	MessageClass uint8  `json:"messageClass,omitempty"`
	MessageType  uint8  `json:"messageType,omitempty"`
}

func (e ServiceM2UA) Type() string { return ProtoM2UA }

type ServiceM3UA struct {
	InfoString   string `json:"infoString,omitempty"`
	ErrorCode    uint32 `json:"errorCode,omitempty"`
	MessageClass uint8  `json:"messageClass,omitempty"`
	MessageType  uint8  `json:"messageType,omitempty"`
}

func (e ServiceM3UA) Type() string { return ProtoM3UA }

type ServiceSUA struct {
	InfoString   string `json:"infoString,omitempty"`
	ErrorCode    uint32 `json:"errorCode,omitempty"`
	MessageClass uint8  `json:"messageClass,omitempty"`
	MessageType  uint8  `json:"messageType,omitempty"`
}

func (e ServiceSUA) Type() string { return ProtoSUA }

type ServiceActiveMQOpenWire struct {
	Version int      `json:"version,omitempty"` // OpenWire protocol version (1-12)
	CPEs    []string `json:"cpes,omitempty"`
}

func (e ServiceActiveMQOpenWire) Type() string { return ProtoActiveMQOpenWire }

type ServiceATG struct {
	StationName string   `json:"stationName,omitempty"`
	TankCount   int      `json:"tankCount,omitempty"`
	Products    []string `json:"products,omitempty"`
	CPEs        []string `json:"cpes,omitempty"`
}

func (e ServiceATG) Type() string { return ProtoATG }

type ServiceAMQP struct {
	Product  string   `json:"product,omitempty"`  // e.g., "RabbitMQ"
	Version  string   `json:"version,omitempty"`  // e.g., "3.12.0"
	Platform string   `json:"platform,omitempty"` // e.g., "Erlang/OTP 26.0"
	CPEs     []string `json:"cpes,omitempty"`
}

func (e ServiceAMQP) Type() string { return ProtoAMQP }

type ServiceZooKeeper struct {
	CPEs        []string `json:"cpes,omitempty"`        // Common Platform Enumeration identifiers for vulnerability tracking
	Mode        string   `json:"mode,omitempty"`        // ZooKeeper mode: standalone, leader, follower, observer
	Connections int      `json:"connections,omitempty"` // Number of active connections
	NodeCount   int      `json:"nodeCount,omitempty"`   // Number of ZNodes in the namespace
	Restricted  bool     `json:"restricted,omitempty"`  // Whether commands are restricted by whitelist
}

func (e ServiceZooKeeper) Type() string { return ProtoZooKeeper }

type ServiceNFS struct {
	Version          int   `json:"version"`          // Highest detected NFS version (4, 3, or 2)
	DetectedVersions []int `json:"detectedVersions"` // All versions that responded successfully
}

func (e ServiceNFS) Type() string { return ProtoNFS }

type ServiceBACnet struct {
	DeviceInstance uint32   `json:"deviceInstance"`
	VendorID       uint16   `json:"vendorID"`
	VendorName     string   `json:"vendorName"`
	MaxAPDU        uint16   `json:"maxAPDU,omitempty"`
	Segmentation   string   `json:"segmentation,omitempty"`
	ModelName      string   `json:"modelName,omitempty"`
	FirmwareRev    string   `json:"firmwareRevision,omitempty"`
	CPEs           []string `json:"cpes,omitempty"`
}

func (e ServiceBACnet) Type() string { return ProtoBACnet }

type ServiceBGP struct {
	Version  uint8 `json:"version"`
	Detected bool  `json:"detected"`
}

func (e ServiceBGP) Type() string { return ProtoBGP }

type ServiceSCCP struct {
	DeviceType      string `json:"deviceType,omitempty"`
	ProtocolVersion string `json:"protocolVersion,omitempty"`
	MaxStreams      int    `json:"maxStreams,omitempty"`
	DeviceName      string `json:"deviceName,omitempty"`
}

func (e ServiceSCCP) Type() string { return ProtoSCCP }

type ServiceX2AP struct {
	ProcedureCode uint8 `json:"procedureCode,omitempty"`
	Criticality   uint8 `json:"criticality,omitempty"`
	MessageType   uint8 `json:"messageType,omitempty"` // 0=Initiating, 1=Successful, 2=Unsuccessful
}

func (e ServiceX2AP) Type() string { return ProtoX2AP }

type ServiceSGsAP struct {
	MessageType uint8 `json:"messageType,omitempty"`
	SGsCause    uint8 `json:"sgsCause,omitempty"`
}

func (e ServiceSGsAP) Type() string { return ProtoSGsAP }

type ServiceZabbixAgent struct {
	RemoteCommandsEnabled bool     `json:"remoteCommandsEnabled"`
	CPEs                  []string `json:"cpes,omitempty"`
}

func (e ServiceZabbixAgent) Type() string { return ProtoZabbixAgent }

type ServiceX11 struct {
	MajorVersion  uint16 `json:"majorVersion"`
	MinorVersion  uint16 `json:"minorVersion"`
	Vendor        string `json:"vendor,omitempty"`
	AccessGranted bool   `json:"accessGranted"`
	DisplayNumber int    `json:"displayNumber,omitempty"`
}

func (e ServiceX11) Type() string { return ProtoX11 }

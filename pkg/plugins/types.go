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

// Severity represents the severity level of a security finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// SecurityFinding represents a security misconfiguration detected during fingerprinting.
// Evidence should contain observable protocol-level data (e.g., banner text, response codes,
// negotiated parameters). Do not include credentials, tokens, or other secrets.
type SecurityFinding struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence,omitempty"`
}

// Valid returns true if the severity is a recognized value.
func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	default:
		return false
	}
}

const (
	ProtoActiveMQOpenWire = "activemq-openwire"
	ProtoATG              = "atg"
	ProtoAMQP             = "amqp"
	ProtoAnyDesk          = "anydesk"
	ProtoBACnet           = "bacnet"
	ProtoBGP              = "bgp"
	ProtoCassandra        = "cassandra"
	ProtoChromaDB         = "chromadb"
	ProtoCitrixICA        = "citrix-ica"
	ProtoCoAP             = "coap"
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
	ProtoMikroTikWinbox   = "mikrotik-winbox"
	ProtoMilvus           = "milvus"
	ProtoMilvusMetrics    = "milvus-metrics"
	ProtoModbus           = "modbus"
	ProtoMongoDB          = "mongodb"
	ProtoMQTT             = "mqtt"
	ProtoMSRPC            = "msrpc"
	ProtoMSSQL            = "mssql"
	ProtoMySQL            = "mysql"
	ProtoMySQLX           = "mysqlx"
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
	ProtoQdrant           = "qdrant"
	ProtoRDP              = "rdp"
	ProtoRedis            = "redis"
	ProtoRedisTLS         = "redis"
	ProtoRMI              = "java-rmi"
	ProtoRPC              = "rpc"
	ProtoRsync            = "rsync"
	ProtoRTMP             = "rtmp"
	ProtoRtsp             = "rtsp"
	ProtoS7comm           = "s7comm"
	ProtoSmartInstall     = "smart-install"
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
	ProtoTeamViewer       = "teamviewer"
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
	case ProtoCitrixICA:
		var p ServiceCitrixICA
		_ = json.Unmarshal(e.Raw, &p)
		return p
	case ProtoCoAP:
		var p ServiceCoAP
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
	case ProtoTeamViewer:
		var p ServiceTeamViewer
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
	case ProtoMSRPC:
		var p ServiceMSRPC
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
	case ProtoMySQLX:
		var p ServiceMySQLX
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
	case ProtoRTMP:
		var p ServiceRTMP
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
	case ProtoSmartInstall:
		var p ServiceSmartInstall
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
	case ProtoMikroTikWinbox:
		var p ServiceMikroTikWinbox
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
	case ProtoQdrant:
		var p ServiceQdrant
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
	case ProtoAnyDesk:
		var p ServiceAnyDesk
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
	if m != nil {
		service.Protocol = m.Type()
	} else {
		service.Protocol = ProtoUnknown
	}
	service.Transport = strings.ToLower(transport.String())
	service.Raw = json.RawMessage(b)
	if version != "" {
		service.Version = version
	}
	service.TLS = tls

	return &service
}

type Target struct {
	Address    netip.AddrPort
	Host       string
	Misconfigs bool // when true, plugins should populate SecurityFindings
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
	// AnonymousAccess is the canonical top-level field for anonymous access detection.
	// Per-service metadata types (e.g., ServiceSOCKS5) may also have their own AnonymousAccess
	// field for protocol-specific context; the Service-level field is authoritative for reporting.
	AnonymousAccess  bool              `json:"anonymous_access,omitempty"`
	SecurityFindings []SecurityFinding `json:"security_findings,omitempty"`
}

type ServiceHTTP struct {
	Status              string                    `json:"status"`      // e.g. "200 OK"
	StatusCode          int                       `json:"status_code"` // e.g. 200
	ResponseHeaders     http.Header               `json:"response_headers"`
	Technologies        []string                  `json:"technologies,omitempty"`
	CPEs                []string                  `json:"cpes,omitempty"`
	FingerprintMetadata map[string]map[string]any `json:"fingerprint_metadata,omitempty"`
}

func (e ServiceHTTP) Type() string { return ProtoHTTP }

type ServiceHTTPS struct {
	Status              string                    `json:"status"`      // e.g. "200 OK"
	StatusCode          int                       `json:"status_code"` // e.g. 200
	ResponseHeaders     http.Header               `json:"response_headers"`
	Technologies        []string                  `json:"technologies,omitempty"`
	CPEs                []string                  `json:"cpes,omitempty"`
	FingerprintMetadata map[string]map[string]any `json:"fingerprint_metadata,omitempty"`
}

func (e ServiceHTTPS) Type() string { return ProtoHTTPS }

type ServiceH323 struct {
	VendorID     string   `json:"vendor_id,omitempty"`
	ProductName  string   `json:"product_name,omitempty"`
	Version      string   `json:"version,omitempty"`
	TerminalType string   `json:"terminal_type,omitempty"`
	CPEs         []string `json:"cpes,omitempty"`
}

func (e ServiceH323) Type() string { return ProtoH323 }

type ServiceHARTIP struct {
	Version       uint8  `json:"version"`        // HART-IP protocol version (0x01)
	MessageType   uint8  `json:"message_type"`   // Message type (0x01=Response, 0x03=Error, 0x0F=NAK)
	Status        uint8  `json:"status"`         // Status code
	StatusDesc    string `json:"status_desc"`    // Status description (Success/Error/NAK)
	TransactionID uint16 `json:"transaction_id"` // Transaction ID echoed from request
}

func (e ServiceHARTIP) Type() string { return ProtoHARTIP }

type ServiceRDP struct {
	OSFingerprint       string `json:"fingerprint,omitempty"` // e.g. Windows Server 2016 or 2019
	OSVersion           string `json:"os_version,omitempty"`
	TargetName          string `json:"target_name,omitempty"`
	NetBIOSComputerName string `json:"netbios_computer_name,omitempty"`
	NetBIOSDomainName   string `json:"netbios_domain_name,omitempty"`
	DNSComputerName     string `json:"dns_computer_name,omitempty"`
	DNSDomainName       string `json:"dns_domain_name,omitempty"`
	ForestName          string `json:"forest_name,omitempty"`
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
	SigningEnabled      bool   `json:"signing_enabled"`  // e.g. Is SMB Signing Enabled?
	SigningRequired     bool   `json:"signing_required"` // e.g. Is SMB Signing Required?
	OSVersion           string `json:"os_version"`
	NetBIOSComputerName string `json:"netbios_computer_name,omitempty"`
	NetBIOSDomainName   string `json:"netbios_domain_name,omitempty"`
	DNSComputerName     string `json:"dns_computer_name,omitempty"`
	DNSDomainName       string `json:"dns_domain_name,omitempty"`
	ForestName          string `json:"forest_name,omitempty"`
}

func (e ServiceSMB) Type() string { return ProtoSMB }

type ServiceMySQL struct {
	PacketType   string   `json:"packet_type"`    // the type of packet returned by the server (i.e. handshake or error)
	ErrorMessage string   `json:"error_msg"`      // error message if the server returns an error packet
	ErrorCode    int      `json:"error_code"`     // error code returned if the server returns an error packet
	CPEs         []string `json:"cpes,omitempty"` // Common Platform Enumeration identifiers for vulnerability tracking
}

func (e ServiceMySQL) Type() string { return ProtoMySQL }

type ServiceMySQLX struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceMySQLX) Type() string { return ProtoMySQLX }

func (e ServicePostgreSQL) Type() string { return ProtoPostgreSQL }

type ServicePostgreSQL struct {
	AuthRequired bool     `json:"auth_required"`
	CPEs         []string `json:"cpes,omitempty"`
}

type ServiceProConOS struct {
	LadderLogicRuntime string   `json:"ladder_logic_runtime,omitempty"` // Version from offset 13
	PLCType            string   `json:"plc_type,omitempty"`             // PLC type from offset 45
	ProjectName        string   `json:"project_name,omitempty"`         // Project name from offset 78
	BootProject        string   `json:"boot_project,omitempty"`         // Boot project (variable offset)
	ProjectSourceCode  string   `json:"project_source_code,omitempty"`  // Source code file (variable offset)
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
	ProtocolVersion int      `json:"protocol_version,omitempty"`
	CPEs            []string `json:"cpes,omitempty"`
}

func (e ServicePulsar) Type() string { return ProtoPulsar }

type ServicePulsarAdmin struct {
	Clusters []string `json:"clusters,omitempty"`
}

func (e ServicePulsarAdmin) Type() string { return ProtoPulsarAdmin }

type ServiceQdrant struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceQdrant) Type() string { return ProtoQdrant }

type ServiceSNMP struct{}

func (e ServiceSNMP) Type() string { return ProtoSNMP }

type ServiceSNPP struct {
	Banner string `json:"banner"`
}

func (e ServiceSNPP) Type() string { return ProtoSNPP }

type ServiceSIP struct {
	Banner         string   `json:"banner,omitempty"`
	Server         string   `json:"server,omitempty"`
	AllowedMethods []string `json:"allowed_methods,omitempty"`
	CPEs           []string `json:"cpes,omitempty"`
}

func (e ServiceSIP) Type() string { return ProtoSIP }

type ServiceSIPS struct {
	Banner         string   `json:"banner,omitempty"`
	Server         string   `json:"server,omitempty"`
	AllowedMethods []string `json:"allowed_methods,omitempty"`
	CPEs           []string `json:"cpes,omitempty"`
}

func (e ServiceSIPS) Type() string { return ProtoSIPS }

type ServiceSOCKS5 struct {
	SelectedMethod  string   `json:"selected_method"`
	OfferedMethods  []string `json:"offered_methods,omitempty"`
	AnonymousAccess bool     `json:"anonymous_access"`
	CPEs            []string `json:"cpes,omitempty"`
}

func (e ServiceSOCKS5) Type() string { return ProtoSOCKS5 }

type ServiceSOCKS4 struct {
	Status          string   `json:"status"`
	SOCKS4a         bool     `json:"socks4a"`
	AnonymousAccess bool     `json:"anonymous_access"`
	CPEs            []string `json:"cpes,omitempty"`
}

func (e ServiceSOCKS4) Type() string { return ProtoSOCKS4 }

type ServiceSonarQube struct {
	Status          string   `json:"status,omitempty"`
	AnonymousAccess bool     `json:"anonymous_access,omitempty"`
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
	NetBIOSName string `json:"netbios_name"`
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
	ServerName     string   `json:"server_name,omitempty"`
	NetworkName    string   `json:"network_name,omitempty"`
	Version        string   `json:"version,omitempty"`
	ServerSoftware string   `json:"server_software,omitempty"`
	CreatedDate    string   `json:"created_date,omitempty"`
	UserModes      string   `json:"user_modes,omitempty"`
	ChannelModes   string   `json:"channel_modes,omitempty"`
	UserCount      int      `json:"user_count,omitempty"`
	ChannelCount   int      `json:"channel_count,omitempty"`
	CPEs           []string `json:"cpes,omitempty"`
}

func (e ServiceIRC) Type() string { return ProtoIRC }

type ServiceIRCS struct {
	ServerName     string   `json:"server_name,omitempty"`
	NetworkName    string   `json:"network_name,omitempty"`
	Version        string   `json:"version,omitempty"`
	ServerSoftware string   `json:"server_software,omitempty"`
	CreatedDate    string   `json:"created_date,omitempty"`
	UserModes      string   `json:"user_modes,omitempty"`
	ChannelModes   string   `json:"channel_modes,omitempty"`
	UserCount      int      `json:"user_count,omitempty"`
	ChannelCount   int      `json:"channel_count,omitempty"`
	CPEs           []string `json:"cpes,omitempty"`
}

func (e ServiceIRCS) Type() string { return ProtoIRCS }

type ServiceInfluxDB struct {
	CPEs []string `json:"cpes,omitempty"` // Common Platform Enumeration identifiers for vulnerability tracking
}

func (e ServiceInfluxDB) Type() string { return ProtoInfluxDB }

type ServiceIKEv2 struct {
	ResponderSPI string `json:"responder_spi"`
	MessageID    string `json:"message_id"`
	Vendor       string `json:"vendor,omitempty"`
}

func (e ServiceIKEv2) Type() string { return "IKEv2" }

type ServiceIAX2 struct {
	Detected bool `json:"detected"`
}

func (e ServiceIAX2) Type() string { return ProtoIAX2 }

type ServiceIPSEC struct {
	ResponderISP string `json:"responder_isp"`
	MessageID    string `json:"message_id"`
}

func (e ServiceIPSEC) Type() string { return ProtoIPSEC }

type ServiceIUA struct {
	InfoString   string `json:"info_string,omitempty"`
	ErrorCode    uint32 `json:"error_code,omitempty"`
	MessageClass uint8  `json:"message_class,omitempty"`
	MessageType  uint8  `json:"message_type,omitempty"`
}

func (e ServiceIUA) Type() string { return ProtoIUA }

type ServiceJetDirect struct {
	Manufacturer     string   `json:"manufacturer,omitempty"`
	Model            string   `json:"model,omitempty"`
	Firmware         string   `json:"firmware,omitempty"`
	RawID            string   `json:"raw_id"`
	Status           string   `json:"status,omitempty"`
	FilesystemAccess bool     `json:"filesystem_access,omitempty"`
	CPEs             []string `json:"cpes,omitempty"`
}

func (e ServiceJetDirect) Type() string { return ProtoJetDirect }

type ServicePPTP struct {
	Hostname            string `json:"hostname,omitempty"`
	VendorString        string `json:"vendor_string,omitempty"`
	FirmwareRevision    uint16 `json:"firmware_revision"`
	ProtocolVersion     string `json:"protocol_version,omitempty"`
	FramingCapabilities uint32 `json:"framing_capabilities"`
	BearerCapabilities  uint32 `json:"bearer_capabilities"`
	MaxChannels         uint16 `json:"max_channels"`
	ResultCode          uint8  `json:"result_code"`
}

func (e ServicePPTP) Type() string { return ProtoPPTP }

type ServiceMSRPC struct{}

func (e ServiceMSRPC) Type() string { return ProtoMSRPC }

type ServiceMSSQL struct {
	CPEs []string `json:"cpes,omitempty"` // Common Platform Enumeration identifiers for vulnerability tracking
}

func (e ServiceMSSQL) Type() string { return ProtoMSSQL }

type ServiceVNC struct{}

func (e ServiceVNC) Type() string { return ProtoVNC }

type ServiceVMware struct {
	ProductType   string   `json:"product_type"` // "esxi", "vcenter", or "vsphere"
	FullName      string   `json:"full_name,omitempty"`
	Build         string   `json:"build,omitempty"`
	ApiType       string   `json:"api_type,omitempty"`
	ApiVersion    string   `json:"api_version,omitempty"`
	OsType        string   `json:"os_type,omitempty"`
	ProductLineId string   `json:"product_line_id,omitempty"`
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

type ServiceTeamViewer struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceTeamViewer) Type() string { return ProtoTeamViewer }

type ServiceTelnet struct {
	ServerData string `json:"server_data"`
}

func (e ServiceTelnet) Type() string { return ProtoTelnet }

type ServiceTFTP struct {
	ErrorMessage string `json:"error_message,omitempty"`
}

func (e ServiceTFTP) Type() string { return ProtoTFTP }

type ServiceTURN struct {
	Software string `json:"software,omitempty"`
	Realm    string `json:"realm,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
}

func (e ServiceTURN) Type() string { return ProtoTURN }

type ServiceRedis struct {
	AuthRequired bool     `json:"auth_required"`
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
	RecoveryTimestamp uint32 `json:"recovery_timestamp,omitempty"`
	NodeID            string `json:"node_id,omitempty"`
}

func (e ServicePFCP) Type() string { return ProtoPFCP }

type ServiceFTP struct {
	Banner     string   `json:"banner"`
	Confidence string   `json:"confidence,omitempty"` // Detection confidence: "high", "medium", or "low"
	CPEs       []string `json:"cpes,omitempty"`
}

func (e ServiceFTP) Type() string { return ProtoFTP }

type ServiceFox struct {
	Version     string   `json:"version,omitempty"`      // Fox protocol version
	HostName    string   `json:"host_name,omitempty"`    // Device hostname
	HostAddress string   `json:"host_address,omitempty"` // Device IP address
	AppName     string   `json:"app_name,omitempty"`     // Application name
	AppVersion  string   `json:"app_version,omitempty"`  // Application version
	VMName      string   `json:"vm_name,omitempty"`      // Virtual machine name
	VMVersion   string   `json:"vm_version,omitempty"`   // VM version
	OSName      string   `json:"os_name,omitempty"`      // Operating system name
	StationName string   `json:"station_name,omitempty"` // Station name
	BrandId     string   `json:"brand_id,omitempty"`     // Brand identifier
	CPEs        []string `json:"cpes,omitempty"`         // Common Platform Enumeration identifiers for vulnerability tracking
}

func (e ServiceFox) Type() string { return ProtoFox }

type ServiceGESRTP struct {
	PLCName         string   `json:"plc_name,omitempty"`
	DeviceIndicator uint8    `json:"device_indicator,omitempty"`
	CPEs            []string `json:"cpes,omitempty"`
}

func (e ServiceGESRTP) Type() string { return ProtoGESRTP }

// ServiceGit contains metadata extracted from a Git daemon ref advertisement.
type ServiceGit struct {
	ProtocolVersion int      `json:"protocol_version,omitempty"` // 0=implicit, 1=explicit v1, 2=v2
	HeadRef         string   `json:"head_ref,omitempty"`         // SHA-1 hash of HEAD
	Branches        []string `json:"branches,omitempty"`         // Branch names (without refs/heads/ prefix)
	Tags            []string `json:"tags,omitempty"`             // Tag names (without refs/tags/ prefix)
	Capabilities    []string `json:"capabilities,omitempty"`     // Server capabilities from ref advertisement
}

func (e ServiceGit) Type() string { return ProtoGit }

type ServiceSMPP struct {
	CPEs            []string `json:"cpes,omitempty"`             // Common Platform Enumeration identifiers for vulnerability tracking
	ProtocolVersion string   `json:"protocol_version,omitempty"` // SMPP protocol version (e.g., "3.4", "5.0")
	SystemID        string   `json:"system_id,omitempty"`        // System ID from bind_transceiver_resp
	Vendor          string   `json:"vendor,omitempty"`           // Vendor identified from system_id
	Product         string   `json:"product,omitempty"`          // Product identified from system_id
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
	PasswordAuthEnabled bool   `json:"password_auth_enabled"`
	Algo                string `json:"algo"`
	HostKey             string `json:"host_key,omitempty"`
	HostKeyType         string `json:"host_key_type,omitempty"`
	HostKeyFingerprint  string `json:"host_key_fingerprint,omitempty"`
}

func (e ServiceSSH) Type() string { return ProtoSSH }

type ServiceSVN struct {
	MinVersion   int      `json:"min_version"`
	MaxVersion   int      `json:"max_version"`
	AuthMechs    []string `json:"auth_mechs"`
	Capabilities []string `json:"capabilities"`
}

func (e ServiceSVN) Type() string { return ProtoSVN }

type ServiceSybase struct {
	CPEs    []string `json:"cpes,omitempty"`
	Version string   `json:"version,omitempty"`
}

func (e ServiceSybase) Type() string { return ProtoSybase }

type ServiceEthernetIP struct {
	VendorID    uint16   `json:"vendor_id,omitempty"`
	VendorName  string   `json:"vendor_name,omitempty"`
	DeviceType  uint16   `json:"device_type,omitempty"`
	ProductCode uint16   `json:"product_code,omitempty"`
	Revision    string   `json:"revision,omitempty"`
	Serial      string   `json:"serial,omitempty"`
	ProductName string   `json:"product_name,omitempty"`
	CPEs        []string `json:"cpes,omitempty"`
}

func (e ServiceEthernetIP) Type() string { return ProtoEthernetIP }

type ServiceLDAP struct{}

func (e ServiceLDAP) Type() string { return ProtoLDAP }

type ServiceLDAPS struct{}

func (e ServiceLDAPS) Type() string { return ProtoLDAPS }

type ServiceLibreChat struct {
	ConfigVersion string   `json:"config_version,omitempty"`
	HasHealth     bool     `json:"has_health,omitempty"`
	CPEs          []string `json:"cpes,omitempty"`
}

func (e ServiceLibreChat) Type() string { return ProtoLibreChat }

type ServiceKafka struct{}

func (e ServiceKafka) Type() string { return ProtoKafka }

type ServiceKerberos struct {
	Realm     string `json:"realm,omitempty"`
	ErrorCode int    `json:"error_code,omitempty"`
	ErrorText string `json:"error_text,omitempty"`
}

func (e ServiceKerberos) Type() string { return ProtoKerberos }

type ServiceKNXIP struct {
	DeviceName      string   `json:"device_name"`                // Friendly name (30 chars max)
	KNXAddress      string   `json:"knx_address"`                // Individual address "area.line.device"
	SerialNumber    string   `json:"serial_number"`              // 6-byte hex string
	MACAddress      string   `json:"mac_address"`                // XX:XX:XX:XX:XX:XX
	KNXMedium       string   `json:"knx_medium,omitempty"`       // "TP1", "PL110", "RF", "IP"
	ServiceFamilies []string `json:"service_families,omitempty"` // ["Core", "Tunnelling", "Routing"]
}

func (e ServiceKNXIP) Type() string { return ProtoKNXIP }

type ServiceKubernetes struct {
	CPEs         []string `json:"cpes,omitempty"`
	GitVersion   string   `json:"git_version,omitempty"`
	GitCommit    string   `json:"git_commit,omitempty"`
	BuildDate    string   `json:"build_date,omitempty"`
	GoVersion    string   `json:"go_version,omitempty"`
	Platform     string   `json:"platform,omitempty"`
	Distribution string   `json:"distribution,omitempty"` // k3s, gke, eks, aks, openshift, minikube, vanilla
	Vendor       string   `json:"vendor,omitempty"`       // kubernetes, rancher, google, aws, azure, redhat
}

func (e ServiceKubernetes) Type() string { return ProtoKubernetes }

type ServiceL2TP struct {
	ProtocolVersion  string `json:"protocol_version,omitempty"`
	HostName         string `json:"host_name,omitempty"`
	VendorName       string `json:"vendor_name,omitempty"`
	FirmwareRevision uint16 `json:"firmware_revision,omitempty"`
	AssignedTunnelID uint16 `json:"assigned_tunnel_id,omitempty"`
	FramingCaps      uint32 `json:"framing_caps,omitempty"`
	BearerCaps       uint32 `json:"bearer_caps,omitempty"`
}

func (e ServiceL2TP) Type() string { return ProtoL2TP }

type ServiceOracle struct {
	Info string `json:"info"`
}

func (e ServiceOracle) Type() string { return ProtoOracle }

type ServicePCOM struct {
	Model     string   `json:"model,omitempty"`
	HWVersion string   `json:"hw_version,omitempty"`
	OSVersion string   `json:"os_version,omitempty"`
	UnitID    string   `json:"unit_id,omitempty"`
	CPEs      []string `json:"cpes,omitempty"`
}

func (e ServicePCOM) Type() string { return ProtoPCOM }

type ServicePinecone struct {
	CPEs       []string `json:"cpes,omitempty"`        // Common Platform Enumeration with wildcard version
	APIVersion string   `json:"api_version,omitempty"` // Pinecone API version from x-pinecone-api-version header
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
	StreamID       string   `json:"stream_id,omitempty"`
	ServerFrom     string   `json:"server_from,omitempty"`
	AuthMechanisms []string `json:"auth_mechanisms,omitempty"`
	TLSSupport     string   `json:"tls_support,omitempty"`
	Compression    []string `json:"compression,omitempty"`
	CapsNode       string   `json:"caps_node,omitempty"`
	CapsVer        string   `json:"caps_ver,omitempty"`
	ServerSoftware string   `json:"server_software,omitempty"`
	CPEs           []string `json:"cpes,omitempty"`
}

func (e ServiceXMPP) Type() string { return ProtoXMPP }

type ServiceOMRONFINS struct {
	ControllerModel   string   `json:"controller_model,omitempty"`
	ControllerVersion string   `json:"controller_version,omitempty"`
	CPEs              []string `json:"cpes,omitempty"`
}

func (e ServiceOMRONFINS) Type() string { return ProtoOMRONFINS }

type ServiceOPCUA struct {
	ApplicationName string   `json:"application_name,omitempty"` // Server application name
	ProductURI      string   `json:"product_uri,omitempty"`      // Product URI from server
	SecurityModes   []string `json:"security_modes,omitempty"`   // None, Sign, SignAndEncrypt
	CPEs            []string `json:"cpes,omitempty"`
}

func (e ServiceOPCUA) Type() string { return ProtoOPCUA }

type ServicePCWorx struct {
	PLCType         string   `json:"plc_type,omitempty"`
	FirmwareVersion string   `json:"firmware_version,omitempty"`
	FirmwareDate    string   `json:"firmware_date,omitempty"`
	FirmwareTime    string   `json:"firmware_time,omitempty"`
	ModelNumber     string   `json:"model_number,omitempty"`
	CPEs            []string `json:"cpes,omitempty"`
}

func (e ServicePCWorx) Type() string { return ProtoPCWorx }

type ServiceMQTT struct{}

func (e ServiceMQTT) Type() string { return ProtoMQTT }

type ServiceMegaco struct {
	Version   string `json:"version,omitempty"`
	MID       string `json:"mid,omitempty"`
	Profile   string `json:"profile,omitempty"`
	ErrorCode int    `json:"error_code,omitempty"`
}

func (e ServiceMegaco) Type() string { return ProtoMegaco }

type ServiceMemcached struct {
	Version string   `json:"version,omitempty"`
	CPEs    []string `json:"cpes,omitempty"`
}

func (e ServiceMemcached) Type() string { return ProtoMemcached }

type ServiceMGCP struct {
	ResponseCode int      `json:"response_code,omitempty"`
	Endpoints    []string `json:"endpoints,omitempty"`
	Packages     []string `json:"packages,omitempty"`
}

func (e ServiceMGCP) Type() string { return ProtoMGCP }

type ServiceMelsecQ struct {
	CPUModel string   `json:"cpu_model,omitempty"`
	CPEs     []string `json:"cpes,omitempty"`
}

func (e ServiceMelsecQ) Type() string { return ProtoMelsecQ }

type ServiceMikroTikWinbox struct {
	SubProtocol string   `json:"sub_protocol"`
	CPEs        []string `json:"cpes,omitempty"`
}

func (e ServiceMikroTikWinbox) Type() string { return ProtoMikroTikWinbox }

type ServiceMilvus struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceMilvus) Type() string { return ProtoMilvus }

type ServiceMilvusMetrics struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceMilvusMetrics) Type() string { return ProtoMilvusMetrics }

type ServiceModbus struct {
	VendorName  string   `json:"vendor_name,omitempty"`  // Object ID 0x00: Vendor name
	ProductCode string   `json:"product_code,omitempty"` // Object ID 0x01: Product code
	Revision    string   `json:"revision,omitempty"`     // Object ID 0x02: Major.Minor revision
	VendorURL   string   `json:"vendor_url,omitempty"`   // Object ID 0x03: Vendor URL
	ProductName string   `json:"product_name,omitempty"` // Object ID 0x04: Product name
	ModelName   string   `json:"model_name,omitempty"`   // Object ID 0x05: Model name
	CPEs        []string `json:"cpes,omitempty"`         // Common Platform Enumeration identifiers
}

func (e ServiceModbus) Type() string { return ProtoModbus }

type ServiceMongoDB struct {
	MaxWireVersion int      `json:"max_wire_version,omitempty"` // Wire protocol version (indicates capabilities, NOT precise version; e.g., wire 21 = MongoDB 7.0.x)
	MinWireVersion int      `json:"min_wire_version,omitempty"` // Minimum wire protocol version supported
	ServerType     string   `json:"server_type,omitempty"`      // "mongod" or "mongos"
	CPEs           []string `json:"cpes,omitempty"`
}

func (e ServiceMongoDB) Type() string { return ProtoMongoDB }

type ServiceNeo4j struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceNeo4j) Type() string { return ProtoNeo4j }

type ServiceNRPE struct {
	CommandArgsEnabled *bool    `json:"command_args_enabled,omitempty"`
	CPEs               []string `json:"cpes,omitempty"`
}

func (e ServiceNRPE) Type() string { return ProtoNRPE }

type ServiceNATS struct {
	ServerID     string   `json:"server_id,omitempty"`
	ServerName   string   `json:"server_name,omitempty"`
	AuthRequired bool     `json:"auth_required"`
	TLSRequired  bool     `json:"tls_required"`
	TLSAvailable bool     `json:"tls_available,omitempty"`
	JetStream    bool     `json:"jet_stream,omitempty"`
	Headers      bool     `json:"headers,omitempty"`
	Proto        int      `json:"proto,omitempty"`
	MaxPayload   int64    `json:"max_payload,omitempty"`
	GoVersion    string   `json:"go_version,omitempty"`
	GitCommit    string   `json:"git_commit,omitempty"`
	Cluster      string   `json:"cluster,omitempty"`
	Domain       string   `json:"domain,omitempty"`
	ConnectURLs  []string `json:"connect_urls,omitempty"`
	ClientIP     string   `json:"client_ip,omitempty"`
	LDM          bool     `json:"ldm,omitempty"`
	CPEs         []string `json:"cpes,omitempty"`
}

func (e ServiceNATS) Type() string { return ProtoNATS }

type ServiceRtsp struct {
	ServerInfo string `json:"server_info"`
}

func (e ServiceRtsp) Type() string { return ProtoRtsp }

type ServiceS7comm struct {
	PLCType         string   `json:"plc_type,omitempty"`         // "S7-300", "S7-400", "S7-1200", "S7-1500"
	ModuleType      string   `json:"module_type,omitempty"`      // Module type identifier from SZL
	OrderCode       string   `json:"order_code,omitempty"`       // 6ES7 XXX-XXXXX-XXXX
	SerialNumber    string   `json:"serial_number,omitempty"`    // Hardware serial number
	FirmwareVersion string   `json:"firmware_version,omitempty"` // V1.2.3 format
	ProtectionLevel uint8    `json:"protection_level,omitempty"` // 1=none, 2=read, 3=full
	ModuleName      string   `json:"module_name,omitempty"`      // PLC module name
	PlantID         string   `json:"plant_id,omitempty"`         // Plant/system identifier
	CPEs            []string `json:"cpes,omitempty"`             // CPE identifiers
}

func (e ServiceS7comm) Type() string { return ProtoS7comm }

type ServiceSmartInstall struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceSmartInstall) Type() string { return ProtoSmartInstall }

type ServicePROFINET struct {
	DeviceName string   `json:"device_name,omitempty"`
	DeviceType string   `json:"device_type,omitempty"`
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
	ServerHeader string   `json:"server_header,omitempty"`
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
	SourceAddress      uint16   `json:"source_address,omitempty"`      // DNP3 source address
	DestinationAddress uint16   `json:"destination_address,omitempty"` // DNP3 destination address
	DeviceRole         string   `json:"device_role,omitempty"`         // "master" or "outstation"
	FunctionCode       uint8    `json:"function_code,omitempty"`       // Function code used in detection
	CPEs               []string `json:"cpes,omitempty"`                // Common Platform Enumeration identifiers
}

func (e ServiceDNP3) Type() string { return ProtoDNP3 }

type ServiceDocker struct {
	ApiVersion string   `json:"api_version,omitempty"` // Docker API version (e.g., "1.43")
	Os         string   `json:"os,omitempty"`          // Operating system (e.g., "linux")
	Arch       string   `json:"arch,omitempty"`        // Architecture (e.g., "amd64")
	CPEs       []string `json:"cpes,omitempty"`        // Common Platform Enumeration identifiers
}

func (e ServiceDocker) Type() string { return ProtoDocker }

type ServiceDB2 struct {
	ServerName string   `json:"server_name,omitempty"` // DB2 instance name
	CPEs       []string `json:"cpes,omitempty"`
}

func (e ServiceDB2) Type() string { return ProtoDB2 }

type ServiceIPP struct {
	PrinterMakeAndModel string   `json:"printer_make_and_model,omitempty"`
	FirmwareVersion     string   `json:"firmware_version,omitempty"`
	PrinterState        string   `json:"printer_state,omitempty"`
	IPPVersions         []string `json:"ipp_versions,omitempty"`
	PrinterName         string   `json:"printer_name,omitempty"`
	PrinterURI          string   `json:"printer_uri,omitempty"`
	CPEs                []string `json:"cpes,omitempty"`
}

func (e ServiceIPP) Type() string { return ProtoIPP }

type ServiceCassandra struct {
	Product          string   `json:"product,omitempty"`           // "Apache Cassandra", "ScyllaDB", "DataStax Enterprise"
	CQLVersion       string   `json:"cql_version,omitempty"`       // CQL version from SUPPORTED response (e.g., "3.4.5")
	ProtocolVersions []string `json:"protocol_versions,omitempty"` // Native protocol versions (e.g., ["3/v3", "4/v4", "5/v5"])
	Compression      []string `json:"compression,omitempty"`       // Compression algorithms (e.g., ["lz4", "snappy", "zstd"])
	Confidence       string   `json:"confidence,omitempty"`        // Version detection confidence ("high", "medium", "low")
	CPEs             []string `json:"cpes,omitempty"`
}

func (e ServiceCassandra) Type() string { return ProtoCassandra }

type ServiceChromaDB struct {
	CPEs []string `json:"cpes,omitempty"`
}

func (e ServiceChromaDB) Type() string { return ProtoChromaDB }

type ServiceCitrixICA struct {
	BannerMatch bool     `json:"banner_match"` // true if double ICA signature matched (high confidence)
	CPEs        []string `json:"cpes,omitempty"`
}

func (e ServiceCitrixICA) Type() string { return ProtoCitrixICA }

type ServiceCoAP struct {
	Resources string `json:"resources,omitempty"`
}

func (e ServiceCoAP) Type() string { return ProtoCoAP }

type ServiceCODESYS struct {
	Version     string   `json:"version,omitempty"`
	DeviceName  string   `json:"device_name,omitempty"`
	VendorName  string   `json:"vendor_name,omitempty"`
	OSType      string   `json:"os_type,omitempty"`
	OSName      string   `json:"os_name,omitempty"`
	AuthEnabled bool     `json:"auth_enabled,omitempty"`
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
	ClusterVersion string   `json:"cluster_version,omitempty"`
	PortType       string   `json:"port_type,omitempty"` // "client" or "peer"
}

func (e ServiceEtcd) Type() string { return ProtoEtcd }

type ServiceEcho struct{}

func (e ServiceEcho) Type() string { return ProtoEcho }

type ServiceEtherCAT struct {
	WorkingCounter uint16 `json:"working_counter"` // Number of slaves that processed the request
	DatagramCount  int    `json:"datagram_count"`  // Number of datagrams in response
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

type ServiceRTMP struct{}

func (e ServiceRTMP) Type() string { return ProtoRTMP }

type ServiceJDWP struct {
	Description string `json:"description"`
	JdwpMajor   int32  `json:"jdwp_major"`
	JdwpMinor   int32  `json:"jdwp_minor"`
	VMVersion   string `json:"vm_version"`
	VMName      string `json:"vm_name"`
}

func (e ServiceJDWP) Type() string { return ProtoJDWP }

type ServiceRMI struct {
	Endpoint string   `json:"endpoint,omitempty"`
	CPEs     []string `json:"cpes,omitempty"`
}

func (e ServiceRMI) Type() string { return ProtoRMI }

type ServiceM2UA struct {
	InfoString   string `json:"info_string,omitempty"`
	ErrorCode    uint32 `json:"error_code,omitempty"`
	MessageClass uint8  `json:"message_class,omitempty"`
	MessageType  uint8  `json:"message_type,omitempty"`
}

func (e ServiceM2UA) Type() string { return ProtoM2UA }

type ServiceM3UA struct {
	InfoString   string `json:"info_string,omitempty"`
	ErrorCode    uint32 `json:"error_code,omitempty"`
	MessageClass uint8  `json:"message_class,omitempty"`
	MessageType  uint8  `json:"message_type,omitempty"`
}

func (e ServiceM3UA) Type() string { return ProtoM3UA }

type ServiceSUA struct {
	InfoString   string `json:"info_string,omitempty"`
	ErrorCode    uint32 `json:"error_code,omitempty"`
	MessageClass uint8  `json:"message_class,omitempty"`
	MessageType  uint8  `json:"message_type,omitempty"`
}

func (e ServiceSUA) Type() string { return ProtoSUA }

type ServiceActiveMQOpenWire struct {
	Version int      `json:"version,omitempty"` // OpenWire protocol version (1-12)
	CPEs    []string `json:"cpes,omitempty"`
}

func (e ServiceActiveMQOpenWire) Type() string { return ProtoActiveMQOpenWire }

type ServiceATG struct {
	StationName string   `json:"station_name,omitempty"`
	TankCount   int      `json:"tank_count,omitempty"`
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

type ServiceAnyDesk struct {
	CertSubject string   `json:"certSubject,omitempty"`
	SelfSigned  bool     `json:"selfSigned"`
	CPEs        []string `json:"cpes,omitempty"`
}

func (e ServiceAnyDesk) Type() string { return ProtoAnyDesk }

type ServiceZooKeeper struct {
	CPEs        []string `json:"cpes,omitempty"`        // Common Platform Enumeration identifiers for vulnerability tracking
	Mode        string   `json:"mode,omitempty"`        // ZooKeeper mode: standalone, leader, follower, observer
	Connections int      `json:"connections,omitempty"` // Number of active connections
	NodeCount   int      `json:"node_count,omitempty"`  // Number of ZNodes in the namespace
	Restricted  bool     `json:"restricted,omitempty"`  // Whether commands are restricted by whitelist
}

func (e ServiceZooKeeper) Type() string { return ProtoZooKeeper }

type ServiceNFS struct {
	Version          int   `json:"version"`           // Highest detected NFS version (4, 3, or 2)
	DetectedVersions []int `json:"detected_versions"` // All versions that responded successfully
}

func (e ServiceNFS) Type() string { return ProtoNFS }

type ServiceBACnet struct {
	DeviceInstance uint32   `json:"device_instance"`
	VendorID       uint16   `json:"vendor_id"`
	VendorName     string   `json:"vendor_name"`
	MaxAPDU        uint16   `json:"max_apdu,omitempty"`
	Segmentation   string   `json:"segmentation,omitempty"`
	ModelName      string   `json:"model_name,omitempty"`
	FirmwareRev    string   `json:"firmware_revision,omitempty"`
	CPEs           []string `json:"cpes,omitempty"`
}

func (e ServiceBACnet) Type() string { return ProtoBACnet }

type ServiceBGP struct {
	Version  uint8 `json:"version"`
	Detected bool  `json:"detected"`
}

func (e ServiceBGP) Type() string { return ProtoBGP }

type ServiceSCCP struct {
	DeviceType      string `json:"device_type,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
	MaxStreams      int    `json:"max_streams,omitempty"`
	DeviceName      string `json:"device_name,omitempty"`
}

func (e ServiceSCCP) Type() string { return ProtoSCCP }

type ServiceX2AP struct {
	ProcedureCode uint8 `json:"procedure_code,omitempty"`
	Criticality   uint8 `json:"criticality,omitempty"`
	MessageType   uint8 `json:"message_type,omitempty"` // 0=Initiating, 1=Successful, 2=Unsuccessful
}

func (e ServiceX2AP) Type() string { return ProtoX2AP }

type ServiceSGsAP struct {
	MessageType uint8 `json:"message_type,omitempty"`
	SGsCause    uint8 `json:"sgs_cause,omitempty"`
}

func (e ServiceSGsAP) Type() string { return ProtoSGsAP }

type ServiceZabbixAgent struct {
	RemoteCommandsEnabled bool     `json:"remote_commands_enabled"`
	CPEs                  []string `json:"cpes,omitempty"`
}

func (e ServiceZabbixAgent) Type() string { return ProtoZabbixAgent }

type ServiceX11 struct {
	MajorVersion  uint16 `json:"major_version"`
	MinorVersion  uint16 `json:"minor_version"`
	Vendor        string `json:"vendor,omitempty"`
	AccessGranted bool   `json:"access_granted"`
	DisplayNumber int    `json:"display_number,omitempty"`
}

func (e ServiceX11) Type() string { return ProtoX11 }

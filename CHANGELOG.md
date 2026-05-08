# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.0] - 2026-05-08

### Added

#### New Fingerprinters
- OPC UA security mode misconfiguration detection (LAB-2681)
- S7comm protection level misconfiguration detection (LAB-2682)
- Zyxel firewall HTTP fingerprinter (LAB-1840)
- GitLab DevOps Platform fingerprinter (LAB-1837)
- Doccano NLP annotation platform fingerprinter (LAB-1208)
- ConnectWise ScreenConnect HTTP fingerprinter (LAB-1838, CVE-2024-1709, CVE-2024-1708)
- WatchGuard Firebox fingerprinter + Sophos re-audit (LAB-1853)
- Roundcube Webmail HTTP fingerprinter
- HP iLO, HP Embedded Web Server (LaserJet/PageWide/OfficeJet/DesignJet), and HP ChaiSOE fingerprinters (LAB-1834)
- AJP (Apache JServ Protocol) fingerprinter on port 8009 using CPing/CPong handshake (LAB-1842)
- Boa (abandoned embedded web server) fingerprinter (LAB-1830)
- mini_httpd and micro_httpd HTTP fingerprinters (LAB-1829)

#### Security Enrichment
- Flag weak TLS versions in HTTPS fingerprinting (LAB-2262)
- Flag missing security headers: HSTS, CSP, X-Frame-Options (LAB-2261)
- Flag RDP end-of-life OS versions (LAB-2093)
- Flag memcached detection as no-auth high severity (LAB-2094)
- Flag SNMP default public community string (LAB-2092)
- Detect MongoDB unauthenticated access as critical finding (LAB-2263)
- MySQL anonymous access detection (LAB-2264)
- MQTT anonymous access detection (LAB-2266)
- Kafka SASL requirement check (LAB-2265)

#### Documentation
- Complete README rewrite with accurate protocol documentation
- Architecture diagram (Mermaid)
- Use Cases section for security professionals
- Troubleshooting guide
- Terminology glossary
- CITATION.cff for research citations

### Fixed
- Avoid indefinite stall in ssh.Dial()

### Changed
- Renamed examples/scan.go to examples/service-fingerprinting-example.go

## [1.3.0] - 2026-04-10

### Added

#### New Fingerprinters
- Sophos XG/XGS Firewall fingerprinter (LAB-1189)
- lighttpd HTTP fingerprinter (LAB-1828)
- LwM2M IoT device management plugin (LAB-1187)
- pgAdmin PostgreSQL management fingerprinter (LAB-1183)
- Backstage developer portal fingerprinter (LAB-1173)
- Kubeflow Central Dashboard fingerprinter (LAB-1177)
- MLflow ML platform fingerprinting plugin (LAB-1176)
- Gradio ML web UI fingerprinter (LAB-1174)
- MikroTik RouterOS fingerprinter (LAB-1196)
- RTMP streaming protocol plugin (LAB-1861)
- MS-RPC (DCE/RPC) plugin for Windows RPC detection (LAB-1860)
- Cisco Smart Install plugin (LAB-1859)
- MySQL X Protocol (mysqlx) plugin (LAB-1858)
- Mongoose embedded web server fingerprinter (LAB-1826)
- Streamlit fingerprinting plugin

#### Security Enrichment
- Security misconfiguration detection framework (LAB-1160)
- SSH weak crypto and password auth detection (LAB-1716, LAB-1717)

### Fixed
- Handle SSH keyboard-interactive auth failure without info request
- Report JDWP protocol identity when version detection fails
- Add stack trace to pool panic recovery logging
- Address additional panics in scan pool
- Top-level recover handler for JDWP
- CrimsonV3 false positive on MySQL X Protocol
- Firebird false positive fix

### Changed
- GitHub Actions release workflow for cross-platform builds

## [1.2.0] - 2026-03-27

### Added

#### New Fingerprinters
- Redis Commander fingerprinting plugin
- Microsoft Dynamics 365 / Power Apps Portals fingerprinter
- OPNsense firewall fingerprinter
- Ubiquiti UniFi/EdgeOS HTTP fingerprinters
- Cisco ASA/FTD appliance fingerprinter
- Open WebUI fingerprinting plugin
- Home Assistant HTTP fingerprinter
- YugabyteDB HTTP fingerprinter (LAB-1172)
- Swagger/OpenAPI HTTP fingerprinter
- CoAP service detection plugin
- Oracle Service Cloud (RightNow) fingerprinter
- AnyDesk remote desktop detector (LAB-1181)
- Apache Guacamole HTTP fingerprinter
- pfSense fingerprinter (reimplemented as HTTP fingerprinter)
- M2PA (MTP2 Peer Adaptation) fingerprinter
- M2UA fingerprinting plugin for port 2904/SCTP
- Ollama LLM inference server fingerprinter
- WordPress HTTP fingerprinter
- Citrix ICA virtual desktop plugin
- Adobe Experience Manager (AEM) HTTP fingerprinter

#### Security Enrichment
- Security misconfiguration detection foundation (LAB-1642)

#### Infrastructure
- Proxy and DNS resolution support with ProxyDialer and caching

### Fixed
- Convert remaining camelCase metadata keys to snake_case
- Preserve external API parsing struct tags as camelCase
- Reimplement pfSense as HTTP fingerprinter instead of standalone plugin

### Changed
- Standardize JSON output to snake_case convention (LAB-1427)

## [1.1.0] - 2026-03-13

### Added

#### New Fingerprinters
- PPTP service fingerprinting plugin
- IRC/IRCS service fingerprinting plugin
- Git daemon service fingerprinting plugin
- XMPP/Jabber service fingerprinting plugin
- MinIO object storage detection
- VMware vSphere fingerprinting (ESXi, vCenter, vSphere)
- Express.js HTTP fingerprinter
- Weaviate vector database HTTP fingerprinter
- LibreChat service detection and version fingerprinting
- H.323 protocol with structured H.225.0 parsing
- Microsoft Exchange Server fingerprinter
- Apache HTTP Server fingerprinter
- Apache Tomcat HTTP fingerprinter
- Tengine HTTP fingerprinter
- SonicWall firewall/VPN fingerprinter
- Check Point security gateway fingerprinter
- Juniper SRX/Junos firewall fingerprinter
- Portainer Docker management fingerprinter
- Qdrant vector database fingerprinter (LAB-1163)
- CockroachDB HTTP fingerprinter
- Gitea HTTP fingerprinter
- TiDB HTTP fingerprinter
- Keycloak HTTP fingerprinter (including WildFly variant)
- Splunk fingerprinter
- Go pprof HTTP fingerprinter
- SAP NetWeaver/ICM HTTP fingerprinter
- Harbor container registry fingerprinter
- Gotenberg fingerprinting plugin
- NVIDIA Triton Inference Server fingerprinter
- TeamViewer fingerprinting plugin (LAB-1180)
- LocalAI HTTP fingerprinter
- vLLM HTTP fingerprinter
- 4 HTTP fingerprinters from PALIG hunt

#### Protocols
- SUA (SCTP User Adaptation) fingerprinting plugin
- M2UA fingerprinting plugin

#### Infrastructure
- Channel-based worker pool for concurrent scanning
- Scan resume capability with worker pool integration
- Worker utilization metrics in progress output
- IPv6 literal address support in target parsing
- Fingerprint metadata propagation through HTTP pipeline

### Fixed
- XMPP split TCP segment handling
- RTSP bounds check to prevent panic on truncated responses
- Hostname URL-prefix check to prevent false positives
- Checkpoint false positive reduction (require 2+ body matches)
- SonicWall version extraction for real-world responses
- Juniper J-Web detection improvements
- Weaviate anonymous access flagging in metadata
- Apache httpd OS and module extraction

### Changed
- External contribution notification workflow

## [1.0.0] - 2024

### Added
- **SCTP Transport Support** (Linux only)
  - New `--sctp` / `-S` flag
  - Diameter-SCTP plugin for telecom network fingerprinting (3GPP/LTE/5G)

- **54 Protocol Detection Plugins**

  **Databases (18):**
  - Relational: PostgreSQL, MySQL, MSSQL, OracleDB, DB2, Sybase, Firebird
  - NoSQL: MongoDB, Redis, Cassandra, CouchDB, Elasticsearch, InfluxDB, Neo4j, Memcached
  - Vector: ChromaDB, Milvus, Pinecone

  **Remote Access (4):** SSH, RDP, Telnet, VNC

  **Web & API (2):** HTTP/HTTPS (with Wappalyzer tech detection), Kubernetes

  **Messaging (5):** Kafka (old/new), MQTT (3/5), SMTP/SMTPS, POP3/POP3S, IMAP/IMAPS

  **File Transfer (3):** FTP, SMB, Rsync

  **Directory (2):** LDAP, LDAPS

  **Network Services (10):** DNS (TCP/UDP), DHCP, NTP, SNMP, NetBIOS-NS, STUN, OpenVPN, IPsec, IPMI, Echo

  **Industrial & Telecom (5):** Modbus, IPMI, Diameter (TCP), Diameter-SCTP, SMPP

  **Developer Tools (4):** JDWP, Java RMI, RTSP, Linux RPC

- **Output Formats:** JSON, CSV, human-readable text
- **Fast Mode:** Default-port-only scanning for rapid reconnaissance
- **Library API:** Import as Go package for custom applications
- **Docker Support:** Containerized deployment

### Technical Details
- Default timeout: 2000ms (configurable via `-w`)
- UDP scanning requires `-U` flag (may need root on Linux/Darwin)
- SCTP requires Linux kernel support

## Attribution

Nerva is a maintained fork of [fingerprintx](https://github.com/praetorian-inc/fingerprintx), originally developed by Praetorian's intern class of 2022.

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

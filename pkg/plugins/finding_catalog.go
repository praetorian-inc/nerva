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

// FindingMeta holds the canonical metadata for a known finding type.
// The finding catalog is the authoritative source for severity calibration.
type FindingMeta struct {
	Title          string
	Severity       Severity
	Impact         string
	Recommendation string
	CVSS           string
}

// findingCatalog maps finding IDs to their canonical metadata.
// Enrich() uses this to populate Title, Impact, Recommendation, and to
// override severity to the catalog-authoritative value.
//
//nolint:gochecknoglobals // package-level registry by design
var findingCatalog = map[string]FindingMeta{
	// ── HTTP findings ────────────────────────────────────────────────────
	"http-missing-hsts": {
		Title:          "Missing HTTP Strict Transport Security",
		Severity:       SeverityLow,
		Impact:         "Without HSTS, browsers may connect over plaintext HTTP, exposing session tokens and credentials to network attackers via protocol downgrade or man-in-the-middle attacks.",
		Recommendation: "Configure the Strict-Transport-Security response header with a minimum max-age of 31536000 (one year) and include the includeSubDomains directive.",
		CVSS:           "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
	},
	"http-missing-csp": {
		Title:          "Missing Content-Security-Policy",
		Severity:       SeverityLow,
		Impact:         "Without CSP, the application relies solely on output encoding to prevent cross-site scripting. A single encoding miss allows full XSS exploitation with no browser-level mitigation.",
		Recommendation: "Deploy a Content-Security-Policy header that restricts script sources. Start with a report-only policy to identify violations before enforcing.",
		CVSS:           "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
	},
	"http-missing-x-frame-options": {
		Title:          "Missing X-Frame-Options",
		Severity:       SeverityLow,
		Impact:         "Without framing protections, an attacker can embed the application in a malicious page and trick users into performing unintended actions via clickjacking.",
		Recommendation: "Set the X-Frame-Options header to DENY or SAMEORIGIN. For modern browsers, also use the frame-ancestors directive in Content-Security-Policy.",
		CVSS:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
	},
	"http-cors-wildcard": {
		Title:          "Permissive CORS Policy",
		Severity:       SeverityLow,
		Impact:         "A wildcard Access-Control-Allow-Origin header allows any website to read cross-origin responses, potentially exposing sensitive data to unauthorized origins.",
		Recommendation: "Replace the wildcard origin with an explicit allowlist of trusted origins. Validate the Origin header server-side before reflecting it.",
		CVSS:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
	},
	"http-cors-wildcard-credentials": {
		Title:          "CORS Wildcard with Credentials Flag",
		Severity:       SeverityLow,
		Impact:         "The server returns Access-Control-Allow-Origin: * alongside Access-Control-Allow-Credentials: true. Browsers reject this combination per the Fetch specification, but it signals a server-side misconfiguration that may mask deeper CORS logic errors.",
		Recommendation: "Remove the wildcard origin or the credentials flag. If credentialed cross-origin requests are needed, reflect a validated origin from an allowlist.",
		CVSS:           "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
	},
	"http-server-version": {
		Title:          "Server Version Disclosure",
		Severity:       SeverityInfo,
		Impact:         "Exposing the server software and version in HTTP headers helps attackers fingerprint the technology stack and identify known vulnerabilities.",
		Recommendation: "Configure the web server to suppress or genericize the Server header. For example, set server_tokens off in Nginx or ServerTokens Prod in Apache.",
		CVSS:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
	},
	"http-directory-listing": {
		Title:          "Directory Listing Enabled",
		Severity:       SeverityLow,
		Impact:         "Auto-generated directory listings expose file names, directory structure, and potentially sensitive files such as configuration backups or source code.",
		Recommendation: "Disable automatic directory listing in the web server configuration. Ensure sensitive files are not stored in web-accessible directories.",
		CVSS:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
	},
	"http-cleartext": {
		Title:          "Cleartext HTTP Service",
		Severity:       SeverityLow,
		Impact:         "Cleartext HTTP exposes all transmitted data, including credentials and session tokens, to passive network eavesdropping.",
		Recommendation: "Enable TLS on all HTTP endpoints and redirect plaintext requests to HTTPS.",
		CVSS:           "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
	},
	"http-cleartext-form": {
		Title:          "Login Form Served Over Cleartext HTTP",
		Severity:       SeverityLow,
		Impact:         "Credentials submitted through forms served over unencrypted HTTP are transmitted in plaintext, enabling network-level credential interception.",
		Recommendation: "Serve all pages containing login or sensitive forms exclusively over HTTPS with HSTS.",
		CVSS:           "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
	},

	// ── TLS findings ─────────────────────────────────────────────────────
	"tls-weak-version-10": {
		Title:          "TLS 1.0 Supported",
		Severity:       SeverityLow,
		Impact:         "TLS 1.0 has known cryptographic weaknesses (BEAST, POODLE) that can allow an attacker to decrypt traffic under specific conditions.",
		Recommendation: "Disable TLS 1.0 and 1.1 on the server. Configure a minimum protocol version of TLS 1.2 with strong cipher suites.",
		CVSS:           "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
	},
	"tls-weak-version-11": {
		Title:          "TLS 1.1 Supported",
		Severity:       SeverityLow,
		Impact:         "TLS 1.1 is deprecated per RFC 8996. While no practical attacks are widely exploited, continued support signals outdated configuration and may violate compliance requirements.",
		Recommendation: "Disable TLS 1.1 and configure a minimum protocol version of TLS 1.2.",
		CVSS:           "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
	},
	"tls-certificate-expired": {
		Title:          "Expired TLS Certificate",
		Severity:       SeverityLow,
		Impact:         "An expired TLS certificate causes browser trust warnings and may indicate an abandoned or unmaintained service. It does not directly enable decryption but degrades user trust and signals poor security hygiene.",
		Recommendation: "Renew the TLS certificate and implement automated certificate management (e.g., ACME/Let's Encrypt) to prevent future expiration.",
		CVSS:           "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
	},
	"tls-self-signed": {
		Title:          "Self-Signed TLS Certificate",
		Severity:       SeverityInfo,
		Impact:         "A self-signed certificate cannot be validated against a trusted CA, making it impossible for clients to verify the server's identity without manual trust configuration.",
		Recommendation: "Replace self-signed certificates with certificates issued by a trusted Certificate Authority for production services.",
		CVSS:           "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",
	},
	"tls-weak-key": {
		Title:          "Weak TLS Certificate Key",
		Severity:       SeverityLow,
		Impact:         "Cryptographic keys below recommended minimum sizes (RSA 2048, EC 256) may be factored or broken with current or near-future computing resources, compromising all traffic encrypted with the certificate.",
		Recommendation: "Generate a new key pair meeting current NIST minimums: RSA 2048+ bits or ECDSA P-256+. Reissue the certificate with the new key.",
		CVSS:           "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
	},

	// ── SSH findings ─────────────────────────────────────────────────────
	"ssh-weak-cipher": {
		Title:          "SSH Weak Encryption Algorithms",
		Severity:       SeverityLow,
		Impact:         "Weak ciphers such as arcfour and 3des-cbc have known cryptographic weaknesses that could allow traffic decryption under certain conditions.",
		Recommendation: "Remove weak ciphers from the SSH server configuration. Restrict to modern algorithms such as chacha20-poly1305 and aes256-gcm.",
		CVSS:           "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
	},
	"ssh-weak-kex": {
		Title:          "SSH Weak Key Exchange Algorithms",
		Severity:       SeverityLow,
		Impact:         "Weak key exchange algorithms like diffie-hellman-group1-sha1 use small group sizes vulnerable to precomputation attacks.",
		Recommendation: "Configure the SSH server to use curve25519-sha256 or diffie-hellman-group16-sha512 as the preferred key exchange algorithms.",
		CVSS:           "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
	},
	"ssh-weak-mac": {
		Title:          "SSH Weak MAC Algorithms",
		Severity:       SeverityLow,
		Impact:         "Weak MAC algorithms such as hmac-md5 and hmac-sha1-96 have reduced collision resistance, potentially allowing message integrity bypass.",
		Recommendation: "Restrict MAC algorithms to hmac-sha2-256-etm or hmac-sha2-512-etm.",
		CVSS:           "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
	},
	"ssh-password-auth": {
		Title:          "SSH Password Authentication Enabled",
		Severity:       SeverityLow,
		Impact:         "Password authentication allows brute-force attacks against user accounts. Combined with weak or reused passwords, this can lead to unauthorized access.",
		Recommendation: "Disable password authentication and enforce public key or certificate-based authentication in the SSH server configuration.",
		CVSS:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
	},

	// ── SNMP ─────────────────────────────────────────────────────────────
	"snmp-default-community": {
		Title:          "SNMP Default Community String",
		Severity:       SeverityMedium,
		Impact:         "The default 'public' community string provides unauthenticated read access to system information including hostnames, interfaces, routing tables, and installed software. Write-community access may also be available.",
		Recommendation: "Change the SNMP community string to a non-default value. Migrate to SNMPv3 with authentication and encryption. Restrict SNMP access to management networks via firewall rules.",
		CVSS:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
	},

	// ── FTP ──────────────────────────────────────────────────────────────
	"ftp-cleartext": {
		Title:          "Cleartext FTP Service",
		Severity:       SeverityLow,
		Impact:         "FTP transmits all data including credentials in cleartext, enabling passive network eavesdropping of authentication material and file contents.",
		Recommendation: "Replace FTP with SFTP or FTPS. If FTP must remain, restrict access to trusted networks and enforce strong credentials.",
		CVSS:           "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
	},

	// ── Vault ────────────────────────────────────────────────────────────
	"vault-uninitialized": {
		Title:          "Uninitialized HashiCorp Vault",
		Severity:       SeverityMedium,
		Impact:         "An uninitialized Vault instance can be claimed by the first entity that sends an init request, granting full administrative control over the secrets engine.",
		Recommendation: "Initialize the Vault instance immediately through a trusted administrative channel. Restrict network access to the Vault API during initialization.",
		CVSS:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
	},
	"vault-unsealed-anonymous": {
		Title:          "HashiCorp Vault Unsealed Without Authentication",
		Severity:       SeverityMedium,
		Impact:         "The Vault instance is unsealed and its health endpoint is accessible without authentication, indicating the secrets engine may be reachable by unauthenticated users.",
		Recommendation: "Restrict network access to the Vault instance immediately. Review Vault ACL policies and audit logs for unauthorized access. Consider re-sealing and rotating all stored secrets.",
		CVSS:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	},

	// ── Database findings ────────────────────────────────────────────────
	"redis-no-auth": {
		Title:          "Redis Accessible Without Authentication",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated access to Redis allows attackers to read, modify, or delete cached data and potentially achieve remote code execution via Lua scripting or module loading.",
		Recommendation: "Enable Redis authentication with a strong password using the requirepass directive. Bind Redis to localhost or trusted network interfaces only.",
	},
	"mongodb-no-auth": {
		Title:          "MongoDB Accessible Without Authentication",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated access to MongoDB allows attackers to read, modify, or delete all databases and collections, potentially exfiltrating sensitive data.",
		Recommendation: "Enable MongoDB authentication and authorization. Bind to localhost or trusted interfaces and enforce access controls via SCRAM or x.509 authentication.",
	},
	"postgresql-no-auth": {
		Title:          "PostgreSQL Trust Authentication",
		Severity:       SeverityMedium,
		Impact:         "Trust authentication accepts all connections without credentials, granting full database access to any network-reachable client.",
		Recommendation: "Replace trust authentication with scram-sha-256 in pg_hba.conf. Restrict listen addresses to trusted network interfaces.",
	},
	"mysql-no-auth": {
		Title:          "MySQL Empty Root Password",
		Severity:       SeverityMedium,
		Impact:         "An empty root password allows any network-reachable client to gain full administrative access to all databases and stored data.",
		Recommendation: "Set a strong root password immediately. Restrict root login to localhost and create least-privilege accounts for application access.",
	},
	"cassandra-no-auth": {
		Title:          "Cassandra Accessible Without Authentication",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated access to Cassandra allows attackers to read, modify, or drop keyspaces and tables containing potentially sensitive data.",
		Recommendation: "Enable authentication and authorization in cassandra.yaml. Use PasswordAuthenticator and CassandraAuthorizer with strong credentials.",
	},
	"memcached-no-auth": {
		Title:          "Memcached Accessible Without Authentication",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated access to Memcached allows attackers to read cached data, poison cache entries, or abuse the instance for amplification attacks.",
		Recommendation: "Enable SASL authentication on Memcached. Bind to localhost or trusted interfaces and restrict access via firewall rules.",
	},
	"influxdb-no-auth": {
		Title:          "InfluxDB Accessible Without Authentication",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated access to InfluxDB allows attackers to read or modify time-series data, potentially exposing metrics, monitoring data, or operational telemetry.",
		Recommendation: "Enable InfluxDB authentication and create users with appropriate privileges. Restrict network access to trusted clients.",
	},

	// ── LDAP ─────────────────────────────────────────────────────────────
	"ldap-anonymous-bind": {
		Title:          "LDAP Anonymous Bind Permitted",
		Severity:       SeverityLow,
		Impact:         "Anonymous LDAP binding allows unauthenticated enumeration of directory entries, potentially exposing user accounts, group memberships, and organizational structure.",
		Recommendation: "Disable anonymous bind on the LDAP server. Require authentication for all bind operations and restrict read access to authorized principals.",
	},
	"ldap-cleartext": {
		Title:          "Cleartext LDAP Service",
		Severity:       SeverityLow,
		Impact:         "Cleartext LDAP transmits credentials and directory data without encryption, enabling passive network interception of bind credentials and query results.",
		Recommendation: "Enable LDAPS (LDAP over TLS) or STARTTLS on the LDAP server. Disable plaintext LDAP listeners on production systems.",
	},

	// ── Container and orchestration ──────────────────────────────────────
	"docker-unauth-api": {
		Title:          "Docker API Accessible Without Authentication",
		Severity:       SeverityMedium,
		Impact:         "An unauthenticated Docker API allows attackers to create privileged containers, mount the host filesystem, and achieve full host compromise.",
		Recommendation: "Restrict Docker API access to Unix sockets or TLS-authenticated endpoints. Never expose the Docker API to untrusted networks without mTLS.",
	},
	"docker-registry-unauthenticated-catalog": {
		Title:          "Docker Registry Unauthenticated Catalog Access",
		Severity:       SeverityMedium,
		Impact:         "An unauthenticated Docker registry allows attackers to pull proprietary images, push malicious images, or overwrite existing tags with backdoored versions.",
		Recommendation: "Enable authentication on the Docker registry. Use token-based authentication or integrate with an identity provider.",
	},
	"portainer-setup-exposed": {
		Title:          "Portainer Setup Wizard Exposed",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated Portainer access grants full container management capabilities, allowing attackers to deploy, modify, or destroy containers and access sensitive environment variables.",
		Recommendation: "Configure Portainer with strong authentication immediately. Restrict network access to the management interface to trusted administrators.",
	},
	"jenkins-script-console": {
		Title:          "Jenkins Script Console Exposed",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated Jenkins access allows attackers to view build configurations, access credentials stored in Jenkins, and execute arbitrary code via build pipelines.",
		Recommendation: "Enable Jenkins security and configure authentication. Disable anonymous read access and restrict script console access to administrators.",
	},
	"minio-exposed": {
		Title:          "MinIO Default Credentials",
		Severity:       SeverityMedium,
		Impact:         "Default MinIO credentials (minioadmin:minioadmin) grant full administrative access to all buckets and stored objects, allowing data exfiltration or destruction.",
		Recommendation: "Change the default access key and secret key immediately. Use IAM policies to enforce least-privilege access to buckets.",
	},

	// ── Message queues and streaming ─────────────────────────────────────
	"kafka-no-sasl": {
		Title:          "Kafka Without SASL Authentication",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated Kafka access allows attackers to consume messages, produce to topics, and enumerate cluster metadata, potentially exposing sensitive event data.",
		Recommendation: "Enable SASL authentication and TLS encryption on Kafka brokers. Configure ACLs to restrict topic access to authorized clients.",
	},
	"nats-no-auth": {
		Title:          "NATS Accessible Without Authentication",
		Severity:       SeverityLow,
		Impact:         "Unauthenticated NATS access allows attackers to subscribe to subjects, publish messages, and potentially disrupt message routing across the system.",
		Recommendation: "Enable NATS authentication using tokens, NKeys, or credentials. Configure authorization rules to restrict subject access.",
	},
	"nats-no-tls": {
		Title:          "NATS Without TLS",
		Severity:       SeverityLow,
		Impact:         "NATS without TLS transmits messages and credentials in cleartext.",
		Recommendation: "Enable TLS on the NATS server.",
	},
	"amqp-default-creds": {
		Title:          "AMQP Default Credentials",
		Severity:       SeverityMedium,
		Impact:         "Default AMQP credentials (guest:guest) grant access to message queues, allowing attackers to consume, publish, or purge messages and access management APIs.",
		Recommendation: "Change the default guest credentials. Create application-specific accounts with least-privilege permissions and disable the guest user.",
	},
	"mqtt-no-auth": {
		Title:          "MQTT Accessible Without Authentication",
		Severity:       SeverityLow,
		Impact:         "Unauthenticated MQTT access allows attackers to subscribe to all topics and publish messages, potentially controlling IoT devices or intercepting telemetry data.",
		Recommendation: "Enable MQTT authentication with username/password or client certificates. Configure topic-level ACLs to restrict access.",
	},

	// ── gRPC ─────────────────────────────────────────────────────────────
	"grpc-reflection-exposed": {
		Title:          "gRPC Reflection Exposed",
		Severity:       SeverityInfo,
		Impact:         "gRPC server reflection exposes the full service definition, including method signatures and message types, aiding reconnaissance of the API surface.",
		Recommendation: "Disable gRPC reflection in production deployments. If reflection is needed for internal tooling, restrict access via network controls.",
	},

	// ── Remote access ────────────────────────────────────────────────────
	"rdp-nla-disabled": {
		Title:          "RDP Network Level Authentication Disabled",
		Severity:       SeverityLow,
		Impact:         "Without NLA, an attacker can reach the RDP login screen without pre-authentication, enabling brute-force attacks and exposing the server to pre-authentication vulnerabilities.",
		Recommendation: "Enable Network Level Authentication (NLA) on the RDP server to require authentication before establishing the full RDP session.",
	},
	"rdp-deprecated-encryption": {
		Title:          "RDP Deprecated Encryption",
		Severity:       SeverityLow,
		Impact:         "RDP Standard Security encryption uses RC4 with weak key derivation, which may allow traffic decryption under certain conditions.",
		Recommendation: "Configure the RDP server to require Enhanced RDP Security (TLS/NLA) and disable Standard RDP Security encryption.",
	},
	"rdp-eol-os": {
		Title:          "RDP End-of-Life Operating System",
		Severity:       SeverityLow,
		Impact:         "RDP Standard Security encryption uses RC4 with weak key derivation, which may allow traffic decryption under certain conditions.",
		Recommendation: "Configure the RDP server to require Enhanced RDP Security (TLS/NLA) and disable Standard RDP Security encryption.",
	},
	"rdp-cleartext-credentials": {
		Title:          "RDP Standard Security Allows Credential Interception",
		Severity:       SeverityLow,
		Impact:         "RDP Standard Security transmits credentials with weak encryption that can be intercepted and decrypted by a man-in-the-middle attacker.",
		Recommendation: "Enforce Enhanced RDP Security (TLS/NLA) to protect credential transmission. Disable Standard RDP Security on all servers.",
	},
	"telnet-cleartext": {
		Title:          "Cleartext Telnet Service",
		Severity:       SeverityLow,
		Impact:         "Telnet transmits all data including credentials in cleartext, enabling passive network eavesdropping.",
		Recommendation: "Replace Telnet with SSH for remote administration. Disable the Telnet service on all production systems.",
	},
	"x11-unauth-access": {
		Title:          "X11 Unauthenticated Access",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated X11 access allows attackers to capture keystrokes, take screenshots, and inject input events on the target display.",
		Recommendation: "Disable X11 TCP listening or restrict access via xhost and MIT-MAGIC-COOKIE authentication. Use SSH X11 forwarding instead.",
	},
	"teamviewer-exposed": {
		Title:          "TeamViewer Service Exposed",
		Severity:       SeverityLow,
		Impact:         "An exposed TeamViewer service increases the attack surface for unauthorized remote access, especially if weak or reused passwords are in use.",
		Recommendation: "Restrict TeamViewer access to trusted networks. Enable two-factor authentication and review access permissions regularly.",
	},
	"anydesk-exposed": {
		Title:          "AnyDesk Service Exposed",
		Severity:       SeverityLow,
		Impact:         "An exposed AnyDesk service increases the attack surface for unauthorized remote access, especially if default or weak credentials are configured.",
		Recommendation: "Restrict AnyDesk access to trusted networks. Configure strong passwords and enable two-factor authentication.",
	},
	"pptp-insecure": {
		Title:          "PPTP VPN Service",
		Severity:       SeverityLow,
		Impact:         "PPTP uses MS-CHAPv2 authentication, which has known weaknesses allowing offline credential recovery. The protocol's encryption can be broken in practice.",
		Recommendation: "Replace PPTP with a modern VPN protocol such as IKEv2/IPsec, WireGuard, or OpenVPN. Disable PPTP on the server.",
	},
	"openvpn-management-exposed": {
		Title:          "OpenVPN Management Interface Exposed",
		Severity:       SeverityMedium,
		Impact:         "An unauthenticated OpenVPN management interface allows attackers to disconnect clients, modify configurations, and potentially extract certificates or keys.",
		Recommendation: "Restrict the OpenVPN management interface to localhost. If remote management is required, enable password authentication and use SSH tunneling.",
	},

	// ── Windows protocols ────────────────────────────────────────────────
	"winrm-cleartext": {
		Title:          "WinRM Cleartext Communication",
		Severity:       SeverityLow,
		Impact:         "WinRM without TLS transmits authentication tokens and command output in cleartext, enabling credential interception by network attackers.",
		Recommendation: "Configure WinRM to use HTTPS (port 5986) with a valid TLS certificate. Disable the HTTP listener (port 5985) in production.",
	},
	"winrm-no-auth": {
		Title:          "WinRM Basic Authentication Enabled",
		Severity:       SeverityLow,
		Impact:         "Basic authentication sends credentials in base64 encoding (not encryption), making them trivially recoverable by network attackers without TLS.",
		Recommendation: "Disable WinRM Basic authentication. Use Kerberos or CredSSP authentication over HTTPS instead.",
	},
	"smb-signing-not-required": {
		Title:          "SMB Signing Not Required",
		Severity:       SeverityLow,
		Impact:         "Without mandatory SMB signing, an attacker can perform relay attacks to impersonate clients and gain unauthorized access to file shares.",
		Recommendation: "Enable mandatory SMB signing on both the server and client via Group Policy to prevent relay attacks.",
	},
	"smb-null-session": {
		Title:          "SMB Null Session Permitted",
		Severity:       SeverityLow,
		Impact:         "SMB null sessions allow unauthenticated enumeration of shares, users, and groups, providing reconnaissance data for further attacks.",
		Recommendation: "Disable null sessions by configuring RestrictAnonymous and RestrictAnonymousSAM registry values. Restrict anonymous access to named pipes and shares.",
	},
	"smb-guest-access": {
		Title:          "SMB Guest Access Enabled",
		Severity:       SeverityLow,
		Impact:         "Guest access to SMB shares allows unauthenticated users to read shared files, potentially exposing sensitive documents or configuration data.",
		Recommendation: "Disable guest access on all SMB shares. Require authenticated access with appropriate permissions for each share.",
	},
	"smb-v1-enabled": {
		Title:          "SMBv1 Protocol Enabled",
		Severity:       SeverityLow,
		Impact:         "SMBv1 has known critical vulnerabilities (EternalBlue/MS17-010) that enable remote code execution without authentication.",
		Recommendation: "Disable SMBv1 on the server and enforce a minimum SMB protocol version of SMBv2 or higher.",
	},

	// ── Kerberos ─────────────────────────────────────────────────────────
	"kerberos-weak-etypes": {
		Title:          "Kerberos Weak Encryption Types Supported",
		Severity:       SeverityLow,
		Impact:         "Weak encryption types (RC4, DES) in Kerberos enable Kerberoasting attacks with faster offline cracking and potential ticket forgery.",
		Recommendation: "Disable RC4 and DES encryption for Kerberos. Configure AES128 and AES256 as the minimum supported encryption types in Active Directory.",
	},
	"kerberos-preauth-not-required": {
		Title:          "Kerberos Pre-Authentication Not Required",
		Severity:       SeverityMedium,
		Impact:         "Accounts without pre-authentication required are vulnerable to AS-REP roasting, allowing offline brute-force of the account's password.",
		Recommendation: "Enable Kerberos pre-authentication on all user accounts. Audit accounts with the DONT_REQUIRE_PREAUTH flag set.",
	},
	"kerberos-internet-exposed": {
		Title:          "Kerberos Service Internet Exposed",
		Severity:       SeverityLow,
		Impact:         "Kerberos exposed to the internet enables remote ticket attacks and domain enumeration.",
		Recommendation: "Restrict Kerberos to internal networks. Block ports 88/464 at the perimeter.",
	},

	// ── Email protocols ──────────────────────────────────────────────────
	"imap-cleartext": {
		Title:          "Cleartext IMAP Service",
		Severity:       SeverityLow,
		Impact:         "Cleartext IMAP transmits email credentials and message content without encryption, enabling passive interception of sensitive communications.",
		Recommendation: "Enable IMAPS (IMAP over TLS) or STARTTLS. Disable the plaintext IMAP listener on production mail servers.",
	},
	"smtp-cleartext": {
		Title:          "Cleartext SMTP Service",
		Severity:       SeverityLow,
		Impact:         "Cleartext SMTP transmits email content and authentication credentials without encryption, enabling passive interception.",
		Recommendation: "Enable SMTPS or STARTTLS on the SMTP server. Disable plaintext submission ports in production.",
	},
	"smtp-open-relay": {
		Title:          "SMTP Open Relay",
		Severity:       SeverityMedium,
		Impact:         "An open mail relay allows attackers to send spam or phishing emails through the server, leading to IP blacklisting and reputational damage.",
		Recommendation: "Configure the SMTP server to reject relay attempts from unauthenticated or external senders. Restrict relay to authorized users and networks.",
	},
	"smtp-vrfy-enabled": {
		Title:          "SMTP VRFY Command Enabled",
		Severity:       SeverityLow,
		Impact:         "The SMTP VRFY command allows attackers to enumerate valid email addresses on the server, aiding targeted phishing or brute-force attacks.",
		Recommendation: "Disable the VRFY command in the SMTP server configuration to prevent user enumeration.",
	},
	"smtp-no-auth": {
		Title:          "SMTP Accessible Without Authentication",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated SMTP access may allow mail relay or user enumeration.",
		Recommendation: "Require SMTP authentication for all operations.",
	},
	"pop3-cleartext": {
		Title:          "Cleartext POP3 Service",
		Severity:       SeverityLow,
		Impact:         "Cleartext POP3 transmits email credentials and message content without encryption, enabling passive interception.",
		Recommendation: "Enable POP3S (POP3 over TLS) or STARTTLS. Disable the plaintext POP3 listener on production mail servers.",
	},
	"xmpp-cleartext": {
		Title:          "Cleartext XMPP Service",
		Severity:       SeverityLow,
		Impact:         "Cleartext XMPP transmits messaging credentials and conversation content without encryption, enabling passive interception.",
		Recommendation: "Enable TLS on the XMPP server. Configure STARTTLS as mandatory for all client and server-to-server connections.",
	},

	// ── Debug and management ─────────────────────────────────────────────
	"jdwp-exposed": {
		Title:          "JDWP Debug Port Exposed",
		Severity:       SeverityMedium,
		Impact:         "The Java Debug Wire Protocol allows unauthenticated remote code execution by attaching a debugger and invoking arbitrary methods.",
		Recommendation: "Remove JDWP from production JVM arguments. If debugging is required, bind to localhost only and use SSH tunneling for remote access.",
	},
	"dify-setup-not-started": {
		Title:          "Dify Setup Not Started",
		Severity:       SeverityMedium,
		Impact:         "Debug mode may expose detailed error messages, stack traces, and internal application state to unauthenticated users.",
		Recommendation: "Disable debug mode in production by setting the appropriate environment variable. Ensure error details are not exposed to end users.",
	},
	"gradio-unauthenticated-interface": {
		Title:          "Gradio Unauthenticated Interface",
		Severity:       SeverityLow,
		Impact:         "An unauthenticated Gradio interface allows anyone to interact with the underlying ML model, potentially submitting malicious inputs or accessing sensitive outputs.",
		Recommendation: "Enable Gradio authentication using the auth parameter. Restrict network access to the Gradio interface.",
	},

	// ── IPMI ─────────────────────────────────────────────────────────────
	"ipmi-exposed": {
		Title:          "IPMI Interface Exposed",
		Severity:       SeverityMedium,
		Impact:         "An exposed IPMI interface allows attackers to manage hardware remotely, including power cycling, accessing the console, and potentially extracting credentials.",
		Recommendation: "Restrict IPMI access to a dedicated management VLAN. Disable IPMI on public-facing interfaces and enforce strong credentials.",
	},
	"ipmi-cipher-zero": {
		Title:          "IPMI Cipher Zero Enabled",
		Severity:       SeverityMedium,
		Impact:         "IPMI cipher zero bypasses authentication entirely, allowing any network-reachable attacker to gain full administrative control of the BMC.",
		Recommendation: "Disable cipher zero on the BMC. Update BMC firmware and restrict IPMI access to a dedicated management network.",
	},
	"ipmi-anonymous-login": {
		Title:          "IPMI Anonymous Login",
		Severity:       SeverityMedium,
		Impact:         "Anonymous IPMI authentication allows unauthenticated access to hardware management functions, including power control and console access.",
		Recommendation: "Disable anonymous authentication on the BMC. Require strong credentials for all IPMI access.",
	},

	// ── ICS/SCADA protocols ──────────────────────────────────────────────
	"s7comm-no-protection": {
		Title:          "S7comm PLC No Access Protection",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated S7comm access allows attackers to read and write PLC memory, start/stop the CPU, and alter industrial control processes.",
		Recommendation: "Enable S7comm access protection at the highest practical level. Isolate PLCs on dedicated OT networks with firewall rules restricting access.",
	},
	"s7comm-read-only": {
		Title:          "S7comm PLC Read-Only Access",
		Severity:       SeverityMedium,
		Impact:         "A Siemens S7comm authentication bypass allows attackers to fully control the PLC regardless of configured access protection levels.",
		Recommendation: "Apply firmware updates that address the authentication bypass. Isolate affected PLCs behind network segmentation and monitor for unauthorized access.",
	},
	"modbus-no-auth": {
		Title:          "Modbus Accessible Without Authentication",
		Severity:       SeverityMedium,
		Impact:         "Modbus has no built-in authentication, allowing any network-reachable client to read sensor data and write to coils/registers controlling physical processes.",
		Recommendation: "Isolate Modbus devices on a dedicated OT network. Deploy a Modbus-aware firewall or gateway that enforces access controls.",
	},
	"dnp3-no-auth": {
		Title:          "DNP3 Accessible Without Authentication",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated DNP3 access allows attackers to read and control SCADA outstations, potentially disrupting utility or infrastructure operations.",
		Recommendation: "Enable DNP3 Secure Authentication (SA) on outstations. Isolate DNP3 communications on dedicated OT networks.",
	},
	"bacnet-no-auth": {
		Title:          "BACnet Accessible Without Authentication",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated BACnet access allows attackers to read and modify building automation parameters such as HVAC setpoints, alarms, and access controls.",
		Recommendation: "Isolate BACnet devices on a dedicated network segment. Deploy BACnet-aware firewalls and restrict access to authorized management stations.",
	},
	"opcua-no-security": {
		Title:          "OPC UA No Security Configured",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated OPC UA access allows attackers to browse the address space, read process data, and potentially write to control variables.",
		Recommendation: "Configure OPC UA servers to require authentication with Security Mode Sign or SignAndEncrypt. Disable the Anonymous user token policy.",
	},
	"opcua-weak-security": {
		Title:          "OPC UA Weak Security Mode",
		Severity:       SeverityLow,
		Impact:         "OPC UA Security Mode None transmits all data without signing or encryption, enabling eavesdropping and message tampering.",
		Recommendation: "Remove SecurityMode None from the OPC UA server endpoint configuration. Require Sign or SignAndEncrypt for all connections.",
	},

	// ── Version control ──────────────────────────────────────────────────
	"svn-source-code-exposed": {
		Title:          "SVN Source Code Exposed",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated SVN access allows attackers to checkout the full repository history, potentially exposing source code, credentials, and internal documentation.",
		Recommendation: "Enable SVN authentication and restrict anonymous read access. Use svnserve with SASL or Apache mod_authz_svn for access control.",
	},
	"git-source-code-exposed": {
		Title:          "Git Source Code Exposed",
		Severity:       SeverityMedium,
		Impact:         "An exposed Git repository allows attackers to clone the full commit history, potentially revealing source code, credentials, and sensitive configuration data.",
		Recommendation: "Restrict access to the Git daemon or HTTP endpoint. Require authentication for repository access and audit for exposed .git directories.",
	},

	// ── Streaming ────────────────────────────────────────────────────────
	"rtsp-unauthenticated-stream": {
		Title:          "RTSP Unauthenticated Stream",
		Severity:       SeverityLow,
		Impact:         "Unauthenticated RTSP access allows attackers to view live camera feeds, potentially compromising physical security and privacy.",
		Recommendation: "Enable authentication on the RTSP server. Restrict access to authorized clients and isolate cameras on a dedicated network segment.",
	},
	"rtmp-unauthenticated-stream": {
		Title:          "RTMP Unauthenticated Stream",
		Severity:       SeverityLow,
		Impact:         "Unauthenticated RTMP access allows attackers to view or inject content into live media streams.",
		Recommendation: "Enable authentication on the RTMP server. Restrict publishing and playback to authorized clients.",
	},

	// ── Miscellaneous services ───────────────────────────────────────────
	"cups-remote-access": {
		Title:          "CUPS Remote Access Enabled",
		Severity:       SeverityLow,
		Impact:         "An exposed CUPS service may allow remote print job submission or information disclosure about the print infrastructure.",
		Recommendation: "Restrict CUPS web interface and IPP access to localhost or trusted networks. Configure access controls in cupsd.conf.",
	},
	"irc-cleartext": {
		Title:          "Cleartext IRC Service",
		Severity:       SeverityLow,
		Impact:         "Cleartext IRC transmits messages and authentication credentials without encryption, enabling passive interception.",
		Recommendation: "Enable TLS on the IRC server and redirect plaintext connections. Require SASL authentication over TLS.",
	},
	"irc-unauthenticated": {
		Title:          "IRC Server Unauthenticated Access",
		Severity:       SeverityLow,
		Impact:         "An IRC server without authentication allows anonymous participation, which may be exploited for command-and-control communication or spam.",
		Recommendation: "Require SASL or NickServ authentication on the IRC server. Restrict connections to authorized users.",
	},
	"ntp-monlist": {
		Title:          "NTP Monlist Enabled",
		Severity:       SeverityLow,
		Impact:         "The NTP monlist command can be abused for amplification DDoS attacks, as responses are significantly larger than requests.",
		Recommendation: "Disable the monlist command by adding 'disable monitor' to ntp.conf or upgrading to NTP 4.2.7p26+ which disables it by default.",
	},
	"dns-zone-transfer": {
		Title:          "DNS Zone Transfer Permitted",
		Severity:       SeverityLow,
		Impact:         "Unrestricted zone transfers expose the complete DNS zone, revealing all hostnames, IP addresses, and internal network topology.",
		Recommendation: "Restrict zone transfers (AXFR) to authorized secondary DNS servers only using the allow-transfer directive.",
	},

	// ── LLM and AI services ─────────────────────────────────────────────
	"ollama-unauthenticated-api": {
		Title:          "Ollama LLM API Accessible Without Authentication",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated access to the Ollama API allows attackers to run LLM inference, consume GPU resources, and potentially extract model data or training artifacts.",
		Recommendation: "Deploy Ollama behind an authenticating reverse proxy. Restrict API access to trusted networks and authorized clients.",
	},
	"open-webui-unauthenticated-api": {
		Title:          "Open WebUI Unauthenticated API",
		Severity:       SeverityLow,
		Impact:         "An exposed Open WebUI instance may allow unauthenticated interaction with connected LLM backends, potentially consuming resources or accessing sensitive prompts.",
		Recommendation: "Restrict Open WebUI access to trusted networks. Enable authentication and disable public access.",
	},
	"open-webui-onboarding-exposed": {
		Title:          "Open WebUI Onboarding Exposed",
		Severity:       SeverityMedium,
		Impact:         "Open self-registration allows anyone to create accounts and access connected LLM services, potentially consuming resources or accessing sensitive data.",
		Recommendation: "Disable self-registration in Open WebUI settings. Use invite-only or LDAP/OIDC-based enrollment.",
	},
	"localai-unauthenticated-api": {
		Title:          "LocalAI API Accessible Without Authentication",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated LocalAI access allows attackers to run inference, consume GPU resources, and potentially access loaded models.",
		Recommendation: "Deploy LocalAI behind an authenticating reverse proxy. Restrict API access to trusted clients only.",
	},
	"librechat-signup-enabled": {
		Title:          "LibreChat Self-Registration Enabled",
		Severity:       SeverityLow,
		Impact:         "Open self-registration allows anyone to create accounts and interact with configured LLM providers, potentially consuming API credits or accessing sensitive data.",
		Recommendation: "Disable self-registration in LibreChat configuration. Restrict access to invited users or integrate with an identity provider.",
	},
	"librechat-unauthenticated": {
		Title:          "LibreChat Accessible Without Authentication",
		Severity:       SeverityMedium,
		Impact:         "Unauthenticated LibreChat access allows anyone to interact with connected LLM providers, consuming API credits and potentially accessing conversation history.",
		Recommendation: "Enable authentication in LibreChat. Restrict network access and configure user management.",
	},
}

// Enrich fills in Title, Impact, and Recommendation from the finding catalog
// if those fields are not already set. It also corrects severity to match the
// catalog-authoritative value.
func (f *SecurityFinding) Enrich() {
	meta, ok := findingCatalog[f.ID]
	if !ok {
		return
	}
	if f.Title == "" {
		f.Title = meta.Title
	}
	if f.Impact == "" {
		f.Impact = meta.Impact
	}
	if f.Recommendation == "" {
		f.Recommendation = meta.Recommendation
	}
	if f.CVSS == "" && meta.CVSS != "" {
		f.CVSS = meta.CVSS
	}
	// Apply catalog severity - the catalog is the authoritative source.
	f.Severity = meta.Severity
}

# PledgeStrike

<p align="center">
____  _     _____ ____   ____ _____   ____ _____ ____  ___ _  _______ 
|  _ \| |   | ____|  _ \ / ___| ____| / ___|_   _|  _ \|_ _| |/ / ____|
| |_) | |   |  _| | | | | |  _|  _|   \___ \ | | | |_) || || ' /|  _|  
|  __/| |___| |___| |_| | |_| | |___   ___) || | |  _ < | || . \| |___ 
|_|   |_____|_____|____/ \____|_____| |____/ |_| |_| \_\___|_|\_\_____|
</p>

**An all-in-one offensive security toolkit built in Rust.**

120+ independent attack modules covering web exploitation, infrastructure testing, credential attacks, AI/LLM abuse, cloud/container, supply chain security, OT/ICS, IoT, network protocols, and payload generation — all in a single binary.

---

## Why PledgeStrike?

Most penetration testing tools cover one specific area — one for SQLi, one for SSRF, one for brute force, etc. PledgeStrike consolidates the entire offensive security workflow into a single fast, statically-linked binary. No Python dependencies, no Node runtime, no Docker required. Just download and run.

### Key Features

- **120+ attack modules** with 478+ subcommands
- **Single binary** — statically compiled, no runtime dependencies
- **Cross-platform** — Linux, macOS, Windows (x86_64 + ARM)
- **Multi-threaded** — built with Tokio async runtime and Rayon parallelism
- **Modular** — each module is independent and composable
- **Fast** — Rust performance with zero-cost abstractions

---

## Installation

### Cargo (Rust)
```bash
cargo install pledgestrike
```

### npm
```bash
npm install -g pledgestrike
```

### PyPI
```bash
pip install pledgestrike
```

### RubyGems
```bash
gem install pledgestrike
```

### NuGet
```bash
dotnet tool install --global pledgestrike
```

### Pre-built Binaries
Download from [GitHub Releases](https://github.com/pledgeandgrow/pledgestrike/releases) for your platform.

---

## Quick Start

```bash
# Decode a JWT token
pledgestrike jwt decode --token <JWT>

# Scan for SQL injection
pledgestrike sqli error --url https://target.com/page --param id

# Test for SSRF with callback detection
pledgestrike ssrf probe --url "http://target.com/fetch?url={SSRF}" --port 8888

# Brute force HTTP Basic Auth
pledgestrike brute http --url https://target.com --users-file users.txt --pass-file pass.txt

# Scan TLS configuration
pledgestrike tls scan --host example.com --verbose

# Generate reverse shell one-liners
pledgestrike shell generate --shell-type bash --ip 10.0.0.1 --port 4444

# Search exploit database
pledgestrike exploit search --query "log4j"
```

---

## Use Cases

### Web Application Penetration Testing
Test for the OWASP Top 10 and beyond: SQL injection (error/blind/time/UNION), XSS (reflected/stored/DOM/blind), command injection, XXE, LFI/RFI, SSTI, CORS misconfiguration, CRLF injection, open redirect, HTTP request smuggling, deserialization, prototype pollution, padding oracle, and more.

### API Security Testing
REST API endpoint discovery, GraphQL introspection and batch attacks, gRPC reflection, WebSocket fuzzing, OpenAPI/Swagger abuse, IDOR/BOLA, broken function level authorization, mass assignment, and rate limit testing.

### Infrastructure & Cloud Security
SSRF chaining to cloud metadata (AWS/GCP/Azure), S3 bucket enumeration, IAM analysis, Kubernetes RBAC audit and pod escape, Docker API exploitation, DNS rebinding, subdomain takeover, and DNS enumeration.

### Credential Attacks
Password spraying with lockout avoidance, HTTP/SSH/FTP brute force, Kerberoasting, AS-REP roasting, NTLM relay, MFA fatigue bombing, OAuth abuse, SAML XSW, and WebAuthn bypass.

### CI/CD & Supply Chain
Pipeline injection, artifact poisoning, runner takeover, webhook exploitation, typosquatting detection, dependency confusion, Git directory exposure, and secret hunting in JS bundles, repos, API responses, and Docker layers.

### Network Protocol Auditing
Test SMTP, FTP, SMB, RDP, SSH, SNMP, Redis, Elasticsearch, RabbitMQ, IPMI, Memcached, MongoDB, VNC, Telnet, SIP, RTSP, NFS, X11, STOMP, TFTP, ZooKeeper, etcd, UPnP, and more for misconfigurations and vulnerabilities.

### IoT/OT/ICS Security
Modbus/SCADA testing, MQTT broker abuse, CoAP discovery, BLE reconnaissance, NTP amplification, and HMI exposure testing.

### AI/LLM Security
Prompt injection, jailbreak testing, data exfiltration via LLM, agent tool/RAG/memory/plugin abuse — covering the emerging attack surface of AI-integrated applications.

### Microsoft/Enterprise
WinRM brute force and lateral movement, Exchange ProxyLogon/ProxyShell/ProxyNotShell, OWA attacks, SharePoint exploitation, and Active Directory via Kerberos/LDAP.

---

## Documentation

- **[COMMANDS.md](COMMANDS.md)** — Complete command reference with all 120 modules and 478+ subcommands
- **[MODULE.md](MODULE.md)** — Module status, descriptions, and implementation details

---

## Build from Source

```bash
git clone https://github.com/pledgeandgrow/pledgestrike.git
cd pledgestrike
cargo build --release
```

The binary will be at `target/release/pledgestrike`.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Rust (2024 edition) |
| CLI Framework | Clap |
| Async Runtime | Tokio |
| Parallelism | Rayon |
| HTTP Client | Reqwest (rustls) |
| DNS | Hickory Resolver |
| Serialization | Serde / serde_json |
| Crypto | HMAC, SHA-2, base64 |

---

## License

MIT — See [LICENSE](LICENSE) for details.

## Disclaimer

PledgeStrike is for authorized security testing only. You are responsible for complying with applicable laws and obtaining proper authorization before testing any target. The authors are not liable for misuse.

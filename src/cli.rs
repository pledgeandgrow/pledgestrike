use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "pledgestrike",
    version = "0.1.0",
    about = "PledgeStrike — All-in-one offensive security toolkit",
    long_about = "PledgeStrike is a modular offensive security toolkit built in Rust.\n\
                  Each module is an independent attack tool with its own subcommands."
)]
pub struct Cli {
    /// Enable verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Subcommand
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// JWT attack module — decode, crack, forge, vulnerability check
    Jwt {
        #[command(subcommand)]
        action: JwtAction,
    },

    /// SSRF probe — test for server-side request forgery with callback detection
    Ssrf {
        #[command(subcommand)]
        action: SsrfAction,
    },

    /// Reverse shell manager — listen for and manage shell sessions
    Shell {
        #[command(subcommand)]
        action: ShellAction,
    },

    /// API endpoint enumerator — REST/GraphQL discovery, parameter fuzzing, auth bypass
    Api {
        #[command(subcommand)]
        action: ApiAction,
    },

    /// Rate limit tester — burst endpoints to test throttling controls
    Ratelimit {
        #[command(subcommand)]
        action: RatelimitAction,
    },

    /// SSL/TLS auditor — scan hosts for weak ciphers, expired certs, protocol downgrades
    Tls {
        #[command(subcommand)]
        action: TlsAction,
    },

    /// Log parser & IOC extractor — extract indicators of compromise from log files
    Ioc {
        #[command(subcommand)]
        action: IocAction,
    },

    /// SQLi injector — error-based, blind, time-based, data dump
    Sqli {
        #[command(subcommand)]
        action: SqliAction,
    },

    /// XSS hunter — reflected, stored, DOM, blind XSS
    Xss {
        #[command(subcommand)]
        action: XssAction,
    },

    /// Command injection — OS, filter bypass, time-based, OOB
    Cmdi {
        #[command(subcommand)]
        action: CmdiAction,
    },

    /// XXE exploiter — file read, SSRF, blind, OOB
    Xxe {
        #[command(subcommand)]
        action: XxeAction,
    },

    /// LFI/RFI tester — file read, include, PHP wrappers, log poisoning
    Lfi {
        #[command(subcommand)]
        action: LfiAction,
    },

    /// SSRF chain — cloud metadata, gopher, blind, internal scan
    SsrfChain {
        #[command(subcommand)]
        action: SsrfChainAction,
    },

    /// CORS tester — origin reflection, credentials, wildcard, null origin
    Cors {
        #[command(subcommand)]
        action: CorsAction,
    },

    /// CRLF injector — header, body, response splitting, log injection
    Crlf {
        #[command(subcommand)]
        action: CrlfAction,
    },

    /// Open redirect — scan, bypass, chain analysis
    Redirect {
        #[command(subcommand)]
        action: RedirectAction,
    },

    /// Web cache poisoner — cache poisoning, cache deception, key analysis
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },

    /// HTTP smuggler — CL.TE, TE.CL, CL.0, detection
    Smuggle {
        #[command(subcommand)]
        action: SmuggleAction,
    },

    /// WebSocket tester — fuzz, inject, CSWSH, auth bypass
    Ws {
        #[command(subcommand)]
        action: WsAction,
    },

    /// GraphQL attacker — introspection, batch DoS, field suggestion, depth limit
    GraphqlAttack {
        #[command(subcommand)]
        action: GraphqlAttackAction,
    },

    /// OAuth abuser — redirect URI, state, token reuse, scope escalation
    Oauth {
        #[command(subcommand)]
        action: OauthAction,
    },

    /// SSTI exploiter — detect, Jinja2, Twig, FreeMarker
    Ssti {
        #[command(subcommand)]
        action: SstiAction,
    },

    /// Prototype pollution — scan, gadget chains, exploitation
    Proto {
        #[command(subcommand)]
        action: ProtoAction,
    },

    /// Race condition — concurrent request races, TOCTOU, double-spend, coupon abuse
    Race {
        #[command(subcommand)]
        action: RaceAction,
    },

    /// Host header injection — password reset poisoning, cache poisoning, access bypass, SSRF
    Host {
        #[command(subcommand)]
        action: HostAction,
    },

    /// Access control tester — IDOR/BOLA, BFLA, privilege escalation, forced browsing
    Acl {
        #[command(subcommand)]
        action: AclAction,
    },

    /// Subdomain takeover — scan, verify, fingerprint dangling DNS
    Takeover {
        #[command(subcommand)]
        action: TakeoverAction,
    },

    /// Cloud exploiter — S3 bucket enum, IAM abuse, Lambda injection, metadata extraction
    Cloud {
        #[command(subcommand)]
        action: CloudAction,
    },

    /// Kubernetes attacker — pod enum, RBAC abuse, secret extraction, pod escape
    K8s {
        #[command(subcommand)]
        action: K8sAction,
    },

    /// DNS rebind — attack simulation, DNS listener, bypass testing
    Rebind {
        #[command(subcommand)]
        action: RebindAction,
    },

    /// Password sprayer — spray, lockout detection, policy check, round-robin
    Spray {
        #[command(subcommand)]
        action: SprayAction,
    },

    /// Brute forcer — HTTP basic, SSH, FTP, HTTP form
    Brute {
        #[command(subcommand)]
        action: BruteAction,
    },

    /// Payload generator — XSS, SQLi, CMDi payloads with encoding
    Payload {
        #[command(subcommand)]
        action: PayloadAction,
    },

    /// Exfiltration tester — DNS, ICMP, HTTP, steganographic channels
    Exfil {
        #[command(subcommand)]
        action: ExfilAction,
    },

    /// Web fuzzer — parameter, header, body, cookie fuzzing with diff analysis
    Wfuzz {
        #[command(subcommand)]
        action: WfuzzAction,
    },

    /// Deserialization — detection and exploitation for Java, .NET, PHP
    Deser {
        #[command(subcommand)]
        action: DeserAction,
    },

    /// Exploit runner — CVE database, search, run, verify, chain
    Exploit {
        #[command(subcommand)]
        action: ExploitAction,
    },

    /// LLM prompt injection — direct/indirect injection, jailbreak, data leak, hijack, exfil, bypass
    Llm {
        #[command(subcommand)]
        action: LlmAction,
    },

    /// AI agent abuse — tool injection, RAG poisoning, memory manipulation, plugin exploitation
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },

    /// AI model extraction — model stealing, hyperparameter inference, decision boundary
    Ai {
        #[command(subcommand)]
        action: AiAction,
    },

    /// Vector DB extraction — Pinecone, Weaviate, Chroma, Milvus unauthenticated access
    Vectordb {
        #[command(subcommand)]
        action: VectordbAction,
    },

    /// AWS privilege escalation — IAM privesc chains, Lambda code injection
    Aws {
        #[command(subcommand)]
        action: AwsAction,
    },

    /// GCP service account abuse — excessive scopes, IAM misconfig, secret access
    Gcp {
        #[command(subcommand)]
        action: GcpAction,
    },

    /// Azure AD application abuse — service principals, app registrations, role assignments
    Azure {
        #[command(subcommand)]
        action: AzureAction,
    },

    /// Terraform state file exploitation — S3/GCS/Azure Blob tfstate extraction
    Tfstate {
        #[command(subcommand)]
        action: TfstateAction,
    },

    /// Istio service mesh abuse — mTLS bypass, istiod debug, Envoy admin, policy violation
    Istio {
        #[command(subcommand)]
        action: IstioAction,
    },

    /// ArgoCD abuse — unauthenticated access, app enumeration, secret extraction, sync trigger
    Argocd {
        #[command(subcommand)]
        action: ArgoCDAction,
    },

    /// DOM clobbering — HTML element ID override, variable hijacking, toString pollution
    Dom {
        #[command(subcommand)]
        action: DomAction,
    },

    /// XS-Leak detection — timing, error events, frame counting, navigation probes
    Xsleak {
        #[command(subcommand)]
        action: XsleakAction,
    },

    /// MFA bypass — fatigue bombing, OTP race, OTP prediction, fallback bypass
    Mfa {
        #[command(subcommand)]
        action: MfaAction,
    },

    /// SAML/SSO abuse — XSW, response manipulation, cert confusion, assertion forgery
    Saml {
        #[command(subcommand)]
        action: SamlAction,
    },

    /// WebAuthn/FIDO2 tester — origin confusion, resident key, relay, downgrade
    Webauthn {
        #[command(subcommand)]
        action: WebauthnAction,
    },

    /// CSP bypass — policy analysis, bypass testing, inline injection, exfiltration
    Csp {
        #[command(subcommand)]
        action: CspAction,
    },

    /// HTTP/2 attacker — Rapid Reset, stream abuse, HPACK header injection, priority
    H2 {
        #[command(subcommand)]
        action: H2Action,
    },

    /// JNDI injector — LDAP, RMI, DNS injection and gadget chain delivery
    Jndi {
        #[command(subcommand)]
        action: JndiAction,
    },

    /// Container escape — Docker API, kubelet, capabilities, host mount
    Container {
        #[command(subcommand)]
        action: ContainerAction,
    },

    /// CI/CD attacker — pipeline injection, artifact poisoning, runner takeover, webhook
    Cicd {
        #[command(subcommand)]
        action: CicdAction,
    },

    /// Supply chain tester — typosquatting, dependency confusion, package poisoning, audit
    Supply {
        #[command(subcommand)]
        action: SupplyAction,
    },

    /// Subdomain enumerator — brute force, CT logs, passive sources, permutation
    Subdom {
        #[command(subcommand)]
        action: SubdomAction,
    },

    /// Secret hunter — JS bundles, repos, API responses, Docker layers
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },

    /// Web3/smart contract — reentrancy, overflow, access control, delegatecall
    Web3 {
        #[command(subcommand)]
        action: Web3Action,
    },

    /// WebRTC exploiter — IP leak, STUN/TURN abuse, relay, fingerprinting
    Webrtc {
        #[command(subcommand)]
        action: WebrtcAction,
    },

    /// Git exposure & repo attack — .git dump, hook injection, GitHub Actions exploitation
    Git {
        #[command(subcommand)]
        action: GitAction,
    },

    /// NoSQL injection — MongoDB, Redis, Cassandra, blind NoSQLi
    Nosqli {
        #[command(subcommand)]
        action: NosqliAction,
    },

    /// gRPC attack — reflection, method enum, metadata injection, stream abuse
    Grpc {
        #[command(subcommand)]
        action: GrpcAction,
    },

    /// Kerberos attack — Kerberoasting, AS-REP roasting, diamond tickets, S4U abuse
    Kerb {
        #[command(subcommand)]
        action: KerbAction,
    },

    /// LDAP injection — filter injection, blind, enumeration, AD abuse
    Ldapi {
        #[command(subcommand)]
        action: LdapiAction,
    },

    /// postMessage abuse — origin bypass, injection, fuzzing, cross-frame chaining
    Postmsg {
        #[command(subcommand)]
        action: PostmsgAction,
    },

    /// Service Worker poisoning — registration, hijack, persistence, fetch interception
    Sw {
        #[command(subcommand)]
        action: SwAction,
    },

    /// WebAssembly exploitation — analyze, memory, import abuse, reverse engineering
    Wasm {
        #[command(subcommand)]
        action: WasmAction,
    },

    /// MQTT/IoT broker attack — auth bypass, topic wildcard, retain, LWT injection
    Mqtt {
        #[command(subcommand)]
        action: MqttAction,
    },

    /// OT/ICS/SCADA attack — Modbus, device enum, write test, HMI exposure
    Ot {
        #[command(subcommand)]
        action: OtAction,
    },

    /// Padding oracle attack — detect, decrypt, encrypt, bit-flipping
    Padoracle {
        #[command(subcommand)]
        action: PadoracleAction,
    },

    /// SSE abuse — injection, connection exhaustion, exfiltration, replay
    Sse {
        #[command(subcommand)]
        action: SseAction,
    },

    /// Bluetooth/BLE recon — scan, GATT enum, write test, MITM relay
    Ble {
        #[command(subcommand)]
        action: BleAction,
    },

    /// NTP abuse — monlist, amplification, time manipulation, private mode
    Ntp {
        #[command(subcommand)]
        action: NtpAction,
    },

    /// WebDAV exploitation — methods, PROPFIND, upload, COPY/MOVE abuse
    Webdav {
        #[command(subcommand)]
        action: WebdavAction,
    },

    /// DNS zone transfer & enumeration — AXFR, records, NSEC walking, cache snooping
    Dnsenum {
        #[command(subcommand)]
        action: DnsenumAction,
    },

    /// CSRF tester — token bypass, SameSite bypass, JSON CSRF, method-based CSRF
    Csrf {
        #[command(subcommand)]
        action: CsrfAction,
    },

    /// Clickjacking tester — X-Frame-Options bypass, overlay, pointer hijacking, cursor spoofing
    Click {
        #[command(subcommand)]
        action: ClickAction,
    },

    /// HTTP Parameter Pollution — detection, WAF bypass, auth bypass, logic abuse
    Hpp {
        #[command(subcommand)]
        action: HppAction,
    },

    /// SMTP/mail attack — open relay, header injection, SPF/DKIM/DMARC bypass, command injection
    Smtp {
        #[command(subcommand)]
        action: SmtpAction,
    },

    /// FTP server attack — anonymous access, bounce scan, directory traversal, backdoor check
    Ftp {
        #[command(subcommand)]
        action: FtpAction,
    },

    /// SMB/NetBIOS attack — share enumeration, null session, EternalBlue check, relay
    Smb {
        #[command(subcommand)]
        action: SmbAction,
    },

    /// RDP attack — enumeration, BlueKeep check, credential stuffing, NLA bypass
    Rdp {
        #[command(subcommand)]
        action: RdpAction,
    },

    /// SSH audit — protocol audit, weak cipher detection, user enumeration, agent forwarding
    Ssh {
        #[command(subcommand)]
        action: SshAction,
    },

    /// SNMP attack — community string brute, info dump, write test, amplification
    Snmp {
        #[command(subcommand)]
        action: SnmpAction,
    },

    /// Redis direct exploit — unauthorized access, RCE, Lua scripting, data exfiltration
    Redisx {
        #[command(subcommand)]
        action: RedisxAction,
    },

    /// Elasticsearch attack — exposure detection, data exfiltration, script injection, reindex abuse
    Elastic {
        #[command(subcommand)]
        action: ElasticAction,
    },

    /// AMQP/RabbitMQ attack — unauthorized access, message injection, queue flooding, management API abuse
    Amqp {
        #[command(subcommand)]
        action: AmqpAction,
    },

    /// IPMI attack — Cipher 0 bypass, default credentials, BMC info dump, BMC exploitation
    Ipmi {
        #[command(subcommand)]
        action: IpmiAction,
    },

    /// CoAP/IoT protocol attack — resource discovery, amplification, unauthorized access, cache poisoning
    Coap {
        #[command(subcommand)]
        action: CoapAction,
    },

    /// Memcached attack — unauthorized access, stats dump, data dump, slab exploitation
    Memcache {
        #[command(subcommand)]
        action: MemcacheAction,
    },

    /// MongoDB attack — unauthorized access, data dump, NoSQL injection, enumeration
    Mongo {
        #[command(subcommand)]
        action: MongoAction,
    },

    /// VNC attack — unauthorized access, credential brute, auth bypass, enumeration
    Vnc {
        #[command(subcommand)]
        action: VncAction,
    },

    /// Telnet attack — credential brute, enumeration, command injection, banner grab
    Telnet {
        #[command(subcommand)]
        action: TelnetAction,
    },

    /// SIP/VoIP attack — enumeration, credential brute, registration attack, INVITE attack
    Sip {
        #[command(subcommand)]
        action: SipAction,
    },

    /// RTSP camera attack — enumeration, credential brute, stream access, default cred test
    Rtsp {
        #[command(subcommand)]
        action: RtspAction,
    },

    /// NFS exploitation — enumeration, mount test, export list, unauthorized access
    Nfs {
        #[command(subcommand)]
        action: NfsAction,
    },

    /// X11 attack — enumeration, keylogger, screenshot capture, auth bypass
    X11 {
        #[command(subcommand)]
        action: X11Action,
    },

    /// STOMP messaging attack — connection, message injection, queue flooding, enumeration
    Stomp {
        #[command(subcommand)]
        action: StompAction,
    },

    /// TFTP attack — file read, file write, path brute force, enumeration
    Tftp {
        #[command(subcommand)]
        action: TftpAction,
    },

    /// WHOIS recon — lookup, reverse lookup, data enumeration, abuse contact extraction
    Whois {
        #[command(subcommand)]
        action: WhoisAction,
    },

    /// Finger protocol recon — user enumeration, brute force, redirect attack, finger bomb
    Finger {
        #[command(subcommand)]
        action: FingerAction,
    },

    /// ZooKeeper attack — environment dump, data dump, credential brute, server info
    Zookeeper {
        #[command(subcommand)]
        action: ZookeeperAction,
    },

    /// etcd attack — unauthorized access, data dump, key enumeration, auth bypass
    Etcd {
        #[command(subcommand)]
        action: EtcdAction,
    },

    /// UPnP/SSDP attack — discovery, port exposure, SOAP injection, amplification flood
    Upnp {
        #[command(subcommand)]
        action: UpnpAction,
    },

    /// IDOR tester — vulnerability test, enumeration, pattern prediction, chain attack
    Idor {
        #[command(subcommand)]
        action: IdorAction,
    },

    /// Mass assignment attack — vulnerability check, injection, privilege escalation, field enumeration
    Mass {
        #[command(subcommand)]
        action: MassAction,
    },

    /// Cookie attack — session fixation, injection, tampering, buffer overflow
    Cookie {
        #[command(subcommand)]
        action: CookieAction,
    },

    /// Session attack — fixation, token prediction, hijacking, session puzzle
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },

    /// RCE scanner — detection, injection, chain attack, out-of-band detection
    Rce {
        #[command(subcommand)]
        action: RceAction,
    },

    /// Spring Boot Actuator exploitation — env dump, heap dump, Jolokia, shutdown
    Actuator {
        #[command(subcommand)]
        action: ActuatorAction,
    },

    /// Debug/info endpoint scanner — endpoint scan, trace method, stack trace, source exposure
    Debug {
        #[command(subcommand)]
        action: DebugAction,
    },

    /// OpenAPI/Swagger abuse — spec discovery, endpoint fuzzer, auth bypass, parameter injection
    Openapi {
        #[command(subcommand)]
        action: OpenapiAction,
    },

    /// Unicode/encoding attack — homoglyph, overlong UTF-8, bidi (Trojan Source), normalization
    Unicode {
        #[command(subcommand)]
        action: UnicodeAction,
    },

    /// WSDL/SOAP exploitation — parser, injection, XXE, service fuzzer
    Wsdl {
        #[command(subcommand)]
        action: WsdlAction,
    },

    /// NTLM attack — relay, pass-the-hash, brute force, info enumeration
    Ntlm {
        #[command(subcommand)]
        action: NtlmAction,
    },

    /// WinRM attack — brute force, remote execution, enumeration, lateral movement
    Winrm {
        #[command(subcommand)]
        action: WinrmAction,
    },

    /// Exchange exploitation — ProxyLogon, ProxyShell, ProxyNotShell, enumeration
    Exchange {
        #[command(subcommand)]
        action: ExchangeAction,
    },

    /// OWA attack — brute force, user enumeration, password spray, inbox rule injection
    Owa {
        #[command(subcommand)]
        action: OwaAction,
    },

    /// SharePoint exploitation — enumeration, brute force, unauthorized access, injection
    Sharepoint {
        #[command(subcommand)]
        action: SharepointAction,
    },

    /// WAF detector — fingerprint WAF via headers and payload analysis
    Waf {
        #[command(subcommand)]
        action: WafAction,
    },
}

#[derive(Subcommand)]
pub enum JwtAction {
    /// Decode a JWT token and display its contents
    Decode {
        /// The JWT token to decode
        #[arg(short, long)]
        token: String,
    },

    /// Check a JWT token for common vulnerabilities
    Check {
        /// The JWT token to check
        #[arg(short, long)]
        token: String,
    },

    /// Brute-force the signing secret of a JWT token
    Crack {
        /// The JWT token to crack
        #[arg(short, long)]
        token: String,

        /// Wordlist file to use for brute-forcing
        #[arg(short, long)]
        wordlist: String,

        /// Number of threads (default: CPU count)
        #[arg(short = 'j', long)]
        threads: Option<usize>,
    },

    /// Forge a new JWT token with a custom payload
    Forge {
        /// The signing secret/key
        #[arg(short, long)]
        secret: String,

        /// JSON payload to embed in the token
        #[arg(short, long)]
        payload: Option<String>,

        /// Read payload JSON from file
        #[arg(long)]
        payload_file: Option<String>,

        /// Algorithm to use (HS256, HS384, HS512, none)
        #[arg(short, long, default_value = "HS256")]
        alg: String,
    },
}

#[derive(Subcommand)]
pub enum SsrfAction {
    /// Start callback listener and probe a target URL for SSRF
    Probe {
        /// Target URL with {SSRF} placeholder where payload is injected
        /// Example: "http://target.com/fetch?url={SSRF}"
        #[arg(short, long)]
        target: String,

        /// Port for the callback listener
        #[arg(short, long, default_value = "8888")]
        port: u16,

        /// External IP for callback URLs (auto-detected if not provided)
        #[arg(short = 'i', long)]
        external_ip: Option<String>,

        /// Cloud provider metadata payloads to test (aws, gcp, azure, all)
        #[arg(short, long, default_value = "all")]
        cloud: String,

        /// Include protocol smuggling payloads (gopher, file, dict)
        #[arg(long)]
        smuggle: bool,

        /// Custom payload to inject (in addition to built-in payloads)
        #[arg(long)]
        custom: Option<String>,

        /// Request timeout in seconds
        #[arg(short = 't', long, default_value = "10")]
        timeout: u64,
    },

    /// Start only the callback listener (for manual SSRF testing)
    Listen {
        /// Port for the callback listener
        #[arg(short, long, default_value = "8888")]
        port: u16,
    },

    /// Generate SSRF payloads without sending them (for manual use)
    Payloads {
        /// Cloud provider (aws, gcp, azure, all)
        #[arg(short, long, default_value = "all")]
        cloud: String,

        /// External IP for callback URLs
        #[arg(short = 'i', long)]
        external_ip: String,

        /// Include protocol smuggling payloads
        #[arg(long)]
        smuggle: bool,
    },
}

#[derive(Subcommand)]
pub enum ShellAction {
    /// Start listening for incoming reverse shell connections
    Listen {
        /// Port to listen on
        #[arg(short, long, default_value = "4444")]
        port: u16,

        /// Bind address
        #[arg(short = 'b', long, default_value = "0.0.0.0")]
        bind: String,

        /// Enable encryption (simple XOR cipher)
        #[arg(short, long)]
        encrypt: bool,

        /// Encryption key (if encryption enabled, default: random)
        #[arg(long)]
        key: Option<String>,

        /// Log all session output to file
        #[arg(long)]
        log_file: Option<String>,
    },

    /// Generate reverse shell one-liners for various languages
    Generate {
        /// Language/shell type (bash, python, powershell, netcat, node, php, perl, ruby)
        #[arg(short, long, default_value = "bash")]
        shell_type: String,

        /// Attacker IP
        #[arg(short = 'i', long)]
        ip: String,

        /// Attacker port
        #[arg(short = 'p', long, default_value = "4444")]
        port: u16,

        /// Encode payload in base64
        #[arg(long)]
        base64: bool,
    },
}

#[derive(Subcommand)]
pub enum RatelimitAction {
    /// Send burst requests to a single endpoint to test rate limiting
    Burst {
        /// Target URL to test
        #[arg(short, long)]
        url: String,

        /// Number of requests to send
        #[arg(short, long, default_value = "100")]
        count: usize,

        /// Requests per second (0 = as fast as possible)
        #[arg(short = 'r', long, default_value = "0")]
        rate: u64,

        /// Number of concurrent workers
        #[arg(short = 'w', long, default_value = "10")]
        workers: usize,

        /// Bearer token for authenticated requests
        #[arg(short = 't', long)]
        token: Option<String>,

        /// HTTP method to use
        #[arg(short = 'm', long, default_value = "GET")]
        method: String,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },

    /// Send requests with varying identifiers to simulate distributed rate limit testing
    Distributed {
        /// Target URL to test
        #[arg(short, long)]
        url: String,

        /// Number of requests per source
        #[arg(short, long, default_value = "50")]
        count: usize,

        /// Number of simulated sources (different User-Agents/X-Forwarded-For)
        #[arg(short = 's', long, default_value = "5")]
        sources: usize,

        /// Requests per second per source
        #[arg(short = 'r', long, default_value = "0")]
        rate: u64,

        /// Bearer token for authenticated requests
        #[arg(short = 't', long)]
        token: Option<String>,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },

    /// Test multiple endpoints and report which ones lack rate limiting
    Report {
        /// Base URL of the target API
        #[arg(short, long)]
        url: String,

        /// Endpoints to test (comma-separated paths)
        #[arg(short, long)]
        endpoints: String,

        /// Number of requests per endpoint
        #[arg(short = 'n', long, default_value = "50")]
        count: usize,

        /// Bearer token for authenticated requests
        #[arg(short = 't', long)]
        token: Option<String>,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum TlsAction {
    /// Scan a single host for TLS vulnerabilities
    Scan {
        /// Target host (e.g. example.com or example.com:443)
        #[arg(short = 'H', long)]
        host: String,

        /// Show detailed cipher suite information
        #[arg(long)]
        verbose: bool,
    },

    /// Batch scan multiple hosts from a file
    Batch {
        /// File containing hosts (one per line)
        #[arg(short, long)]
        file: String,

        /// Output file for results (JSON)
        #[arg(short, long)]
        output: Option<String>,

        /// Number of concurrent scans
        #[arg(short = 'w', long, default_value = "10")]
        workers: usize,
    },

    /// Generate a compliance-ready report from scan results
    Report {
        /// JSON scan results file (from batch output)
        #[arg(short, long)]
        input: String,

        /// Output format (markdown, html)
        #[arg(short, long, default_value = "markdown")]
        format: String,

        /// Output file path
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum IocAction {
    /// Extract IOCs (IPs, hashes, URLs, emails, domains) from a log file
    Extract {
        /// Log file to parse (use - for stdin)
        #[arg(short, long)]
        file: String,

        /// IOC types to extract (comma-separated: ip,url,email,hash,domain,all)
        #[arg(short = 't', long, default_value = "all")]
        types: String,

        /// Output format (text, json, csv)
        #[arg(short = 'F', long, default_value = "text")]
        format: String,

        /// Output file path (default: stdout)
        #[arg(short = 'o', long)]
        output: Option<String>,
    },

    /// Search for specific IOC patterns in log files
    Hunt {
        /// Log file to search
        #[arg(short, long)]
        file: String,

        /// Search pattern (IP, hash, URL, email, or custom regex)
        #[arg(short, long)]
        pattern: String,

        /// Show surrounding context lines
        #[arg(short = 'c', long, default_value = "0")]
        context: usize,
    },

    /// Extract IOCs and show statistics summary
    Stats {
        /// Log file to analyze
        #[arg(short, long)]
        file: String,

        /// Minimum occurrences to report
        #[arg(short = 'm', long, default_value = "1")]
        min: usize,
    },
}

#[derive(Subcommand)]
pub enum ApiAction {
    /// Enumerate REST API endpoints via wordlist path discovery + method fuzzing
    Enum {
        /// Base URL of the target API (e.g. https://api.target.com)
        #[arg(short, long)]
        url: String,

        /// Wordlist file with endpoint paths (one per line)
        #[arg(short, long)]
        wordlist: String,

        /// HTTP methods to test (comma-separated)
        #[arg(short = 'm', long, default_value = "GET,POST,PUT,DELETE,PATCH")]
        methods: String,

        /// Bearer token for authenticated requests
        #[arg(short = 't', long)]
        token: Option<String>,

        /// API key header (format: "X-API-Key:value")
        #[arg(long)]
        api_key: Option<String>,

        /// Custom headers (format: "Header:value", comma-separated)
        #[arg(long)]
        headers: Option<String>,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,

        /// Filter: only show responses with these status codes (comma-separated)
        #[arg(long)]
        status_filter: Option<String>,

        /// Rate limit: requests per second
        #[arg(short = 'r', long, default_value = "0")]
        rate: u64,
    },

    /// Fuzz query parameters on an endpoint to find hidden/undocumented params
    Fuzz {
        /// Target URL with parameters to fuzz
        #[arg(short, long)]
        url: String,

        /// Wordlist file with parameter names
        #[arg(short, long)]
        wordlist: String,

        /// Bearer token for authenticated requests
        #[arg(short = 't', long)]
        token: Option<String>,

        /// Fuzz value to inject (default: test)
        #[arg(long, default_value = "psfuzz")]
        value: String,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },

    /// GraphQL endpoint discovery and introspection
    GraphQL {
        /// Target GraphQL endpoint URL
        #[arg(short, long)]
        url: String,

        /// Bearer token for authenticated requests
        #[arg(short = 't', long)]
        token: Option<String>,

        /// Run field suggestion attack (brute-force field names via error messages)
        #[arg(long)]
        suggest: bool,

        /// Wordlist for field suggestion attack
        #[arg(long)]
        wordlist: Option<String>,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },

    /// Test for authentication bypass vulnerabilities
    Auth {
        /// Target URL to test
        #[arg(short, long)]
        url: String,

        /// Valid bearer token (for comparison)
        #[arg(short = 't', long)]
        token: Option<String>,

        /// Test IDOR by incrementing/decrementing numeric IDs in the URL
        #[arg(long)]
        idor: bool,

        /// Test without any auth headers
        #[arg(long)]
        no_auth: bool,

        /// Test with manipulated JWT (alg=none)
        #[arg(long)]
        jwt_none: bool,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SqliAction {
    /// Error-based SQLi detection
    Error {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Boolean-based blind SQLi detection
    Blind {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Time-based blind SQLi detection
    Time {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Attempt data extraction via UNION-based SQLi
    Dump {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "users")]
        table: String,
    },
}

#[derive(Subcommand)]
pub enum XssAction {
    /// Reflected XSS detection
    Reflect {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Stored XSS detection
    Store {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// DOM-based XSS detection
    Dom {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Blind XSS with callback
    Blind {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 'c', long)]
        callback_url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum CmdiAction {
    /// OS command injection
    Os {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Filter bypass attempts
    Filter {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Time-based command injection
    Time {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Out-of-band command injection
    Oob {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 'c', long)]
        callback_host: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum XxeAction {
    /// XXE file read
    File {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "/etc/passwd")]
        file: String,
    },
    /// XXE SSRF
    Ssrf {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 'u', long)]
        target_url: String,
    },
    /// Blind XXE
    Blind {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 'c', long)]
        callback_host: String,
    },
    /// OOB XXE exfiltration
    Oob {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 'c', long)]
        callback_host: String,
        #[arg(short, long, default_value = "/etc/passwd")]
        file: String,
    },
}

#[derive(Subcommand)]
pub enum LfiAction {
    /// LFI file read with path traversal
    Read {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "/etc/passwd")]
        file: String,
    },
    /// RFI test
    Include {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 'r', long)]
        remote_url: String,
    },
    /// PHP wrapper exploitation
    Wrapper {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Log poisoning for LFI to RCE
    Log {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SsrfChainAction {
    /// Cloud metadata extraction
    Metadata {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Gopher protocol smuggling
    Gopher {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Blind SSRF with callback
    Blind {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 'c', long)]
        callback_host: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Internal port scan via SSRF
    Scan {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 'p', long, default_value = "common")]
        ports: String,
    },
    /// Cloud metadata extraction v2 — IMDSv2 bypass, GCP/Azure, IPv6, Docker socket
    CloudV2 {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "15")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum CorsAction {
    /// Origin reflection test
    Origin {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Credentials test
    Creds {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Wildcard ACAO test
    Wildcard {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Null origin test
    Null {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum CrlfAction {
    /// Header injection
    Header {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Body injection
    Body {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Response splitting
    Split {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Log injection
    Log {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum RedirectAction {
    /// Scan for open redirect params
    Scan {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Bypass filter with encoded payloads
    Bypass {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Chain analysis (SSRF/XSS via redirect)
    Chain {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum CacheAction {
    /// Cache poisoning via unkeyed headers
    Poison {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Cache deception test
    Deceive {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Cache key analysis
    Key {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SmuggleAction {
    /// CL.TE smuggling
    Clte {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// TE.CL smuggling
    Tecl {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// CL.0 smuggling
    Cl0 {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Auto-detect smuggling type
    Detect {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// HTTP desync v2 — h2c upgrade smuggling, HTTP/2 downgrade, header folding
    Desync {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "15")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum WsAction {
    /// WebSocket fuzzing
    Fuzz {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "ps_ws_fuzz")]
        message: String,
    },
    /// WebSocket injection
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long)]
        payload: String,
    },
    /// Cross-site WebSocket hijacking
    Cswssh {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// WebSocket auth bypass
    Auth {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum GraphqlAttackAction {
    /// GraphQL introspection query — dump schema, types, fields
    Introspect {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Batch query DoS — send N queries in a single request
    Batch {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "30")]
        timeout: u64,
        #[arg(short, long, default_value = "50")]
        count: usize,
    },
    /// Field suggestion attack — extract field names via error messages
    Suggest {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 'w', long)]
        wordlist: Option<String>,
    },
    /// Query depth limit bypass — send increasingly deep nested queries
    Depth {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "30")]
        timeout: u64,
        #[arg(short, long, default_value = "20")]
        max_depth: usize,
    },
    /// Mutation fuzzing — IDOR, mass assignment, unauthorized data modification
    Fuzz {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "30")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum OauthAction {
    /// Redirect URI manipulation — test for open redirect in OAuth callback
    Redirect {
        #[arg(short = 'u', long)]
        auth_url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// State parameter validation — test for missing/weak state CSRF protection
    State {
        #[arg(short = 'u', long)]
        auth_url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Token reuse — replay authorization code to check if tokens can be reused
    Token {
        #[arg(short = 'u', long)]
        token_url: String,
        #[arg(short = 'c', long)]
        client_id: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Scope escalation — request elevated scopes (admin, system, wildcard)
    Scope {
        #[arg(short = 'u', long)]
        token_url: String,
        #[arg(short = 'c', long)]
        client_id: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SstiAction {
    /// Detect SSTI — probe with multiple template syntaxes
    Detect {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Jinja2 exploitation — RCE via class walk and os.popen
    Jinja {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "id")]
        cmd: String,
    },
    /// Twig exploitation — RCE via filter registration and exec
    Twig {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "id")]
        cmd: String,
    },
    /// FreeMarker exploitation — RCE via Execute and ObjectConstructor
    Freemarker {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "id")]
        cmd: String,
    },
}

#[derive(Subcommand)]
pub enum ProtoAction {
    /// Scan for prototype pollution — inject __proto__ and constructor.prototype
    Scan {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Gadget chain analysis — test known PP gadget chains (EJS, Pug, Express, etc.)
    Gadget {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Exploit — attempt RCE via prototype pollution gadget chains
    Exploit {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "id")]
        cmd: String,
    },
}

#[derive(Subcommand)]
pub enum RaceAction {
    /// Generic race condition — send concurrent identical requests
    Race {
        #[arg(short, long)]
        url: String,
        #[arg(short, long, default_value = "GET")]
        method: String,
        #[arg(short = 'b', long)]
        body: Option<String>,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "30")]
        timeout: u64,
        #[arg(short, long, default_value = "10")]
        workers: usize,
        #[arg(short = 'n', long, default_value = "100")]
        count: usize,
    },
    /// TOCTOU — time-of-check vs time-of-use race
    Toctou {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "30")]
        timeout: u64,
    },
    /// Double-spend — concurrent balance transfers
    Balance {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        account: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "30")]
        timeout: u64,
        #[arg(short, long, default_value = "10")]
        workers: usize,
        #[arg(short, long, default_value = "100")]
        amount: String,
    },
    /// Coupon abuse — apply same coupon concurrently
    Coupon {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        coupon: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "30")]
        timeout: u64,
        #[arg(short, long, default_value = "10")]
        workers: usize,
    },
}

#[derive(Subcommand)]
pub enum HostAction {
    /// Password reset poisoning — inject attacker host in reset emails
    Password {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long)]
        email: String,
    },
    /// Cache poisoning — poison cache via host header injection
    Cache {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Access control bypass — reach internal/admin vhosts via Host header
    Access {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// SSRF via Host header — route requests to internal services
    Ssrf {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long)]
        target: String,
    },
}

#[derive(Subcommand)]
pub enum AclAction {
    /// IDOR/BOLA — iterate resource IDs to find unauthorized access
    Idor {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "1")]
        start_id: u64,
        #[arg(short = 'n', long, default_value = "20")]
        count: u64,
    },
    /// BFLA — test broken function level authorization across HTTP methods
    Bfla {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Privilege escalation — compare access with no/low/high privilege tokens
    Privilege {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 'l', long)]
        low_token: String,
    },
    /// Forced browsing — discover hidden paths and endpoints
    Path {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 'w', long)]
        wordlist: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum TakeoverAction {
    /// Scan a file of subdomains for takeover vulnerabilities
    Scan {
        #[arg(short = 'f', long)]
        domains_file: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Verify a single subdomain for takeover
    Verify {
        #[arg(short, long)]
        domain: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Fingerprint a subdomain's service
    Fingerprint {
        #[arg(short, long)]
        domain: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum CloudAction {
    /// AWS S3 bucket enumeration and ACL check
    S3 {
        #[arg(short = 'b', long)]
        bucket: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// AWS IAM enumeration — list users, roles, policies
    Iam {
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// AWS Lambda function injection test
    Lambda {
        #[arg(short = 'u', long)]
        function_url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Cloud metadata extraction via SSRF (AWS/GCP/Azure)
    Metadata {
        #[arg(short = 'u', long)]
        target_url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum K8sAction {
    /// Enumerate Kubernetes pods, namespaces, nodes, services
    Pods {
        #[arg(short = 'a', long)]
        api_server: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Analyze RBAC — cluster roles, bindings, permissions
    Rbac {
        #[arg(short = 'a', long)]
        api_server: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Extract Kubernetes secrets, service accounts, configmaps
    Secrets {
        #[arg(short = 'a', long)]
        api_server: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Test for pod escape vectors — hostPID, hostNetwork, privileged, hostPath
    Escape {
        #[arg(short = 'a', long)]
        api_server: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum RebindAction {
    /// Simulate DNS rebinding attack with alternating IP resolutions
    Attack {
        #[arg(short, long)]
        target: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "30")]
        timeout: u64,
        #[arg(short = 'i', long, default_value = "5")]
        interval: u64,
        #[arg(short = 'n', long, default_value = "10")]
        count: u32,
    },
    /// Start a DNS listener that responds with attacker IP
    Listen {
        #[arg(short = 'p', long, default_value = "53")]
        port: u16,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "60")]
        timeout: u64,
    },
    /// Test DNS rebinding bypass with IP encoding variants
    Bypass {
        #[arg(short, long)]
        target: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SprayAction {
    /// Spray a single password against a user list
    Spray {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'U', long)]
        users_file: String,
        #[arg(short, long)]
        password: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 'd', long, default_value = "5")]
        delay: u64,
    },
    /// Test lockout policy by sending failed attempts
    Lockout {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'u', long)]
        user: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 'n', long, default_value = "10")]
        count: u32,
    },
    /// Detect password policy requirements
    Policy {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Round-robin spraying with built-in seasonal password list
    Round {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'U', long)]
        users_file: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 'd', long, default_value = "5")]
        delay: u64,
    },
}

#[derive(Subcommand)]
pub enum BruteAction {
    /// HTTP Basic Auth brute force
    Http {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'U', long)]
        users_file: String,
        #[arg(short = 'P', long)]
        pass_file: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "4")]
        workers: usize,
    },
    /// SSH brute force
    Ssh {
        #[arg(short = 'H', long)]
        host: String,
        #[arg(short = 'p', long, default_value = "22")]
        port: u16,
        #[arg(short = 'U', long)]
        users_file: String,
        #[arg(short = 'P', long)]
        pass_file: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "4")]
        workers: usize,
    },
    /// FTP brute force
    Ftp {
        #[arg(short = 'H', long)]
        host: String,
        #[arg(short = 'p', long, default_value = "21")]
        port: u16,
        #[arg(short = 'U', long)]
        users_file: String,
        #[arg(short = 'P', long)]
        pass_file: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "4")]
        workers: usize,
    },
    /// HTTP form-based brute force with configurable fields
    Form {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'U', long)]
        users_file: String,
        #[arg(short = 'P', long)]
        pass_file: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "4")]
        workers: usize,
        #[arg(short = 'u', long, default_value = "username")]
        user_field: String,
        #[arg(short = 'p', long, default_value = "password")]
        pass_field: String,
        #[arg(short = 'f', long, default_value = "invalid")]
        fail_text: String,
    },
}

#[derive(Subcommand)]
pub enum PayloadAction {
    /// Generate XSS payloads with encoding variants
    Xss {
        #[arg(short, long, default_value = "")]
        context: String,
    },
    /// Generate SQLi payloads with encoding variants
    Sqli {
        #[arg(short, long, default_value = "")]
        context: String,
    },
    /// Generate command injection payloads with encoding variants
    Cmdi {
        #[arg(short, long, default_value = "")]
        context: String,
    },
    /// Encode a payload with various encoding schemes
    Encode {
        #[arg(short, long)]
        input: String,
        #[arg(short, long, default_value = "all")]
        encoding: String,
    },
}

#[derive(Subcommand)]
pub enum ExfilAction {
    /// DNS tunneling exfiltration test
    Dns {
        #[arg(short, long)]
        domain: String,
        #[arg(short, long)]
        data: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// ICMP exfiltration simulation
    Icmp {
        #[arg(short, long)]
        host: String,
        #[arg(short, long)]
        data: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// HTTP exfiltration test via multiple methods
    Http {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        data: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Steganographic exfiltration via HTTP headers
    Stego {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        data: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum WfuzzAction {
    /// Fuzz URL parameters with diff analysis
    Param {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'w', long)]
        wordlist: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Fuzz HTTP headers with diff analysis
    Header {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'w', long)]
        wordlist: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Fuzz POST body parameters with diff analysis
    Body {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'w', long)]
        wordlist: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Fuzz cookies with diff analysis
    Cookie {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'w', long)]
        wordlist: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum DeserAction {
    /// Detect insecure deserialization across multiple formats
    Detect {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Java deserialization exploitation with gadget chains
    Java {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "id")]
        cmd: String,
    },
    /// .NET deserialization exploitation with gadget chains
    Net {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "id")]
        cmd: String,
    },
    /// PHP deserialization exploitation with POP chains
    Php {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "id")]
        cmd: String,
    },
}

#[derive(Subcommand)]
pub enum ExploitAction {
    /// Search the local exploit database by CVE, name, or category
    Search {
        #[arg(short, long)]
        query: String,
    },
    /// Look up a single CVE by ID (queries NVD API with local fallback)
    Lookup {
        #[arg(short, long)]
        cve: String,
    },
    /// List recent CVEs published within a date range (queries NVD API)
    Recent {
        #[arg(short, long)]
        start: String,
        #[arg(short, long)]
        end: String,
        #[arg(short = 's', long)]
        severity: Option<String>,
    },
    /// Run an exploit against a target
    Run {
        #[arg(short, long)]
        cve: String,
        #[arg(short, long)]
        target: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Verify if a target is vulnerable to a specific CVE
    Verify {
        #[arg(short, long)]
        cve: String,
        #[arg(short, long)]
        target: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    /// Chain multiple exploits together
    Chain {
        #[arg(short, long)]
        cves: String,
        #[arg(short, long)]
        target: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum LlmAction {
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Jailbreak {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Leak {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Hijack {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Exfil {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "30")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Bypass {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "30")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum AgentAction {
    Tool {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Rag {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Memory {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Plugin {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum MfaAction {
    Fatigue {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'u', long)]
        user: String,
        #[arg(short = 'n', long, default_value = "100")]
        count: u32,
        #[arg(short = 'd', long, default_value = "1")]
        delay: u64,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Race {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'u', long)]
        user: String,
        #[arg(short = 'o', long)]
        otp: String,
        #[arg(short = 'n', long, default_value = "10")]
        count: u32,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Otp {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'u', long)]
        user: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 'n', long, default_value = "10")]
        count: u32,
    },
    Fallback {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'u', long)]
        user: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SamlAction {
    Xsw {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Response {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Cert {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Assertion {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum WebauthnAction {
    Origin {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Resident {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Relay {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Downgrade {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum CspAction {
    Analyze {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Bypass {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 'c', long)]
        callback: String,
    },
    Inline {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 'c', long)]
        callback: String,
    },
    Exfil {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 'c', long)]
        callback: String,
    },
}

#[derive(Subcommand)]
pub enum H2Action {
    Rapidreset {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'n', long, default_value = "1000")]
        count: u32,
        #[arg(short = 'r', long, default_value = "100")]
        rate: u32,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Stream {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'n', long, default_value = "100")]
        count: u32,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Header {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Priority {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum JndiAction {
    Ldap {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'c', long)]
        callback: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Rmi {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'c', long)]
        callback: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Dns {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'c', long)]
        callback: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Gadget {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'c', long)]
        callback: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short, long, default_value = "id")]
        cmd: String,
    },
}

#[derive(Subcommand)]
pub enum ContainerAction {
    Docker {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Kubelet {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Cap {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Mount {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum CicdAction {
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Poison {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Runner {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Webhook {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SupplyAction {
    Typosquat {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Confusion {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Poison {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Audit {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum SubdomAction {
    Brute {
        #[arg(short, long)]
        domain: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 'w', long)]
        wordlist: Option<String>,
    },
    Ct {
        #[arg(short, long)]
        domain: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Passive {
        #[arg(short, long)]
        domain: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Permutate {
        #[arg(short, long)]
        domain: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SecretAction {
    Js {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Repo {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Response {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Docker {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum Web3Action {
    Reentrancy {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Overflow {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Access {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Delegatecall {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum WebrtcAction {
    Leak {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Stun {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Relay {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Fingerprint {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum GitAction {
    Expose {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Dump {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Hook {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    Actions {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
        #[arg(short = 't', long)]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum NosqliAction {
    Mongo {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Redis {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Cassandra {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Blind {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum GrpcAction {
    Reflect {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Method {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Meta {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Stream {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'n', long, default_value = "100")]
        count: u32,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum KerbAction {
    Roast {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Asrep {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Diamond {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    S4u {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum LdapiAction {
    Filter {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Blind {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Ad {
        #[arg(short, long)]
        url: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum PostmsgAction {
    Origin {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Fuzz {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Chain {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SwAction {
    Register {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Hijack {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Persist {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Fetch {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum WasmAction {
    Analyze {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Memory {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Import {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Reverse {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum MqttAction {
    Connect {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Topic {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Retain {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Will {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum OtAction {
    Modbus {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Write {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Hmi {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum PadoracleAction {
    Detect {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Decrypt {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short, long)]
        ciphertext: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Encrypt {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short, long)]
        plaintext: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Bit {
        #[arg(short, long)]
        url: String,
        #[arg(short, long)]
        param: String,
        #[arg(short, long)]
        ciphertext: String,
        #[arg(short = 't', long)]
        token: Option<String>,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SseAction {
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Exhaust {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'n', long, default_value = "100")]
        count: u32,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Exfil {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Replay {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum BleAction {
    Scan {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Gatt {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Write {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Mitm {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum NtpAction {
    Monlist {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Amplify {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Time {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Peek {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum WebdavAction {
    Methods {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Propfind {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Upload {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Copy {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum DnsenumAction {
    Axfr {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Records {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Nsec {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Snoop {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum CsrfAction {
    Token {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Samesite {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Json {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Method {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum ClickAction {
    Frame {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Overlay {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Pointer {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Cursor {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum HppAction {
    Detect {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Bypass {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Auth {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Logic {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SmtpAction {
    Relay {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Spf {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Command {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum FtpAction {
    Anon {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Bounce {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Traverse {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Backdoor {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SmbAction {
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Null {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Eternal {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Relay {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum RdpAction {
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Bluekeep {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Cred {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Nla {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SshAction {
    Audit {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Cipher {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Agent {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SnmpAction {
    Brute {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Dump {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Write {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Amplify {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum RedisxAction {
    Access {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Rce {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Lua {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Exfil {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum ElasticAction {
    Expose {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Dump {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Script {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Reindex {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum AmqpAction {
    Access {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Flood {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Mgmt {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum IpmiAction {
    Cipher0 {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Default {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Dump {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Bmc {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum CoapAction {
    Discover {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Amplify {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Access {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Cache {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum MemcacheAction {
    Access {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Stats {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Dump {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Slab {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum MongoAction {
    Access {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Dump {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum VncAction {
    Access {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Brute {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Bypass {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum TelnetAction {
    Brute {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Banner {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SipAction {
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Brute {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Register {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Invite {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum RtspAction {
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Brute {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Stream {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Cred {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum NfsAction {
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Mount {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Export {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Access {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum X11Action {
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Keylog {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Screenshot {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Bypass {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum StompAction {
    Connect {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Flood {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum TftpAction {
    Read {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Write {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Brute {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum WhoisAction {
    Lookup {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Reverse {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Abuse {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum FingerAction {
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Brute {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Redirect {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Bomb {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum ZookeeperAction {
    Env {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Dump {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Brute {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Srvr {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum EtcdAction {
    Access {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Dump {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Keys {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Auth {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum UpnpAction {
    Discover {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Expose {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Flood {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum IdorAction {
    Test {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Predict {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Chain {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum MassAction {
    Check {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Escalate {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum CookieAction {
    Fixation {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Tamper {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Overflow {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SessionAction {
    Fixation {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Predict {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Hijack {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Puzzle {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum RceAction {
    Detect {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Chain {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Oob {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum ActuatorAction {
    Env {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Heapdump {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Jolokia {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Shutdown {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum DebugAction {
    Scan {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Trace {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Stack {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Source {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum OpenapiAction {
    Spec {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Fuzz {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Auth {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum UnicodeAction {
    Homoglyph {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Overlong {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Bidi {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Normalize {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum WsdlAction {
    Parse {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Xxe {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Fuzz {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum NtlmAction {
    Relay {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Pass {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Brute {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum WinrmAction {
    Brute {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Exec {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Lateral {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum ExchangeAction {
    Proxylogon {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Proxyshell {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Proxynotshell {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum OwaAction {
    Brute {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Spray {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Rule {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum SharepointAction {
    Enum {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Brute {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Access {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
    Inject {
        #[arg(short, long)]
        url: String,
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum WafAction {
    /// Detect and fingerprint WAF via header analysis and payload probing
    Detect {
        /// Target URL
        #[arg(short, long)]
        url: String,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum AiAction {
    /// Model stealing via repeated API queries — extracts decision boundaries
    Extract {
        /// Target prediction API URL
        #[arg(short, long)]
        url: String,

        /// Number of queries to send
        #[arg(short = 'n', long, default_value = "1000")]
        queries: u32,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "30")]
        timeout: u64,

        /// Auth token
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    /// Infer hyperparameters via timing and output analysis
    Hyper {
        /// Target prediction API URL
        #[arg(short, long)]
        url: String,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "30")]
        timeout: u64,

        /// Auth token
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    /// Test for adversarial evasion — perturb inputs to cause misclassification
    Adversarial {
        /// Target classification API URL
        #[arg(short, long)]
        url: String,

        /// Input type (text, image, tabular)
        #[arg(short, long, default_value = "text")]
        input_type: String,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "30")]
        timeout: u64,

        /// Auth token
        #[arg(short = 't', long)]
        token: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum VectordbAction {
    /// Extract vectors and metadata from unauthenticated vector databases
    Extract {
        /// Vector DB URL (Pinecone, Weaviate, Chroma, Milvus)
        #[arg(short, long)]
        url: String,

        /// Number of records to fetch per query
        #[arg(short = 'n', long, default_value = "100")]
        limit: u32,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "15")]
        timeout: u64,

        /// Auth token
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    /// Enumerate collections, indexes, and schema
    Enum {
        /// Vector DB URL
        #[arg(short, long)]
        url: String,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "15")]
        timeout: u64,

        /// Auth token
        #[arg(short = 't', long)]
        token: Option<String>,
    },
    /// Test for unauthenticated access and open endpoints
    Probe {
        /// Vector DB URL
        #[arg(short, long)]
        url: String,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "15")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum AwsAction {
    /// Test AWS IAM for privilege escalation paths (18+ escalation vectors)
    Privesc {
        /// AWS access token / Bearer token
        #[arg(short = 't', long)]
        token: Option<String>,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "15")]
        timeout: u64,
    },
    /// Test Lambda functions for code injection via event payload manipulation
    LambdaInject {
        /// Lambda function URL
        #[arg(short = 'u', long)]
        url: String,

        /// Auth token
        #[arg(short = 't', long)]
        token: Option<String>,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "15")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum GcpAction {
    /// Test GCP service account for excessive scopes and IAM misconfigurations
    Abuse {
        /// GCP service account access token
        #[arg(short = 't', long)]
        token: Option<String>,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "15")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum AzureAction {
    /// Test Azure AD service principals and app registrations for excessive permissions
    App {
        /// Azure AD tenant ID or domain
        #[arg(short, long)]
        tenant: String,

        /// Azure AD access token
        #[arg(short = 't', long)]
        token: Option<String>,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "15")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum TfstateAction {
    /// Exploit exposed Terraform state files to extract secrets and infrastructure data
    Exploit {
        /// S3 bucket name, GCS bucket name, or Azure storage account name
        #[arg(short = 'b', long)]
        bucket: String,

        /// Auth token (for authenticated buckets)
        #[arg(short = 't', long)]
        token: Option<String>,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "15")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum IstioAction {
    /// Enumerate Istio service mesh — istiod debug, Envoy admin, service registry
    Enum {
        /// Istio control plane URL (e.g. http://target.com:15010)
        #[arg(short, long)]
        url: String,

        /// Auth token
        #[arg(short = 't', long)]
        token: Option<String>,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "15")]
        timeout: u64,
    },
    /// Test for unauthenticated access to Istio control plane
    Probe {
        /// Istio control plane URL
        #[arg(short, long)]
        url: String,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "15")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum ArgoCDAction {
    /// Enumerate ArgoCD — applications, clusters, repos, secrets, projects
    Enum {
        /// ArgoCD server URL
        #[arg(short, long)]
        url: String,

        /// ArgoCD auth token
        #[arg(short = 't', long)]
        token: Option<String>,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "15")]
        timeout: u64,
    },
    /// Test for unauthenticated access to ArgoCD API
    Probe {
        /// ArgoCD server URL
        #[arg(short, long)]
        url: String,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "15")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum DomAction {
    /// DOM clobbering attack — inject HTML elements to override JS variables
    Clobber {
        /// Target URL
        #[arg(short, long)]
        url: String,

        /// Auth token
        #[arg(short = 't', long)]
        token: Option<String>,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "15")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum XsleakAction {
    /// Detect cross-site leak vectors — timing, error events, frame count, navigation
    Detect {
        /// Target URL
        #[arg(short, long)]
        url: String,

        /// Auth token
        #[arg(short = 't', long)]
        token: Option<String>,

        /// Request timeout in seconds
        #[arg(short = 'T', long, default_value = "30")]
        timeout: u64,
    },
}

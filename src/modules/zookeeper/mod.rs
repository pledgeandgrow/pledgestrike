use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn env(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} ZooKeeper Environment Dump", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let endpoints = ["/env", "/environment", "/commands/env"];
    for ep in &endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} {:20} — {} bytes", "[+]".green().bold(), ep, text.len());
                    if text.contains("java.version") || text.contains("user.dir") {
                        println!("    {} Environment variables exposed", "[!]".red().bold());
                    }
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn dump(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} ZooKeeper Data Dump", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let paths = ["/", "/zookeeper", "/zookeeper/config", "/zookeeper/quota", "/app", "/config", "/services", "/brokers"];
    for path in &paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} {:25} — {} bytes", "[+]".green().bold(), path, text.len());
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn brute(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} ZooKeeper Credential Brute Force", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let creds = [
        ("admin", "admin"), ("admin", "password"), ("admin", ""),
        ("super", "super"), ("guest", "guest"), ("test", "test"),
        ("zookeeper", "zookeeper"), ("app", "app"), ("root", "root"),
    ];

    for (user, pass) in &creds {
        match client.get(url).basic_auth(user, Some(pass)).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                if status == 200 {
                    println!("  {} {:15}:{:15} — AUTH SUCCESS", "[+]".green().bold(), user, if pass.is_empty() { "(empty)" } else { pass });
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn srvr(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} ZooKeeper Server Info", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let commands = ["/commands/srvr", "/commands/stat", "/commands/conf", "/commands/cons", "/commands/dirs", "/commands/ruok"];
    for cmd in &commands {
        let target = format!("{}{}", url.trim_end_matches('/'), cmd);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} {:25} — {} bytes", "[+]".green().bold(), cmd, text.len());
                    if cmd == &"/commands/ruok" && text.contains("imok") {
                        println!("    {} Server healthy and responding", "[+]".green().bold());
                    }
                }
            }
            Err(_) => println!("  {} {:25} — error", "[-]".dimmed(), cmd),
        }
    }

    Ok(())
}

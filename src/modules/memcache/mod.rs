use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn access(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Memcached Unauthorized Access", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 && (body.contains("memcached") || body.contains("Memcached")) {
        println!("  {} Memcached interface exposed!", "[!]".red().bold());
    }

    let default_endpoints = ["/stats", "/items", "/slabs", "/settings"];
    for ep in &default_endpoints {
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

pub async fn stats(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Memcached Stats Dump", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let stat_endpoints = ["/stats", "/stats/settings", "/stats/items", "/stats/slabs", "/stats/conns"];
    for ep in &stat_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} {:25} — {} bytes", "[+]".green().bold(), ep, text.len());
                    if text.contains("version") {
                        println!("    {} Server version info leaked", "[!]".red().bold());
                    }
                } else {
                    println!("  {} {:25} — status={}", "[-]".dimmed(), ep, status);
                }
            }
            Err(_) => println!("  {} {:25} — error", "[-]".dimmed(), ep),
        }
    }

    Ok(())
}

pub async fn dump(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Memcached Data Dump", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let dump_endpoints = ["/items", "/slabs", "/dump"];
    for ep in &dump_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} {:15} — {} bytes of data retrieved", "[+]".green().bold(), ep, text.len());
                    if text.contains("key") || text.contains("value") {
                        println!("    {} Cached data exposed — potential sensitive info leak", "[!]".red().bold());
                    }
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn slab(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Memcached Slab Exploitation", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);

    for slab_id in 1..=5 {
        let target = format!("{}/slabs/{}", url.trim_end_matches('/'), slab_id);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} Slab {} — {} bytes", "[+]".green().bold(), slab_id, text.len());
                }
            }
            Err(_) => {}
        }
    }

    let cachedump = format!("{}/stats/cachedump/1/10", url.trim_end_matches('/'));
    if let Ok(r) = client.get(&cachedump).send().await {
        let status = r.status().as_u16();
        let text = r.text().await.unwrap_or_default();
        if status == 200 && !text.is_empty() {
            println!("\n  {} Cachedump retrieved — {} bytes of key data", "[!]".red().bold(), text.len());
        }
    }

    Ok(())
}

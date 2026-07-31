use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn access(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} etcd Unauthorized Access", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 && (body.contains("etcd") || body.contains("etcdserver")) {
        println!("  {} etcd service exposed!", "[!]".red().bold());
    }

    let endpoints = ["/v2/keys", "/v2/keys/", "/v3/kv/range", "/v3/maintenance/status", "/health", "/version"];
    for ep in &endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        if let Ok(r) = client.get(&target).send().await {
            let s = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if s == 200 && !text.is_empty() {
                println!("  {} {:30} — {} bytes", "[+]".green().bold(), ep, text.len());
            }
        }
    }

    Ok(())
}

pub async fn dump(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} etcd Data Dump", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let dump_paths = [
        ("/v2/keys/", "Root keys (v2)"),
        ("/v2/keys/config", "Config keys (v2)"),
        ("/v2/keys/secrets", "Secrets (v2)"),
        ("/v2/keys/services", "Services (v2)"),
        ("/v2/keys/registry", "Registry (v2)"),
        ("/v3/kv/range", "All KV range (v3)"),
    ];

    for (path, name) in &dump_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} {:25} — {} bytes", "[+]".green().bold(), name, text.len());
                    if text.contains("password") || text.contains("secret") || text.contains("token") {
                        println!("    {} Sensitive data detected in etcd", "[!]".red().bold());
                    }
                }
            }
            Err(_) => println!("  {} {:25} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn keys(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} etcd Key Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let key_paths = [
        "/v2/keys/", "/v2/keys/config", "/v2/keys/secrets",
        "/v2/keys/services", "/v2/keys/registry", "/v2/keys/cluster",
        "/v2/keys/network", "/v2/keys/calico", "/v2/keys/credentials",
    ];

    for path in &key_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    let key_count = text.matches("\"key\"").count();
                    println!("  {} {:30} — {} entries", "[+]".green().bold(), path, key_count);
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn auth(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} etcd Auth Bypass", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let auth_endpoints = ["/v2/auth", "/v2/auth/roles", "/v2/auth/users", "/v3/auth/user/list", "/v3/auth/role/list"];
    for ep in &auth_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} {:25} — {} bytes", "[!]".red().bold(), ep, text.len());
                } else if status == 401 {
                    println!("  {} {:25} — auth required", "[-]".dimmed(), ep);
                }
            }
            Err(_) => {}
        }
    }

    let body = serde_json::json!({"name": "root", "password": ""});
    let target = format!("{}/v3/auth/authenticate", url.trim_end_matches('/'));
    if let Ok(r) = client.post(&target).json(&body).send().await {
        let status = r.status().as_u16();
        if status == 200 {
            println!("  {} Empty password auth — SUCCESS", "[!]".red().bold());
        }
    }

    Ok(())
}

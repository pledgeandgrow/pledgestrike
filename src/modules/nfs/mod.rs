use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} NFS Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 && (body.contains("nfs") || body.contains("NFS") || body.contains("export")) {
        println!("  {} NFS service detected", "[+]".green().bold());
    }

    let enum_endpoints = ["/exports", "/nfs", "/rpc", "/mount", "/nfsstat"];
    for ep in &enum_endpoints {
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

pub async fn mount(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} NFS Mount Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mount_paths = ["/", "/home", "/var", "/tmp", "/opt", "/srv", "/mnt", "/data", "/backup", "/share"];
    for path in &mount_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} {:15} — accessible ({} bytes)", "[+]".green().bold(), path, text.len());
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn export(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} NFS Export List", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let export_endpoints = ["/exports", "/nfs/exports", "/rpc/exports"];
    for ep in &export_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} {:20} — {} bytes", "[+]".green().bold(), ep, text.len());
                    if text.contains("*") || text.contains("no_root_squash") {
                        println!("    {} Insecure export found — wildcard or no_root_squash", "[!]".red().bold());
                    }
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn access(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} NFS Unauthorized Access", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let access_paths = ["/etc", "/etc/passwd", "/etc/shadow", "/root", "/home", "/var/log", "/var/lib"];
    for path in &access_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} {:15} — {} bytes", "[+]".green().bold(), path, text.len());
                    if path == &"/etc/passwd" && text.contains("root:") {
                        println!("    {} passwd file readable!", "[!]".red().bold());
                    }
                    if path == &"/etc/shadow" && text.contains("root:") {
                        println!("    {} shadow file readable!", "[!]".red().bold());
                    }
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

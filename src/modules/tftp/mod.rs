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

pub async fn read(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} TFTP File Read", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let files = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/config",
        "/boot.cfg",
        "/firmware",
        "/startup-config",
        "/running-config",
    ];
    for file in &files {
        let target = format!("{}{}", url.trim_end_matches('/'), file);
        if let Ok(r) = client.get(&target).send().await {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if status == 200 && !text.is_empty() {
                println!(
                    "  {} {:25} — {} bytes",
                    "[+]".green().bold(),
                    file,
                    text.len()
                );
                if file == &"/etc/passwd" && text.contains("root:") {
                    println!("    {} passwd file readable!", "[!]".red().bold());
                }
            }
        }
    }

    Ok(())
}

pub async fn write(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} TFTP File Write Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let write_paths = [
        "/test.txt",
        "/tmp/test.txt",
        "/upload/test.txt",
        "/incoming/test.txt",
    ];
    for path in &write_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        let body = "TFTP_WRITE_TEST";
        match client.put(&target).body(body).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                if status == 200 || status == 201 || status == 204 {
                    println!("  {} {:25} — WRITE SUCCESS", "[!]".red().bold(), path);
                } else {
                    println!("  {} {:25} — status={}", "[-]".dimmed(), path, status);
                }
            }
            Err(_) => println!("  {} {:25} — error", "[-]".dimmed(), path),
        }
    }

    Ok(())
}

pub async fn brute(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} TFTP Path Brute Force", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let paths = [
        "/config",
        "/backup",
        "/firmware",
        "/image",
        "/os",
        "/startup",
        "/running",
        "/vlan.dat",
        "/license",
        "/boot",
        "/system",
        "/admin",
        "/private",
        "/secret",
        "/key",
    ];

    for path in &paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        if let Ok(r) = client.get(&target).send().await {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if status == 200 && !text.is_empty() {
                println!(
                    "  {} {:20} — {} bytes",
                    "[+]".green().bold(),
                    path,
                    text.len()
                );
            }
        }
    }

    Ok(())
}

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} TFTP Enumeration", "[*]".cyan().bold());
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

    if status == 200 {
        println!("  {} TFTP service accessible", "[+]".green().bold());
    }

    if !body.is_empty() {
        let preview: String = body.chars().take(200).collect();
        println!("  Body: {}", preview);
    }

    Ok(())
}

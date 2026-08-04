use colored::Colorize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::sleep;

pub async fn burst(
    url: &str,
    count: usize,
    rate: u64,
    workers: usize,
    token: Option<&str>,
    method: &str,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Rate Limit Burst Test", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:     {}", "[*]".cyan().bold(), url.green());
    println!("{} Requests: {}", "[*]".cyan().bold(), count);
    println!("{} Workers:  {}", "[*]".cyan().bold(), workers);
    println!(
        "{} Rate:    {} req/s",
        "[*]".cyan().bold(),
        if rate == 0 {
            "max".to_string()
        } else {
            rate.to_string()
        }
    );
    println!("{} Method:  {}", "[*]".cyan().bold(), method.yellow());
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token)?;

    let sent = Arc::new(AtomicU64::new(0));
    let throttled = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let status_counts: Arc<Mutex<std::collections::HashMap<u16, u64>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));

    let start = Instant::now();
    let mut handles = Vec::new();

    let requests_per_worker = count / workers;
    let remainder = count % workers;

    for w in 0..workers {
        let worker_count = requests_per_worker + if w < remainder { 1 } else { 0 };
        let url = url.to_string();
        let method = method.to_string();
        let client = client.clone();
        let sent = sent.clone();
        let throttled = throttled.clone();
        let errors = errors.clone();
        let status_counts = status_counts.clone();

        handles.push(tokio::spawn(async move {
            for _ in 0..worker_count {
                let req = match method.as_str() {
                    "GET" => client.get(&url),
                    "POST" => client.post(&url),
                    "PUT" => client.put(&url),
                    "DELETE" => client.delete(&url),
                    "PATCH" => client.patch(&url),
                    _ => client.get(&url),
                };

                match req.send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        sent.fetch_add(1, Ordering::Relaxed);

                        if status == 429 || status == 503 {
                            throttled.fetch_add(1, Ordering::Relaxed);
                        }

                        let mut counts = status_counts.lock().await;
                        *counts.entry(status).or_insert(0) += 1;
                    }
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }

                if let Some(delay) = (1000u64).checked_div(rate) {
                    sleep(Duration::from_millis(delay)).await;
                }
            }
        }));
    }

    // Progress monitor
    let monitor_sent = sent.clone();
    let monitor_total = count as u64;
    let monitor_handle = tokio::spawn(async move {
        loop {
            let s = monitor_sent.load(Ordering::Relaxed);
            if s >= monitor_total {
                break;
            }
            print!("\r{} Sent: {}/{}", "[*]".cyan().bold(), s, monitor_total);
            use std::io::Write;
            std::io::stdout().flush().ok();
            sleep(Duration::from_millis(200)).await;
        }
        println!();
    });

    for h in handles {
        let _ = h.await;
    }
    monitor_handle.abort();

    let elapsed = start.elapsed();
    let total_sent = sent.load(Ordering::Relaxed);
    let total_throttled = throttled.load(Ordering::Relaxed);
    let total_errors = errors.load(Ordering::Relaxed);
    let rps = (total_sent as f64 / elapsed.as_secs_f64()).round() as u64;

    println!("\n{}", "═".repeat(60).cyan());
    println!("{} Results", "[*]".cyan().bold());
    println!("{}", "─".repeat(60).dimmed());
    println!("{} Total sent:     {}", "[*]".cyan().bold(), total_sent);
    println!(
        "{} Throttled (429/503): {}",
        "[*]".cyan().bold(),
        if total_throttled > 0 {
            total_throttled.to_string().red().bold().to_string()
        } else {
            "0".green().to_string()
        }
    );
    println!("{} Errors:         {}", "[*]".cyan().bold(), total_errors);
    println!(
        "{} Time:           {:.2}s",
        "[*]".cyan().bold(),
        elapsed.as_secs_f64()
    );
    println!("{} Effective rate: {} req/s", "[*]".cyan().bold(), rps);

    // Status code breakdown
    let counts = status_counts.lock().await;
    if !counts.is_empty() {
        println!("\n{} Status code breakdown:", "[*]".cyan().bold());
        let mut sorted: Vec<_> = counts.iter().collect();
        sorted.sort_by_key(|(k, _)| **k);
        for (code, cnt) in sorted {
            let colored = match *code {
                200..=299 => format!("{}", code).green(),
                300..=399 => format!("{}", code).yellow(),
                400..=499 => format!("{}", code).red(),
                500..=599 => format!("{}", code).magenta(),
                _ => format!("{}", code).white(),
            };
            let pct = (*cnt as f64 / total_sent as f64 * 100.0).round();
            println!("  {} {} ({}%)", "•".cyan(), colored, pct);
        }
    }

    // Verdict
    println!("\n{}", "═".repeat(60).cyan());
    if total_throttled == 0 && total_errors == 0 && total_sent == count as u64 {
        println!(
            "{} NO RATE LIMITING DETECTED — all {} requests succeeded",
            "[!]".red().bold().blink(),
            total_sent
        );
    } else if total_throttled > 0 {
        let throttle_pct = (total_throttled as f64 / total_sent as f64 * 100.0).round();
        println!(
            "{} Rate limiting detected — {}% of requests throttled",
            "[+]".yellow().bold(),
            throttle_pct
        );
        println!(
            "    Throttling started after ~{} requests",
            total_sent - total_throttled
        );
    } else {
        println!(
            "{} Inconclusive — some errors occurred",
            "[-]".yellow().bold()
        );
    }

    Ok(())
}

pub async fn distributed(
    url: &str,
    count: usize,
    sources: usize,
    rate: u64,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Distributed Rate Limit Test", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} URL:     {}", "[*]".cyan().bold(), url.green());
    println!("{} Sources: {} (simulated)", "[*]".cyan().bold(), sources);
    println!("{} Reqs/src: {}", "[*]".cyan().bold(), count);
    println!(
        "{} Total:   {} requests",
        "[*]".cyan().bold(),
        count * sources
    );
    println!("{}", "─".repeat(60).dimmed());

    let user_agents = vec![
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/537.36",
        "Mozilla/5.0 (Android 14; Mobile) AppleWebKit/537.36",
        "curl/8.5.0",
        "Python/3.12 requests/2.31.0",
        "Go-http-client/1.1",
        "PostmanRuntime/7.36.0",
        "okhttp/4.12.0",
    ];

    let client = build_client(timeout, token)?;

    let sent = Arc::new(AtomicU64::new(0));
    let throttled = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));

    let start = Instant::now();
    let mut handles = Vec::new();

    for s in 0..sources {
        let url = url.to_string();
        let client = client.clone();
        let sent = sent.clone();
        let throttled = throttled.clone();
        let errors = errors.clone();
        let ua = user_agents[s % user_agents.len()];
        let fake_ip = format!("10.{}.{}.{}", s + 1, (s * 37) % 255, (s * 73) % 255);

        handles.push(tokio::spawn(async move {
            for _ in 0..count {
                let req = client
                    .get(&url)
                    .header("User-Agent", ua)
                    .header("X-Forwarded-For", &fake_ip);

                match req.send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        sent.fetch_add(1, Ordering::Relaxed);
                        if status == 429 || status == 503 {
                            throttled.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }

                if let Some(delay) = (1000u64).checked_div(rate) {
                    sleep(Duration::from_millis(delay)).await;
                }
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let elapsed = start.elapsed();
    let total_sent = sent.load(Ordering::Relaxed);
    let total_throttled = throttled.load(Ordering::Relaxed);
    let total_errors = errors.load(Ordering::Relaxed);
    let rps = (total_sent as f64 / elapsed.as_secs_f64()).round() as u64;

    println!("\n{}", "═".repeat(60).cyan());
    println!("{} Results", "[*]".cyan().bold());
    println!("{} Total sent:     {}", "[*]".cyan().bold(), total_sent);
    println!(
        "{} Throttled:      {}",
        "[*]".cyan().bold(),
        if total_throttled > 0 {
            total_throttled.to_string().red().bold().to_string()
        } else {
            "0".green().to_string()
        }
    );
    println!("{} Errors:         {}", "[*]".cyan().bold(), total_errors);
    println!(
        "{} Time:           {:.2}s",
        "[*]".cyan().bold(),
        elapsed.as_secs_f64()
    );
    println!("{} Effective rate: {} req/s", "[*]".cyan().bold(), rps);

    println!("\n{}", "═".repeat(60).cyan());
    if total_throttled == 0 {
        println!(
            "{} NO RATE LIMITING DETECTED — distributed requests bypassed throttling",
            "[!]".red().bold().blink()
        );
    } else {
        let pct = (total_throttled as f64 / total_sent as f64 * 100.0).round();
        println!(
            "{} Rate limiting detected even with distributed sources ({}% throttled)",
            "[+]".yellow().bold(),
            pct
        );
    }

    Ok(())
}

pub async fn report(
    base_url: &str,
    endpoints: &str,
    count: usize,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    let paths: Vec<&str> = endpoints.split(',').map(|s| s.trim()).collect();

    println!("{} Rate Limit Report", "[*]".cyan().bold());
    println!("{}", "═".repeat(60).cyan());
    println!("{} Base URL:   {}", "[*]".cyan().bold(), base_url.green());
    println!("{} Endpoints:  {}", "[*]".cyan().bold(), paths.len());
    println!("{} Reqs/endpoint: {}", "[*]".cyan().bold(), count);
    println!("{}", "─".repeat(60).dimmed());

    let client = build_client(timeout, token)?;

    let mut results = Vec::new();

    for path in &paths {
        let url = format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );

        let mut throttled = 0u64;
        let mut sent = 0u64;

        for _ in 0..count {
            if let Ok(resp) = client.get(&url).send().await {
                sent += 1;
                let status = resp.status().as_u16();
                if status == 429 || status == 503 {
                    throttled += 1;
                }
            }
        }

        let verdict = if throttled == 0 && sent == count as u64 {
            "NO RATE LIMITING"
        } else if throttled > 0 {
            "RATE LIMITED"
        } else {
            "INCONCLUSIVE"
        };

        let v_colored = match verdict {
            "NO RATE LIMITING" => verdict.red().bold(),
            "RATE LIMITED" => verdict.green().bold(),
            _ => verdict.yellow(),
        };

        println!(
            "{} {:40} {} (throttled: {}/{})",
            "[>]".cyan(),
            path.white(),
            v_colored,
            throttled,
            sent,
        );

        results.push(EndpointReport {
            path: path.to_string(),
            url,
            sent,
            throttled,
            verdict: verdict.to_string(),
        });
    }

    // Summary
    let no_limit = results
        .iter()
        .filter(|r| r.verdict == "NO RATE LIMITING")
        .count();
    let limited = results
        .iter()
        .filter(|r| r.verdict == "RATE LIMITED")
        .count();

    println!("\n{}", "═".repeat(60).cyan());
    println!("{} Summary", "[*]".cyan().bold());
    println!(
        "{} Rate limited:     {}/{}",
        "[*]".cyan().bold(),
        limited.to_string().green(),
        paths.len()
    );
    println!(
        "{} No rate limiting: {}/{}",
        "[*]".cyan().bold(),
        no_limit.to_string().red().bold(),
        paths.len()
    );

    if no_limit > 0 {
        println!("\n{} Endpoints WITHOUT rate limiting:", "[!]".red().bold());
        for r in &results {
            if r.verdict == "NO RATE LIMITING" {
                println!("  {} {} — {}", "•".red(), r.path.white().bold(), r.url);
            }
        }
    }

    Ok(())
}

struct EndpointReport {
    path: String,
    url: String,
    sent: u64,
    throttled: u64,
    verdict: String,
}

fn build_client(timeout: u64, token: Option<&str>) -> anyhow::Result<reqwest::Client> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "User-Agent",
        reqwest::header::HeaderValue::from_static("PledgeStrike/0.1"),
    );

    if let Some(t) = token {
        headers.insert(
            "Authorization",
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", t))?,
        );
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    Ok(client)
}

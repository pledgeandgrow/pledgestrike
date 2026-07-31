use colored::Colorize;
use reqwest::Client;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

fn build_client(timeout: u64, token: Option<&str>) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(t) = token {
        builder = builder.default_headers(
            reqwest::header::HeaderMap::from_iter([(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", t)).unwrap(),
            )]),
        );
    }
    builder.build().unwrap_or_else(|_| Client::new())
}

pub async fn race(
    url: &str,
    method: &str,
    body: Option<&str>,
    token: Option<&str>,
    timeout: u64,
    workers: usize,
    count: usize,
) -> anyhow::Result<()> {
    println!("{} Race Condition Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:     {}", "[*]".cyan().bold(), url);
    println!("{} Method:  {}", "[*]".cyan().bold(), method);
    println!("{} Workers: {}", "[*]".cyan().bold(), workers);
    println!("{} Count:   {}", "[*]".cyan().bold(), count);
    println!("{}", "-".repeat(60).dimmed());

    let client = Arc::new(build_client(timeout, token));
    let results = Arc::new(Mutex::new(Vec::new()));
    let barrier = Arc::new(tokio::sync::Barrier::new(workers));

    let requests_per_worker = count / workers;
    let remainder = count % workers;

    let mut handles = Vec::new();
    for worker_id in 0..workers {
        let client = Arc::clone(&client);
        let results = Arc::clone(&results);
        let barrier = Arc::clone(&barrier);
        let url = url.to_string();
        let method = method.to_string();
        let body = body.map(|b| b.to_string());
        let n = requests_per_worker + if worker_id < remainder { 1 } else { 0 };

        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let start = Instant::now();
            for _ in 0..n {
                let mut req = match method.to_uppercase().as_str() {
                    "POST" => client.post(&url),
                    "PUT" => client.put(&url),
                    "PATCH" => client.patch(&url),
                    "DELETE" => client.delete(&url),
                    _ => client.get(&url),
                };
                if let Some(ref b) = body {
                    req = req.header("Content-Type", "application/json").body(b.clone());
                }
                let resp = req.send().await;
                let status = resp.map(|r| r.status().as_u16()).unwrap_or(0);
                let elapsed = start.elapsed();
                results.lock().await.push((status, elapsed));
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let results = results.lock().await;
    let total = results.len();
    let success = results.iter().filter(|(s, _)| *s >= 200 && *s < 300).count();
    let errors = results.iter().filter(|(s, _)| *s == 0).count();
    let conflicts = results.iter().filter(|(s, _)| *s == 409).count();
    let rate_limited = results.iter().filter(|(s, _)| *s == 429).count();

    let avg_time = if total > 0 {
        results.iter().map(|(_, t)| t.as_millis()).sum::<u128>() as f64 / total as f64
    } else { 0.0 };

    println!("\n{} Results:", "[*]".cyan().bold());
    println!("  {} Total requests:    {}", "*".cyan(), total);
    println!("  {} Success (2xx):     {}", "*".cyan(), success);
    println!("  {} Conflicts (409):   {}", "*".cyan(), conflicts);
    println!("  {} Rate limited (429): {}", "*".cyan(), rate_limited);
    println!("  {} Errors:            {}", "*".cyan(), errors);
    println!("  {} Avg time:          {:.1}ms", "*".cyan(), avg_time);

    if success > 1 {
        println!("\n{} [HIGH] {} successful responses — possible race condition!", "[!]".red().bold(), success);
    } else if conflicts > 0 {
        println!("\n{} Server detected conflicts (409). Race condition protection may exist.", "[-]".yellow().bold());
    } else if rate_limited > 0 {
        println!("\n{} Rate limited (429). Server has rate limiting protection.", "[-]".yellow().bold());
    } else {
        println!("\n{} No race condition detected.", "[-]".yellow().bold());
    }
    Ok(())
}

pub async fn toctou(
    url: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} TOCTOU (Time-of-Check Time-of-Use) Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    println!("{} Step 1: Baseline request (check state)...", "[*]".cyan().bold());
    let resp1 = client.get(url).send().await;
    let (status1, body1) = match resp1 {
        Ok(r) => { let s = r.status(); let b = r.text().await.unwrap_or_default(); (s, b) }
        Err(_) => { println!("{} Baseline request failed.", "[-]".red().bold()); return Ok(()); }
    };
    println!("  {} Status: {}, Length: {} bytes", "*".cyan(), status1, body1.len());

    println!("{} Step 2: Concurrent modification + check...", "[*]".cyan().bold());
    let client_arc = Arc::new(client);
    let url_arc = Arc::new(url.to_string());

    let mut handles = Vec::new();
    for i in 0..10 {
        let c = Arc::clone(&client_arc);
        let u = Arc::clone(&url_arc);
        handles.push(tokio::spawn(async move {
            let req = c.post(&*u).header("Content-Type", "application/json")
                .body(format!(r#"{{"action":"modify","seq":{}}}"#, i));
            req.send().await.map(|r| r.status().as_u16()).unwrap_or(0)
        }));
    }

    let mut statuses = Vec::new();
    for h in handles {
        statuses.push(h.await.unwrap_or(0));
    }

    println!("{} Step 3: Final state check...", "[*]".cyan().bold());
    let resp2 = client_arc.get(&*url_arc).send().await;
    let (status2, body2) = match resp2 {
        Ok(r) => { let s = r.status(); let b = r.text().await.unwrap_or_default(); (s, b) }
        Err(_) => { println!("{} Final check failed.", "[-]".red().bold()); return Ok(()); }
    };
    println!("  {} Status: {}, Length: {} bytes", "*".cyan(), status2, body2.len());

    let state_changed = body1 != body2;
    let concurrent_success = statuses.iter().filter(|s| **s >= 200 && **s < 300).count();

    println!("\n{} Results:", "[*]".cyan().bold());
    println!("  {} Concurrent modifications accepted: {}", "*".cyan(), concurrent_success);
    println!("  {} State changed: {}", "*".cyan(), if state_changed { "YES".red().to_string() } else { "no".to_string() });

    if state_changed && concurrent_success > 1 {
        println!("\n{} [HIGH] TOCTOU vulnerability — state changed during concurrent access!", "[!]".red().bold());
    } else {
        println!("\n{} No TOCTOU detected.", "[-]".yellow().bold());
    }
    Ok(())
}

pub async fn balance(
    url: &str,
    account: &str,
    token: Option<&str>,
    timeout: u64,
    workers: usize,
    amount: &str,
) -> anyhow::Result<()> {
    println!("{} Double-Spend / Balance Race Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:      {}", "[*]".cyan().bold(), url);
    println!("{} Account:  {}", "[*]".cyan().bold(), account);
    println!("{} Amount:   {}", "[*]".cyan().bold(), amount);
    println!("{} Workers:  {}", "[*]".cyan().bold(), workers);
    println!("{}", "-".repeat(60).dimmed());

    let client = Arc::new(build_client(timeout, token));
    let results = Arc::new(Mutex::new(Vec::new()));
    let barrier = Arc::new(tokio::sync::Barrier::new(workers));

    let body = format!(r#"{{"account":"{}","amount":{}}}"#, account, amount);

    let mut handles = Vec::new();
    for _ in 0..workers {
        let c = Arc::clone(&client);
        let r = Arc::clone(&results);
        let b = Arc::new(tokio::sync::Barrier::new(0));
        let barrier = Arc::clone(&barrier);
        let url = url.to_string();
        let body = body.clone();

        handles.push(tokio::spawn(async move {
            let _ = &b;
            barrier.wait().await;
            let resp = c.post(&url)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await;
            let (status, body_text) = match resp {
                Ok(r) => { let s = r.status(); let b = r.text().await.unwrap_or_default(); (s.as_u16(), b) }
                Err(_) => (0u16, String::new()),
            };
            r.lock().await.push((status, body_text));
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let results = results.lock().await;
    let success = results.iter().filter(|(s, _)| *s >= 200 && *s < 300).count();
    let balance_after = results.iter()
        .find(|(_, b)| b.contains("balance") || b.contains("amount"))
        .map(|(_, b)| b.chars().take(200).collect::<String>())
        .unwrap_or_default();

    println!("\n{} Results:", "[*]".cyan().bold());
    println!("  {} Concurrent transfers sent: {}", "*".cyan(), workers);
    println!("  {} Successful (2xx):          {}", "*".cyan(), success);

    if success > 1 {
        println!("  {} [HIGH] {} transfers succeeded — double-spend possible!", "[!]".red().bold(), success);
        if !balance_after.is_empty() {
            println!("  {} Balance response: {}", "*".cyan(), balance_after);
        }
    } else if success == 1 {
        println!("  {} Only 1 transfer succeeded — server may have protection.", "[-]".yellow().bold());
    } else {
        println!("  {} No transfers succeeded.", "[-]".yellow().bold());
    }
    Ok(())
}

pub async fn coupon(
    url: &str,
    coupon: &str,
    token: Option<&str>,
    timeout: u64,
    workers: usize,
) -> anyhow::Result<()> {
    println!("{} Coupon Abuse Race Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:     {}", "[*]".cyan().bold(), url);
    println!("{} Coupon:  {}", "[*]".cyan().bold(), coupon);
    println!("{} Workers: {}", "[*]".cyan().bold(), workers);
    println!("{}", "-".repeat(60).dimmed());

    let client = Arc::new(build_client(timeout, token));
    let results = Arc::new(Mutex::new(Vec::new()));
    let barrier = Arc::new(tokio::sync::Barrier::new(workers));

    let mut handles = Vec::new();
    for _ in 0..workers {
        let c = Arc::clone(&client);
        let r = Arc::clone(&results);
        let barrier = Arc::clone(&barrier);
        let url = url.to_string();
        let coupon = coupon.to_string();

        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let test_url = format!("{}{}coupon={}", url, if url.contains('?') { "&" } else { "?" }, coupon);
            let resp = c.post(&test_url)
                .header("Content-Type", "application/json")
                .body(format!(r#"{{"coupon":"{}"}}"#, coupon))
                .send()
                .await;
            let (status, body) = match resp {
                Ok(r) => { let s = r.status(); let b = r.text().await.unwrap_or_default(); (s.as_u16(), b) }
                Err(_) => (0u16, String::new()),
            };
            r.lock().await.push((status, body));
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let results = results.lock().await;
    let success = results.iter().filter(|(s, _)| *s >= 200 && *s < 300).count();
    let applied = results.iter().filter(|(_, b)| b.contains("applied") || b.contains("discount") || b.contains("success")).count();
    let rejected = results.iter().filter(|(_, b)| b.contains("used") || b.contains("expired") || b.contains("invalid") || b.contains("already")).count();

    println!("\n{} Results:", "[*]".cyan().bold());
    println!("  {} Concurrent attempts:  {}", "*".cyan(), workers);
    println!("  {} Successful (2xx):     {}", "*".cyan(), success);
    println!("  {} Coupon applied:       {}", "*".cyan(), applied);
    println!("  {} Rejected:             {}", "*".cyan(), rejected);

    if applied > 1 {
        println!("\n{} [HIGH] Coupon applied {} times — coupon abuse possible!", "[!]".red().bold(), applied);
    } else if applied == 1 {
        println!("\n{} Coupon applied once — server may have protection.", "[-]".yellow().bold());
    } else {
        println!("\n{} Coupon not applied.", "[-]".yellow().bold());
    }
    Ok(())
}

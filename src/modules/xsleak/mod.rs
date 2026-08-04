use colored::Colorize;
use reqwest::Client;
use std::time::{Duration, Instant};

fn build_client(timeout: u64, token: Option<&str>) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(t) = token {
        builder = builder.default_headers(reqwest::header::HeaderMap::from_iter([(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", t)).unwrap(),
        )]));
    }
    builder.build().unwrap_or_else(|_| Client::new())
}

const TIMING_ORIGINS: &[&str] = &[
    "https://target.com",
    "https://evil.com",
    "https://localhost",
    "https://127.0.0.1",
    "https://0.0.0.0",
    "https://[::1]",
    "https://sub.target.com",
    "https://target.com.evil.com",
    "https://attacker.target.com",
    "https://target.com:8080",
    "https://target.com:8443",
    "https://target.com:3000",
    "https://target.com:443",
    "https://target.com:22",
    "https://target.com:6379",
    "https://target.com:27017",
    "https://nonexistent.target.com",
    "https://internal.target.com",
    "https://admin.target.com",
    "https://dev.target.com",
];

const ERROR_EVENTS: &[(&str, &str)] = &[
    ("img onerror", "<img src=\"https://TARGET/x\" onerror=\"log('error')\">"),
    ("script onerror", "<script src=\"https://TARGET/x\" onerror=\"log('error')\">"),
    ("link onerror", "<link rel=\"stylesheet\" href=\"https://TARGET/x\" onerror=\"log('error')\">"),
    ("object onerror", "<object data=\"https://TARGET/x\" onerror=\"log('error')\">"),
    ("audio onerror", "<audio src=\"https://TARGET/x\" onerror=\"log('error')\">"),
    ("video onerror", "<video src=\"https://TARGET/x\" onerror=\"log('error')\">"),
    ("source onerror", "<source src=\"https://TARGET/x\" onerror=\"log('error')\">"),
    ("iframe onload", "<iframe src=\"https://TARGET\" onload=\"log('loaded')\">"),
    ("fetch catch", "fetch('https://TARGET').catch(()=>log('blocked'))"),
    ("XMLHttpRequest", "var x=new XMLHttpRequest();x.open('GET','https://TARGET');x.onerror=()=>log('blocked');x.send()"),
    ("import()", "import('https://TARGET/x').catch(()=>log('blocked'))"),
    ("Worker", "new Worker('https://TARGET/x').onerror=()=>log('blocked')"),
    ("SharedWorker", "new SharedWorker('https://TARGET/x').onerror=()=>log('blocked')"),
    ("WebSocket", "new WebSocket('wss://TARGET/x').onerror=()=>log('blocked')"),
    ("EventSource", "new EventSource('https://TARGET/x').onerror=()=>log('blocked')"),
];

const FRAME_COUNT_PAYLOADS: &[&str] = &[
    "frames.length",
    "window.frames.length",
    "document.getElementsByTagName('iframe').length",
    "document.querySelectorAll('iframe').length",
    "window.length",
    "self.frames.length",
];

const NAVIGATION_PAYLOADS: &[(&str, &str)] = &[
    ("window.open", "window.open('https://TARGET', '_blank')"),
    ("location.href", "location.href='https://TARGET'"),
    ("location.replace", "location.replace('https://TARGET')"),
    ("location.assign", "location.assign('https://TARGET')"),
    ("history.pushState", "history.pushState({}, '', 'https://TARGET')"),
    ("history.replaceState", "history.replaceState({}, '', 'https://TARGET')"),
    ("form.action", "document.forms[0].action='https://TARGET'"),
    ("a.href click", "var a=document.createElement('a');a.href='https://TARGET';a.click()"),
    ("meta refresh", "<meta http-equiv='refresh' content='0;url=https://TARGET'>"),
    ("window.navigate", "window.navigate('https://TARGET')"),
];

pub async fn detect(url: &str, token: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} XS-Leak Detection Suite", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout, token);

    println!("\n{} [1/4] Timing-based XS-Leak detection...", "[*]".cyan().bold());
    println!("  {} Measuring response times for {} origins...", "*".cyan(), TIMING_ORIGINS.len());
    let mut timing_results = Vec::new();

    for origin in TIMING_ORIGINS {
        let test_url = origin.replace("TARGET", &url.trim_start_matches("https://").trim_start_matches("http://"));
        let start = Instant::now();
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let elapsed = start.elapsed();
                let status = resp.status().as_u16();
                let _ = resp.text().await;
                timing_results.push((origin.to_string(), elapsed, status));
                let tag = if elapsed.as_millis() > 500 {
                    "SLOW".yellow().to_string()
                } else if elapsed.as_millis() > 200 {
                    "medium".to_string()
                } else {
                    "fast".green().to_string()
                };
                println!(
                    "  {} {:40} status={} {:6.0}ms {}",
                    "*".cyan(),
                    origin,
                    status,
                    elapsed.as_secs_f64() * 1000.0,
                    tag
                );
            }
            Err(_) => {
                let elapsed = start.elapsed();
                timing_results.push((origin.to_string(), elapsed, 0));
                println!(
                    "  {} {:40} error   {:6.0}ms",
                    "*".red(),
                    origin,
                    elapsed.as_secs_f64() * 1000.0
                );
            }
        }
    }

    let fast_count = timing_results.iter().filter(|(_, t, _)| t.as_millis() < 100).count();
    let slow_count = timing_results.iter().filter(|(_, t, _)| t.as_millis() > 500).count();
    println!(
        "  {} {} fast (<100ms), {} slow (>500ms) — timing side-channel {}",
        "[*]".cyan().bold(),
        fast_count,
        slow_count,
        if slow_count > fast_count / 2 { "POSSIBLE".red().bold().to_string() } else { "unlikely".green().to_string() }
    );

    println!("\n{} [2/4] Error event XS-Leak detection...", "[*]".cyan().bold());
    println!("  {} Testing {} error event vectors...", "*".cyan(), ERROR_EVENTS.len());
    for (name, payload) in ERROR_EVENTS {
        let test_payload = payload.replace("TARGET", &url.trim_start_matches("https://").trim_start_matches("http://"));
        let test_url = format!("{}?xss={}", url, urlencoding_encode(&test_payload));
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let reflected = body.contains(&test_payload) || body.contains("onerror") || body.contains("onload");
                let tag = if reflected {
                    "REFLECTED".red().bold().to_string()
                } else {
                    "not reflected".dimmed().to_string()
                };
                println!("  {} {:20} status={} {}", "*".cyan(), name, status, tag);
            }
            Err(_) => {
                println!("  {} {:20} error", "*".red(), name);
            }
        }
    }

    println!("\n{} [3/4] Frame counting XS-Leak...", "[*]".cyan().bold());
    println!("  {} Testing {} frame count probes...", "*".cyan(), FRAME_COUNT_PAYLOADS.len());
    for payload in FRAME_COUNT_PAYLOADS {
        let test_url = format!("{}?probe={}", url, urlencoding_encode(payload));
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let reflected = body.contains(payload);
                let tag = if reflected {
                    "REFLECTED".red().bold().to_string()
                } else {
                    "not reflected".dimmed().to_string()
                };
                println!("  {} {:45} status={} {}", "*".cyan(), payload, status, tag);
            }
            Err(_) => {
                println!("  {} {:45} error", "*".red(), payload);
            }
        }
    }

    println!("\n{} [4/4] Navigation-based XS-Leak...", "[*]".cyan().bold());
    println!("  {} Testing {} navigation vectors...", "*".cyan(), NAVIGATION_PAYLOADS.len());
    let mut nav_results = Vec::new();
    for (name, payload) in NAVIGATION_PAYLOADS {
        let test_payload = payload.replace("TARGET", &url.trim_start_matches("https://").trim_start_matches("http://"));
        let test_url = format!("{}?nav={}", url, urlencoding_encode(&test_payload));
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let reflected = body.contains(&test_payload) || body.contains("location.href") || body.contains("window.open");
                let tag = if reflected {
                    "REFLECTED".red().bold().to_string()
                } else {
                    "not reflected".dimmed().to_string()
                };
                println!("  {} {:20} status={} {}", "*".cyan(), name, status, tag);
                if reflected {
                    nav_results.push(*name);
                }
            }
            Err(_) => {
                println!("  {} {:20} error", "*".red(), name);
            }
        }
    }

    println!("\n{} XS-Leak Summary:", "[*]".cyan().bold());
    println!("  {} Timing side-channel: {} fast, {} slow responses", "*".cyan(), fast_count, slow_count);
    println!("  {} Error events: {} vectors tested", "*".cyan(), ERROR_EVENTS.len());
    println!("  {} Frame counting: {} probes tested", "*".cyan(), FRAME_COUNT_PAYLOADS.len());
    println!("  {} Navigation: {} / {} reflected", "*".cyan(), nav_results.len(), NAVIGATION_PAYLOADS.len());

    if slow_count > 3 {
        println!("\n{} [HIGH] Timing differences detected — cross-site timing attack possible!", "[!]".red().bold());
    }
    if !nav_results.is_empty() {
        println!("{} [MEDIUM] Navigation payloads reflected — history-based leak possible", "[!]".yellow().bold());
    }

    Ok(())
}

fn urlencoding_encode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u8)
            }
        })
        .collect()
}

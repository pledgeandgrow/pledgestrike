use colored::Colorize;
use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

const PARAM_WORDLIST: &[&str] = &[
    "id", "user", "admin", "debug", "test", "cmd", "exec", "file", "path",
    "url", "redirect", "next", "return", "callback", "token", "key", "secret",
    "api", "query", "search", "filter", "sort", "order", "page", "limit",
    "action", "type", "name", "value", "data", "input", "output", "config",
    "settings", "env", "var", "flag", "mode", "status", "state", "level",
    "role", "group", "perm", "access", "auth", "session", "csrf", "xss",
    "sql", "cmd", "shell", "upload", "download", "import", "export", "backup",
];

const HEADER_WORDLIST: &[&str] = &[
    "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host", "X-Original-URL",
    "X-Rewrite-URL", "X-Custom-Header", "X-Debug", "X-Test", "X-Admin",
    "X-Internal", "X-Backend", "X-Server", "X-Env", "X-Config",
    "X-Forwarded-Proto", "X-Request-ID", "X-Trace-ID", "X-API-Key",
    "X-Auth-Token", "X-Secret", "X-Flag", "X-Mode", "X-Status",
    "X-User", "X-Role", "X-Access", "X-Permission", "X-Override",
];

const COOKIE_WORDLIST: &[&str] = &[
    "session", "token", "auth", "user", "admin", "role", "csrf",
    "jwt", "ssid", "apisid", "hsid", "sid", "uid", "gid",
    "debug", "test", "dev", "staging", "internal", "override",
    "impersonate", "proxy", "access", "perm", "level", "flag",
];

pub async fn param(url: &str, wordlist: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Parameter Fuzzing", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let words: Vec<String> = if let Some(wl) = wordlist {
        std::fs::read_to_string(wl)?.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    } else {
        PARAM_WORDLIST.iter().map(|s| s.to_string()).collect()
    };

    println!("{} Testing {} parameters", "[*]".cyan().bold(), words.len());

    let baseline = client.get(url).send().await;
    let (base_status, base_len, base_body) = match baseline {
        Ok(r) => { let s = r.status().as_u16(); let b = r.text().await.unwrap_or_default(); (s, b.len(), b) }
        Err(_) => { println!("{} Baseline request failed", "[-]".red().bold()); return Ok(()); }
    };
    println!("{} Baseline: status={} len={}", "[*]".cyan().bold(), base_status, base_len);

    let mut interesting = Vec::new();

    for word in &words {
        let test_url = if url.contains('?') { format!("{}&{}=test", url, word) } else { format!("{}?{}=test", url, word) };
        match client.get(&test_url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let len = body.len();
                let status_diff = status != base_status;
                let len_diff = (len as i64 - base_len as i64).abs() > 100;
                let body_diff = body != base_body && !body.is_empty();

                if status_diff || len_diff || body_diff {
                    let tag = if status_diff { "STATUS CHANGE".red().bold().to_string() }
                        else if len_diff { "SIZE CHANGE".yellow().to_string() }
                        else { "BODY CHANGE".to_string() };
                    println!("  {} {:20} status={} len={} {}", "*".cyan(), word, status, len, tag);
                    interesting.push((word.clone(), status, len, tag));
                }
            }
            Err(_) => {}
        }
    }

    if interesting.is_empty() {
        println!("\n{} No interesting parameters found.", "[-]".yellow().bold());
    } else {
        println!("\n{} {} interesting parameter(s) found:", "[*]".cyan().bold(), interesting.len());
        for (param, status, len, tag) in &interesting {
            println!("  {} {:20} status={} len={} {}", "*".green(), param, status, len, tag);
        }
    }
    Ok(())
}

pub async fn header(url: &str, wordlist: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Header Fuzzing", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let words: Vec<String> = if let Some(wl) = wordlist {
        std::fs::read_to_string(wl)?.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    } else {
        HEADER_WORDLIST.iter().map(|s| s.to_string()).collect()
    };

    println!("{} Testing {} headers", "[*]".cyan().bold(), words.len());

    let baseline = client.get(url).send().await;
    let (base_status, base_len) = match baseline {
        Ok(r) => { let s = r.status().as_u16(); let b = r.text().await.unwrap_or_default(); (s, b.len()) }
        Err(_) => { println!("{} Baseline failed", "[-]".red().bold()); return Ok(()); }
    };
    println!("{} Baseline: status={} len={}", "[*]".cyan().bold(), base_status, base_len);

    let mut interesting = Vec::new();

    for word in &words {
        match client.get(url).header(word, "127.0.0.1").send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let len = body.len();
                let status_diff = status != base_status;
                let len_diff = (len as i64 - base_len as i64).abs() > 100;

                if status_diff || len_diff {
                    let tag = if status_diff { "STATUS CHANGE".red().bold().to_string() } else { "SIZE CHANGE".yellow().to_string() };
                    println!("  {} {:25} status={} len={} {}", "*".cyan(), word, status, len, tag);
                    interesting.push((word.clone(), status, len, tag));
                }
            }
            Err(_) => {}
        }
    }

    if interesting.is_empty() {
        println!("\n{} No interesting headers found.", "[-]".yellow().bold());
    } else {
        println!("\n{} {} interesting header(s) found:", "[*]".cyan().bold(), interesting.len());
        for (h, status, len, tag) in &interesting {
            println!("  {} {:25} status={} len={} {}", "*".green(), h, status, len, tag);
        }
    }
    Ok(())
}

pub async fn body(url: &str, wordlist: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Body Fuzzing", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let words: Vec<String> = if let Some(wl) = wordlist {
        std::fs::read_to_string(wl)?.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    } else {
        PARAM_WORDLIST.iter().map(|s| s.to_string()).collect()
    };

    println!("{} Testing {} body parameters", "[*]".cyan().bold(), words.len());

    let baseline = client.post(url).body("").send().await;
    let (base_status, base_len) = match baseline {
        Ok(r) => { let s = r.status().as_u16(); let b = r.text().await.unwrap_or_default(); (s, b.len()) }
        Err(_) => { println!("{} Baseline failed", "[-]".red().bold()); return Ok(()); }
    };
    println!("{} Baseline: status={} len={}", "[*]".cyan().bold(), base_status, base_len);

    let mut interesting = Vec::new();

    for word in &words {
        let body = format!("{}=test", word);
        match client.post(url).header("Content-Type", "application/x-www-form-urlencoded").body(body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_body = resp.text().await.unwrap_or_default();
                let len = resp_body.len();
                let status_diff = status != base_status;
                let len_diff = (len as i64 - base_len as i64).abs() > 100;

                if status_diff || len_diff {
                    let tag = if status_diff { "STATUS CHANGE".red().bold().to_string() } else { "SIZE CHANGE".yellow().to_string() };
                    println!("  {} {:20} status={} len={} {}", "*".cyan(), word, status, len, tag);
                    interesting.push((word.clone(), status, len, tag));
                }
            }
            Err(_) => {}
        }
    }

    if interesting.is_empty() {
        println!("\n{} No interesting body params found.", "[-]".yellow().bold());
    } else {
        println!("\n{} {} interesting param(s) found:", "[*]".cyan().bold(), interesting.len());
        for (p, status, len, tag) in &interesting {
            println!("  {} {:20} status={} len={} {}", "*".green(), p, status, len, tag);
        }
    }
    Ok(())
}

pub async fn cookie(url: &str, wordlist: Option<&str>, timeout: u64) -> anyhow::Result<()> {
    println!("{} Cookie Fuzzing", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let words: Vec<String> = if let Some(wl) = wordlist {
        std::fs::read_to_string(wl)?.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
    } else {
        COOKIE_WORDLIST.iter().map(|s| s.to_string()).collect()
    };

    println!("{} Testing {} cookies", "[*]".cyan().bold(), words.len());

    let baseline = client.get(url).send().await;
    let (base_status, base_len) = match baseline {
        Ok(r) => { let s = r.status().as_u16(); let b = r.text().await.unwrap_or_default(); (s, b.len()) }
        Err(_) => { println!("{} Baseline failed", "[-]".red().bold()); return Ok(()); }
    };
    println!("{} Baseline: status={} len={}", "[*]".cyan().bold(), base_status, base_len);

    let mut interesting = Vec::new();

    for word in &words {
        match client.get(url).header("Cookie", format!("{}=test", word)).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let len = body.len();
                let status_diff = status != base_status;
                let len_diff = (len as i64 - base_len as i64).abs() > 100;

                if status_diff || len_diff {
                    let tag = if status_diff { "STATUS CHANGE".red().bold().to_string() } else { "SIZE CHANGE".yellow().to_string() };
                    println!("  {} {:20} status={} len={} {}", "*".cyan(), word, status, len, tag);
                    interesting.push((word.clone(), status, len, tag));
                }
            }
            Err(_) => {}
        }
    }

    if interesting.is_empty() {
        println!("\n{} No interesting cookies found.", "[-]".yellow().bold());
    } else {
        println!("\n{} {} interesting cookie(s) found:", "[*]".cyan().bold(), interesting.len());
        for (c, status, len, tag) in &interesting {
            println!("  {} {:20} status={} len={} {}", "*".green(), c, status, len, tag);
        }
    }
    Ok(())
}

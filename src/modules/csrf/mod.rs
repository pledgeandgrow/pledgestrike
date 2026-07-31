use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn token(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} CSRF Token Bypass Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    let token_patterns = ["csrf", "CSRF", "csrfToken", "csrf_token", "authenticity_token", "csrfmiddlewaretoken", "__RequestVerificationToken", "anticsrf", "_csrf", "token"];
    let mut found_tokens = Vec::new();
    for p in &token_patterns {
        if body.contains(p) {
            found_tokens.push(*p);
        }
    }

    if found_tokens.is_empty() {
        println!("  {} No CSRF token detected in page.", "[-]".green().bold());
        return Ok(());
    }

    println!("  {} CSRF tokens found: {}", "[+]".yellow().bold(), found_tokens.join(", "));

    let test_cases = [
        ("Remove token", "submit without csrf token"),
        ("Empty token", "submit with empty csrf field"),
        ("Static token", "submit with a hardcoded/static token"),
        ("Cross-user token", "submit with another user's token"),
        ("GET param token", "submit token as GET parameter instead of POST body"),
        ("Header token", "submit token in X-CSRF-Token header"),
    ];

    println!("\n  {} Testing bypass techniques:", "[*]".cyan().bold());
    for (name, desc) in &test_cases {
        println!("    {} {} — {}", "*".cyan(), name, desc);
    }

    let post_body = serde_json::json!({"action": "test", "submit": "1"});
    let no_token_resp = client.post(url).json(&post_body).send().await;
    if let Ok(r) = no_token_resp {
        let s = r.status().as_u16();
        if s == 200 || s == 201 || s == 302 {
            println!("\n  {} Request without token was accepted (status={})!", "[!]".red().bold(), s);
        } else {
            println!("\n  {} Request without token was rejected (status={})", "[-]".green().bold(), s);
        }
    }

    let header_resp = client.post(url).header("X-CSRF-Token", "test").json(&post_body).send().await;
    if let Ok(r) = header_resp {
        let s = r.status().as_u16();
        if s == 200 || s == 201 || s == 302 {
            println!("  {} Token via header was accepted (status={})!", "[!]".red().bold(), s);
        }
    }

    Ok(())
}

pub async fn samesite(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SameSite Cookie Bypass Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let cookies = resp.headers().get_all("set-cookie");

    let mut found_samesite = false;
    for cookie in cookies {
        let cookie_str = cookie.to_str().unwrap_or("");
        if cookie_str.contains("SameSite") {
            found_samesite = true;
            if cookie_str.contains("SameSite=None") {
                println!("  {} Cookie has SameSite=None — cross-site requests allowed.", "[!]".red().bold());
            } else if cookie_str.contains("SameSite=Lax") {
                println!("  {} Cookie has SameSite=Lax — bypassable via top-level navigation GET.", "[*]".yellow().bold());
            } else if cookie_str.contains("SameSite=Strict") {
                println!("  {} Cookie has SameSite=Strict — most restrictive.", "[-]".green().bold());
            }
        } else {
            println!("  {} Cookie without SameSite: {}", "[!]".red().bold(), cookie_str.chars().take(60).collect::<String>());
        }
    }

    if !found_samesite {
        println!("  {} No SameSite attribute on cookies — vulnerable to CSRF!", "[!]".red().bold());
    }

    let bypass_methods = [
        ("window.open", "window.open('target', '_blank') — top-level navigation bypass for Lax"),
        ("meta refresh", "<meta http-equiv='refresh' content='0;url=target'> — navigation bypass"),
        ("form GET", "<form method='GET' action='target'> — Lax allows top-level GET"),
        ("iframe POST", "Cross-origin iframe POST — older browsers ignore SameSite"),
        ("link prefetch", "<link rel='prefetch' href='target'> — background request"),
    ];

    println!("\n  {} SameSite bypass vectors:", "[*]".cyan().bold());
    for (name, desc) in &bypass_methods {
        println!("    {} {} — {}", "*".cyan(), name, desc);
    }

    Ok(())
}

pub async fn json(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} JSON CSRF Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        ("Plain JSON POST", "application/json", r#"{"action":"test"}"#),
        ("Text/plain POST", "text/plain", r#"{"action":"test"}"#),
        ("Multipart CSRF", "multipart/form-data", r#"--boundary\r\nContent-Disposition: form-data; name="action"\r\n\r\ntest\r\n--boundary--"#),
        ("Form-encoded", "application/x-www-form-urlencoded", "action=test"),
    ];

    for (name, ct, body) in &payloads {
        let resp = client.post(url).header("Content-Type", *ct).body(*body).send().await;
        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                let tag = if status == 200 || status == 201 { "ACCEPTED".red().bold().to_string() } else { format!("status={}", status) };
                println!("  {} {:25} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:25} error", "[-]".dimmed(), name),
        }
    }

    println!("\n  {} JSON CSRF requires content-type confusion or CORS misconfiguration.", "[*]".yellow().bold());
    Ok(())
}

pub async fn method(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Method-Based CSRF Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let methods = ["GET", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"];

    for method in &methods {
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let resp = client.request(m, url).body("action=test&value=1").send().await;
        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                let tag = if status == 200 || status == 201 || status == 204 {
                    format!("status={} — STATE CHANGE POSSIBLE", status).red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:8} {}", "*".cyan(), method, tag);
            }
            Err(_) => println!("  {} {:8} error", "[-]".dimmed(), method),
        }
    }

    println!("\n{} GET-based state changes are the most dangerous CSRF vector.", "[*]".yellow().bold());
    Ok(())
}

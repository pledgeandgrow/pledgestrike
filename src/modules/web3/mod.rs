use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn reentrancy(url: &str, timeout: u64, token: Option<&str>) -> anyhow::Result<()> {
    println!("{} Smart Contract Reentrancy Detector", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let checks = [
        ("External call before state update", r#"{"action":"analyze","check":"reentrancy","pattern":"external_call_before_state"}"#),
        ("Withdraw pattern", r#"{"action":"analyze","check":"reentrancy","pattern":"withdraw_without_guard"}"#),
        ("No reentrancy guard", r#"{"action":"analyze","check":"reentrancy","pattern":"no_mutex"}"#),
        ("Call.value before update", r#"{"action":"analyze","check":"reentrancy","pattern":"call_value_before_update"}"#),
        ("Transfer before state", r#"{"action":"analyze","check":"reentrancy","pattern":"transfer_before_update"}"#),
        ("Send before update", r#"{"action":"analyze","check":"reentrancy","pattern":"send_before_update"}"#),
        ("NonReentrant missing", r#"{"action":"analyze","check":"reentrancy","pattern":"no_nonReentrant"}"#),
        ("ERC777 reentrancy", r#"{"action":"analyze","check":"reentrancy","pattern":"erc777_hook"}"#),
    ];

    let mut issues = Vec::new();
    for (name, payload) in &checks {
        let mut req = client.post(url).header("Content-Type", "application/json");
        if let Some(t) = token { req = req.header("Authorization", format!("Bearer {}", t)); }
        match req.body(payload.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let found = body.contains("vulnerable") || body.contains("issue") || body.contains("risk") || body.contains("true");
                let tag = if found { "VULNERABLE".red().bold().to_string() } else { "safe".green().to_string() };
                println!("  {} {:40} status={} {}", "*".cyan(), name, status, tag);
                if found { issues.push(name.to_string()); }
            }
            Err(_) => { println!("  {} {:40} error", "*".red(), name); }
        }
    }

    if !issues.is_empty() { println!("\n{} {} reentrancy issue(s) detected!", "[!]".red().bold(), issues.len()); }
    else { println!("\n{} No reentrancy vulnerabilities found.", "[-]".green().bold()); }
    Ok(())
}

pub async fn overflow(url: &str, timeout: u64, token: Option<&str>) -> anyhow::Result<()> {
    println!("{} Integer Overflow/Underflow Detector", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let checks = [
        ("Unchecked addition", r#"{"action":"analyze","check":"overflow","pattern":"unchecked_add"}"#),
        ("Unchecked subtraction", r#"{"action":"analyze","check":"overflow","pattern":"unchecked_sub"}"#),
        ("Unchecked multiplication", r#"{"action":"analyze","check":"overflow","pattern":"unchecked_mul"}"#),
        ("No SafeMath", r#"{"action":"analyze","check":"overflow","pattern":"no_safemath"}"#),
        ("Balance arithmetic", r#"{"action":"analyze","check":"overflow","pattern":"balance_arithmetic"}"#),
        ("Token supply arithmetic", r#"{"action":"analyze","check":"overflow","pattern":"supply_arithmetic"}"#),
        ("Array length manipulation", r#"{"action":"analyze","check":"overflow","pattern":"array_length"}"#),
        ("Timestamp dependence", r#"{"action":"analyze","check":"overflow","pattern":"timestamp"}"#),
    ];

    let mut issues = Vec::new();
    for (name, payload) in &checks {
        let mut req = client.post(url).header("Content-Type", "application/json");
        if let Some(t) = token { req = req.header("Authorization", format!("Bearer {}", t)); }
        match req.body(payload.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let found = body.contains("vulnerable") || body.contains("issue") || body.contains("true");
                let tag = if found { "VULNERABLE".red().bold().to_string() } else { "safe".green().to_string() };
                println!("  {} {:40} status={} {}", "*".cyan(), name, status, tag);
                if found { issues.push(name.to_string()); }
            }
            Err(_) => { println!("  {} {:40} error", "*".red(), name); }
        }
    }

    if !issues.is_empty() { println!("\n{} {} overflow issue(s) detected!", "[!]".red().bold(), issues.len()); }
    else { println!("\n{} No overflow vulnerabilities found.", "[-]".green().bold()); }
    Ok(())
}

pub async fn access(url: &str, timeout: u64, token: Option<&str>) -> anyhow::Result<()> {
    println!("{} Access Control Analyzer", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let checks = [
        ("No owner check", r#"{"action":"analyze","check":"access","pattern":"no_owner_check"}"#),
        ("Unrestricted mint", r#"{"action":"analyze","check":"access","pattern":"unrestricted_mint"}"#),
        ("Unrestricted burn", r#"{"action":"analyze","check":"access","pattern":"unrestricted_burn"}"#),
        ("Unrestricted transfer", r#"{"action":"analyze","check":"access","pattern":"unrestricted_transfer"}"#),
        ("Unrestricted selfdestruct", r#"{"action":"analyze","check":"access","pattern":"unrestricted_selfdestruct"}"#),
        ("Unrestricted upgrade", r#"{"action":"analyze","check":"access","pattern":"unrestricted_upgrade"}"#),
        ("Unrestricted setOwner", r#"{"action":"analyze","check":"access","pattern":"unrestricted_setowner"}"#),
        ("Missing onlyRole", r#"{"action":"analyze","check":"access","pattern":"missing_onlyrole"}"#),
        ("Public initializer", r#"{"action":"analyze","check":"access","pattern":"public_initializer"}"#),
        ("Unrestricted delegatecall", r#"{"action":"analyze","check":"access","pattern":"unrestricted_delegatecall"}"#),
    ];

    let mut issues = Vec::new();
    for (name, payload) in &checks {
        let mut req = client.post(url).header("Content-Type", "application/json");
        if let Some(t) = token { req = req.header("Authorization", format!("Bearer {}", t)); }
        match req.body(payload.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let found = body.contains("vulnerable") || body.contains("issue") || body.contains("true");
                let tag = if found { "VULNERABLE".red().bold().to_string() } else { "safe".green().to_string() };
                println!("  {} {:40} status={} {}", "*".cyan(), name, status, tag);
                if found { issues.push(name.to_string()); }
            }
            Err(_) => { println!("  {} {:40} error", "*".red(), name); }
        }
    }

    if !issues.is_empty() { println!("\n{} {} access control issue(s) detected!", "[!]".red().bold(), issues.len()); }
    else { println!("\n{} No access control issues found.", "[-]".green().bold()); }
    Ok(())
}

pub async fn delegatecall(url: &str, timeout: u64, token: Option<&str>) -> anyhow::Result<()> {
    println!("{} Delegatecall Abuse Detector", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let checks = [
        ("Unrestricted delegatecall", r#"{"action":"analyze","check":"delegatecall","pattern":"unrestricted"}"#),
        ("User-controlled target", r#"{"action":"analyze","check":"delegatecall","pattern":"user_controlled_target"}"#),
        ("Delegatecall in fallback", r#"{"action":"analyze","check":"delegatecall","pattern":"fallback_delegatecall"}"#),
        ("Proxy pattern abuse", r#"{"action":"analyze","check":"delegatecall","pattern":"proxy_abuse"}"#),
        ("Storage collision", r#"{"action":"analyze","check":"delegatecall","pattern":"storage_collision"}"#),
        ("Selfdestruct in delegatecall", r#"{"action":"analyze","check":"delegatecall","pattern":"selfdestruct_in_delegate"}"#),
        ("Unverified implementation", r#"{"action":"analyze","check":"delegatecall","pattern":"unverified_impl"}"#),
        ("Initializer bypass", r#"{"action":"analyze","check":"delegatecall","pattern":"initializer_bypass"}"#),
    ];

    let mut issues = Vec::new();
    for (name, payload) in &checks {
        let mut req = client.post(url).header("Content-Type", "application/json");
        if let Some(t) = token { req = req.header("Authorization", format!("Bearer {}", t)); }
        match req.body(payload.to_string()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let found = body.contains("vulnerable") || body.contains("issue") || body.contains("true");
                let tag = if found { "VULNERABLE".red().bold().to_string() } else { "safe".green().to_string() };
                println!("  {} {:40} status={} {}", "*".cyan(), name, status, tag);
                if found { issues.push(name.to_string()); }
            }
            Err(_) => { println!("  {} {:40} error", "*".red(), name); }
        }
    }

    if !issues.is_empty() { println!("\n{} {} delegatecall issue(s) detected!", "[!]".red().bold(), issues.len()); }
    else { println!("\n{} No delegatecall vulnerabilities found.", "[-]".green().bold()); }
    Ok(())
}

use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn enum_rdp(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} RDP Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({"action": "rdp_enum", "host": url});
    let resp = client.post(url).json(&body).send().await?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();

    if status == 200 {
        println!("  {} RDP enumeration results:", "[+]".green().bold());
        for line in text.lines().take(20) {
            println!("    {}", line);
        }
    } else {
        println!("  {} RDP enumeration failed (status={})", "[-]".dimmed(), status);
    }

    let info_items = ["OS version", "NetBIOS name", "NLA support", "Security protocol", "Color depth", "Resolution", "Keyboard layout", "Build number"];
    println!("\n  {} Extracted info:", "[*]".cyan().bold());
    for item in &info_items {
        let ibody = serde_json::json!({"action": "rdp_info", "host": url, "field": item});
        if let Ok(r) = client.post(url).json(&ibody).send().await {
            let t = r.text().await.unwrap_or_default();
            if !t.is_empty() && !t.contains("error") {
                println!("    {} {:20}: {}", "*".cyan(), item, t.chars().take(50).collect::<String>());
            }
        }
    }

    Ok(())
}

pub async fn bluekeep(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} BlueKeep (CVE-2019-0708) Checker", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({"action": "rdp_check", "host": url, "vuln": "cve-2019-0708"});
    let resp = client.post(url).json(&body).send().await?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();

    if text.contains("vulnerable") || text.contains("VULNERABLE") || (status == 200 && text.contains("0708")) {
        println!("  {} Target is VULNERABLE to BlueKeep (CVE-2019-0708)!", "[!]".red().bold());
        println!("  {} This allows remote code execution via RDP.", "[!]".red().bold());
    } else if text.contains("safe") || text.contains("patched") || text.contains("not vulnerable") {
        println!("  {} Target is patched against CVE-2019-0708.", "[-]".green().bold());
    } else {
        println!("  {} Could not determine vulnerability status.", "[*]".yellow().bold());
    }

    let other_rdp_vulns = [
        ("CVE-2019-1181/1182", "RCE in LICEC codec"),
        ("CVE-2020-0609", "RCE in RDP gateway"),
        ("CVE-2020-0610", "RCE in RDP gateway"),
        ("CVE-2021-34534", "RDP DoS via channel"),
        ("CVE-2022-21893", "RDP DoS via RDPEFS"),
    ];

    println!("\n  {} Other RDP vulnerabilities to check:", "[*]".cyan().bold());
    for (cve, name) in &other_rdp_vulns {
        println!("    {} {} — {}", "*".cyan(), cve, name);
    }

    Ok(())
}

pub async fn cred(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} RDP Credential Stuffing", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let creds = [
        ("Administrator", "Password123"),
        ("Administrator", "P@ssw0rd"),
        ("admin", "admin"),
        ("admin", "password"),
        ("user", "user"),
        ("Administrator", ""),
        ("Administrator", "123456"),
        ("Administrator", "Password1"),
        ("admin", "P@ssw0rd"),
        ("user", "P@ssw0rd"),
    ];

    for (user, pass) in &creds {
        let body = serde_json::json!({"action": "rdp_login", "host": url, "username": user, "password": pass});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                let success = text.contains("success") || text.contains("logged in") || text.contains("authenticated");
                let locked = text.contains("locked") || text.contains("lockout");
                if success {
                    println!("  {} {:20}:{:20} — LOGIN SUCCESS", "[+]".green().bold(), user, pass);
                } else if locked {
                    println!("  {} {:20}:{:20} — ACCOUNT LOCKED", "[!]".red().bold(), user, pass);
                    println!("  {} Account lockout detected — stopping to prevent lockout.", "[!]".red().bold());
                    break;
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn nla(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} NLA Bypass Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let checks = [
        ("NLA required", "nla_required"),
        ("CredSSP version", "credssp_version"),
        ("Restricted admin", "restricted_admin"),
        ("Pass-the-hash", "pth_support"),
        ("NLA downgrade", "nla_downgrade"),
    ];

    for (name, check) in &checks {
        let body = serde_json::json!({"action": "rdp_check", "host": url, "check": check});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                let enabled = text.contains("enabled") || text.contains("true") || text.contains("yes");
                let tag = if enabled { "enabled".green().to_string() } else if text.contains("disabled") || text.contains("false") { "disabled".red().bold().to_string() } else { text.chars().take(30).collect() };
                println!("  {} {:25} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:25} error", "[-]".dimmed(), name),
        }
    }

    let bypass_vectors = [
        ("CredSSP downgrade", "Force older CredSSP version to bypass NLA"),
        ("Restricted admin", "Use restricted admin mode with pass-the-hash"),
        ("NLA bypass via gateway", "Connect through RDP gateway without NLA"),
        ("Guest account", "Guest accounts may bypass NLA on some configs"),
    ];

    println!("\n  {} NLA bypass vectors:", "[*]".cyan().bold());
    for (name, desc) in &bypass_vectors {
        println!("    {} {} — {}", "*".cyan(), name, desc);
    }

    Ok(())
}

